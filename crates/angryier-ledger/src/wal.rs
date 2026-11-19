//! Append-only, checksummed, generation/sequence-bound write-ahead sidecar for
//! the ANGFRNT3 checkpoint snapshot.
//!
//! Every acknowledged transition is one bounded frame appended to
//! `<checkpoint>.wal` and fsynced BEFORE the in-memory state moves. The
//! ANGFRNT3 snapshot remains the immutable checkpoint anchor: after the first
//! transition it is atomically replaced by an `ANGFRNT9` tombstone so that
//! pre-WAL binaries fail closed instead of accepting a stale checkpoint.
//! A legacy snapshot-only ledger (no WAL sidecar) still opens normally and
//! migrates on its first transition.
//!
//! WAL header (116 bytes, little-endian):
//!   magic "ANGFRWAL" | version:u32 | generation:u64 | manifest_digest:32
//!   | anchor:32 | checksum:32
//! `anchor` is the Digest of the checkpoint bytes the WAL extends; `checksum`
//! covers the preceding 84 bytes.
//!
//! Frame:
//!   kind:u8 | generation:u64 | seq:u64 | payload_len:u32 | payload | checksum:32
//! `checksum` covers kind..payload. `seq` is strictly monotonic within one WAL
//! generation; `generation` must equal the header generation, and the
//! tombstone generation must equal it too.
//!
//! Recovery scans frames in order. The ONLY tolerated damage is a torn final
//! unsynced append: a frame whose length runs past EOF truncates the file back
//! to the last valid frame and syncs — but only after a bounded probe confirms
//! that no fully valid frame follows (right generation, monotonic sequence,
//! in-bounds length, correct checksum). A corrupted interior payload_len that
//! points past EOF has the same shape while acknowledged frames remain behind
//! it; finding any valid later frame fails closed instead of truncating them.
//! When no valid later frame exists, a corrupted final frame length cannot be
//! told apart from a torn unsynced tail and is truncated. A complete frame
//! with a bad checksum, an out-of-order sequence, a wrong generation, a
//! mismatched manifest, or an anchor that no longer matches the checkpoint is
//! rejected; there is no blind checksum forgiveness.
//!
//! No compaction is implemented yet: the WAL grows monotonically and the
//! writer fails closed (`LimitExceeded`) when `MAX_WAL_BYTES` is reached.
use crate::{
    evidence::{self, AcceptedEvidence},
    sustained::{Cursor, Error, MAX_REASON, Record, Status, decode_record, encode_record},
};
use angryier_distribution::contracts::{CampaignManifest, Digest};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(crate) const WAL_MAGIC: &[u8; 8] = b"ANGFRWAL";
pub(crate) const WAL_VERSION: u32 = 1;
pub(crate) const WAL_HEADER_LEN: usize = 8 + 4 + 8 + 32 + 32 + 32; // 116
/// Hard cap on the physical WAL file. The writer fails closed when full.
pub(crate) const MAX_WAL_BYTES: u64 = 1 << 30;
pub(crate) const TOMBSTONE_MAGIC: &[u8; 8] = b"ANGFRNT9";
pub(crate) const TOMBSTONE_VERSION: u32 = 1;
pub(crate) const TOMBSTONE_LEN: usize = 8 + 4 + 8 + 32 + 32; // 84

const KIND_BASE: u8 = 0;
const KIND_RESERVE: u8 = 1;
const KIND_FINISH: u8 = 2;
const KIND_OUTCOME: u8 = 3;
const KIND_REQUEUE: u8 = 4;
const KIND_REVOKE: u8 = 5;
const KIND_SPLIT: u8 = 6;
/// Fixed frame envelope: kind(1) + generation(8) + seq(8) + len(4) + checksum(32).
const FRAME_ENVELOPE: u64 = 53;

pub(crate) fn suffix_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

pub(crate) fn wal_path(path: &Path) -> PathBuf {
    suffix_path(path, ".wal")
}

pub(crate) fn legacy_wal_path(path: &Path) -> Option<PathBuf> {
    let old = path.with_extension("snap.wal");
    (old != wal_path(path)).then_some(old)
}

/// One durable transaction: the exact changed record(s) and accepted evidence.
#[derive(Clone, Debug)]
pub(crate) enum Txn {
    Reserve {
        index: u32,
        attempt: u64,
        owner: Option<Digest>,
    },
    Finish {
        index: u32,
        attempt: u64,
        status: Status,
        reason: String,
    },
    Outcome {
        index: u32,
        attempt: u64,
        status: Status,
        reason: String,
        event: Box<AcceptedEvidence>,
    },
    Requeue {
        index: u32,
        attempt: u64,
    },
    Revoke {
        index: u32,
        attempt: u64,
    },
    Split {
        index: u32,
        attempt: u64,
        children: Box<[Record; 2]>,
        parent_event: Option<Box<AcceptedEvidence>>,
        child_events: Box<[Option<AcceptedEvidence>; 2]>,
    },
}

pub(crate) struct Recovery {
    pub(crate) generation: u64,
    pub(crate) base: Vec<u8>,
    pub(crate) txns: Vec<Txn>,
    pub(crate) last_seq: u64,
    /// Valid state bytes after the header (base frame plus transactions).
    pub(crate) logical: u64,
    /// Offset of the torn final append; the caller truncates and syncs there.
    pub(crate) truncate_at: Option<u64>,
    /// The WAL never reached a complete header: torn first creation.
    pub(crate) header_torn: bool,
}

fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_le_bytes());
}
fn put_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_le_bytes());
}
fn put_digest(out: &mut Vec<u8>, digest: [u8; 32]) {
    out.extend_from_slice(&digest);
}

pub(crate) fn encode_txn(txn: &Txn) -> Result<(u8, Vec<u8>), Error> {
    let mut payload = Vec::new();
    let kind = match txn {
        Txn::Reserve { index, attempt, owner } => {
            put_u32(&mut payload, *index);
            put_u64(&mut payload, *attempt);
            match owner {
                Some(owner) => {
                    payload.push(1);
                    put_digest(&mut payload, owner.0);
                }
                None => payload.push(0),
            }
            KIND_RESERVE
        }
        Txn::Finish {
            index,
            attempt,
            status,
            reason,
        } => {
            put_u32(&mut payload, *index);
            put_u64(&mut payload, *attempt);
            payload.push(evidence::status_byte(*status));
            put_reason(&mut payload, reason)?;
            KIND_FINISH
        }
        Txn::Outcome {
            index,
            attempt,
            status,
            reason,
            event,
        } => {
            put_u32(&mut payload, *index);
            put_u64(&mut payload, *attempt);
            payload.push(evidence::status_byte(*status));
            put_reason(&mut payload, reason)?;
            evidence::encode_event(event, &mut payload)?;
            KIND_OUTCOME
        }
        Txn::Requeue { index, attempt } => {
            put_u32(&mut payload, *index);
            put_u64(&mut payload, *attempt);
            KIND_REQUEUE
        }
        Txn::Revoke { index, attempt } => {
            put_u32(&mut payload, *index);
            put_u64(&mut payload, *attempt);
            KIND_REVOKE
        }
        Txn::Split {
            index,
            attempt,
            children,
            parent_event,
            child_events,
        } => {
            put_u32(&mut payload, *index);
            put_u64(&mut payload, *attempt);
            encode_record(&mut payload, &children[0])?;
            encode_record(&mut payload, &children[1])?;
            for event in [
                parent_event.as_deref(),
                child_events[0].as_ref(),
                child_events[1].as_ref(),
            ] {
                match event {
                    Some(event) => {
                        payload.push(1);
                        evidence::encode_event(event, &mut payload)?;
                    }
                    None => payload.push(0),
                }
            }
            KIND_SPLIT
        }
    };
    Ok((kind, payload))
}

fn put_reason(out: &mut Vec<u8>, reason: &str) -> Result<(), Error> {
    if reason.len() > MAX_REASON {
        return Err(Error::LimitExceeded);
    }
    put_u32(out, u32::try_from(reason.len()).map_err(|_| Error::LimitExceeded)?);
    out.extend_from_slice(reason.as_bytes());
    Ok(())
}

fn read_reason(c: &mut Cursor<'_>) -> Result<String, Error> {
    let len = c.u32()? as usize;
    if len > MAX_REASON {
        return Err(Error::Corrupt);
    }
    String::from_utf8(c.take(len)?.to_vec()).map_err(|_| Error::Corrupt)
}

fn decode_txn(kind: u8, payload: &[u8], manifest: &CampaignManifest) -> Result<Txn, Error> {
    let mut c = Cursor { bytes: payload, pos: 0 };
    let txn = match kind {
        KIND_RESERVE => Txn::Reserve {
            index: c.u32()?,
            attempt: c.u64()?,
            owner: match c.u8()? {
                0 => None,
                1 => Some(c.digest()?),
                _ => return Err(Error::Corrupt),
            },
        },
        KIND_FINISH => Txn::Finish {
            index: c.u32()?,
            attempt: c.u64()?,
            status: evidence::status_from_byte(c.u8()?)?,
            reason: read_reason(&mut c)?,
        },
        KIND_OUTCOME => Txn::Outcome {
            index: c.u32()?,
            attempt: c.u64()?,
            status: evidence::status_from_byte(c.u8()?)?,
            reason: read_reason(&mut c)?,
            event: Box::new(evidence::decode_event(&mut c)?),
        },
        KIND_REQUEUE => Txn::Requeue {
            index: c.u32()?,
            attempt: c.u64()?,
        },
        KIND_REVOKE => Txn::Revoke {
            index: c.u32()?,
            attempt: c.u64()?,
        },
        KIND_SPLIT => Txn::Split {
            index: c.u32()?,
            attempt: c.u64()?,
            children: Box::new([
                decode_record(&mut c, false, manifest)?,
                decode_record(&mut c, false, manifest)?,
            ]),
            parent_event: match c.u8()? {
                0 => None,
                1 => Some(Box::new(evidence::decode_event(&mut c)?)),
                _ => return Err(Error::Corrupt),
            },
            child_events: Box::new([
                match c.u8()? {
                    0 => None,
                    1 => Some(evidence::decode_event(&mut c)?),
                    _ => return Err(Error::Corrupt),
                },
                match c.u8()? {
                    0 => None,
                    1 => Some(evidence::decode_event(&mut c)?),
                    _ => return Err(Error::Corrupt),
                },
            ]),
        },
        _ => return Err(Error::Corrupt),
    };
    if c.pos != payload.len() {
        return Err(Error::Corrupt);
    }
    Ok(txn)
}

/// Bounded fail-closed probe for a purported torn frame whose length ran past
/// EOF. A real torn final unsynced append leaves only that frame's own partial
/// bytes behind, so no complete frame can follow it. A corrupted payload_len on
/// an interior frame looks identical, but acknowledged frames remain behind it.
/// Scan forward for a fully valid frame (header generation, strictly monotonic
/// sequence, in-bounds length, correct checksum); the probe is bounded by the
/// file length, already capped at `MAX_WAL_BYTES`, and never follows the
/// corrupted length. Finding one proves interior corruption. When none is
/// found the caller still truncates: a corrupted final frame length cannot be
/// distinguished from a torn unsynced tail.
fn valid_frame_follows(bytes: &[u8], after: usize, generation: u64, last_seq: u64) -> Result<bool, Error> {
    let mut p = after;
    // A candidate needs at least the 21-byte envelope plus the 32-byte
    // checksum; `p` is bounded by `bytes.len()`.
    while p + FRAME_ENVELOPE as usize <= bytes.len() {
        let mut c = Cursor { bytes, pos: p };
        let _kind = c.u8()?;
        let frame_gen = c.u64()?;
        let seq = c.u64()?;
        let payload_len = c.u32()? as usize;
        if frame_gen != generation || seq <= last_seq {
            p += 1;
            continue;
        }
        let Some(end) = p
            .checked_add(21)
            .and_then(|e| e.checked_add(payload_len))
            .and_then(|e| e.checked_add(32))
            .filter(|end| *end <= bytes.len())
        else {
            p += 1;
            continue;
        };
        let payload_end = end - 32;
        if Digest::of(&bytes[p..payload_end]).0.as_slice() == &bytes[payload_end..payload_end + 32] {
            return Ok(true);
        }
        p += 1;
    }
    Ok(false)
}

/// Scan and validate an existing WAL. `expected_anchor` is `Some(hash)` when
/// the checkpoint snapshot is still a valid base; a mismatch means the
/// checkpoint was rolled back or replaced out-of-band and fails closed.
pub(crate) fn recover(
    wal_path: &Path,
    manifest: &CampaignManifest,
    expected_anchor: Option<Digest>,
) -> Result<Recovery, Error> {
    let mut file = OpenOptions::new().read(true).open(wal_path)?;
    if file.metadata()?.len() > MAX_WAL_BYTES {
        return Err(Error::LimitExceeded);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.len() < WAL_HEADER_LEN {
        return Ok(Recovery {
            generation: 0,
            base: Vec::new(),
            txns: Vec::new(),
            last_seq: 0,
            logical: 0,
            truncate_at: Some(0),
            header_torn: true,
        });
    }
    let mut c = Cursor { bytes: &bytes, pos: 0 };
    if c.take(8)? != WAL_MAGIC {
        return Err(Error::Corrupt);
    }
    if c.u32()? != WAL_VERSION {
        // Unknown or newer WAL format: fail closed, never accept a stale snapshot.
        return Err(Error::Corrupt);
    }
    let generation = c.u64()?;
    let wal_manifest = c.digest()?;
    let anchor = c.digest()?;
    let header_checksum = c.digest()?;
    if Digest::of(&bytes[..WAL_HEADER_LEN - 32]).0.as_slice() != header_checksum.0.as_slice() {
        return Err(Error::Corrupt);
    }
    if wal_manifest != manifest.campaign_digest {
        return Err(Error::MismatchedCampaign);
    }
    if expected_anchor.is_some_and(|expected| anchor != expected) {
        return Err(Error::Corrupt);
    }
    let mut base: Option<Vec<u8>> = None;
    let mut txns = Vec::new();
    let mut last_seq = 0u64;
    let mut truncate_at = None;
    while c.pos < bytes.len() {
        let remaining = bytes.len() - c.pos;
        if remaining < 21 {
            truncate_at = Some(c.pos as u64);
            break;
        }
        let start = c.pos;
        let kind = c.u8()?;
        let frame_gen = c.u64()?;
        let seq = c.u64()?;
        let payload_len = c.u32()? as usize;
        let total = 21usize
            .checked_add(payload_len)
            .and_then(|t| t.checked_add(32))
            .ok_or(Error::Corrupt)?;
        if start + total > bytes.len() {
            // A length running past EOF is usually a torn final unsynced
            // append, but a corrupted payload_len on an interior frame has
            // the same shape while acknowledged frames remain behind it.
            // Fail closed when any valid later frame exists; otherwise the
            // tail is indistinguishable from a torn unsynced append and is
            // truncated as before.
            if valid_frame_follows(&bytes, start + 21, generation, last_seq)? {
                return Err(Error::Corrupt);
            }
            truncate_at = Some(start as u64);
            break;
        }
        let payload_end = start + 21 + payload_len;
        if Digest::of(&bytes[start..payload_end]).0.as_slice() != &bytes[payload_end..payload_end + 32] {
            // A complete frame with a bad checksum is corruption, not a torn append.
            return Err(Error::Corrupt);
        }
        if frame_gen != generation {
            return Err(Error::Corrupt);
        }
        if kind == KIND_BASE {
            if last_seq != 0 || base.is_some() || seq != 0 {
                return Err(Error::Corrupt);
            }
            base = Some(bytes[start + 21..payload_end].to_vec());
        } else {
            if seq != last_seq + 1 {
                return Err(Error::Corrupt);
            }
            txns.push(decode_txn(kind, &bytes[start + 21..payload_end], manifest)?);
        }
        last_seq = seq;
        c.pos = payload_end + 32;
    }
    let keep = truncate_at.unwrap_or(bytes.len() as u64);
    Ok(Recovery {
        generation,
        base: base.ok_or(Error::Corrupt)?,
        txns,
        last_seq,
        logical: keep - WAL_HEADER_LEN as u64,
        truncate_at,
        header_torn: false,
    })
}

/// Tombstone that replaces the checkpoint snapshot once a WAL exists: a
/// pre-WAL binary rejects the unknown magic instead of accepting stale state.
pub(crate) fn tombstone_bytes(generation: u64, manifest_digest: Digest) -> Vec<u8> {
    let mut out = Vec::with_capacity(TOMBSTONE_LEN);
    out.extend_from_slice(TOMBSTONE_MAGIC);
    put_u32(&mut out, TOMBSTONE_VERSION);
    put_u64(&mut out, generation);
    out.extend_from_slice(&manifest_digest.0);
    out.extend_from_slice(&Digest::of(&out).0);
    out
}

pub(crate) fn parse_tombstone(bytes: &[u8]) -> Result<(u64, Digest), Error> {
    if bytes.len() != TOMBSTONE_LEN {
        return Err(Error::Corrupt);
    }
    if &bytes[..8] != TOMBSTONE_MAGIC {
        return Err(Error::Corrupt);
    }
    if u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| Error::Corrupt)?) != TOMBSTONE_VERSION {
        return Err(Error::Corrupt);
    }
    let generation = u64::from_le_bytes(bytes[12..20].try_into().map_err(|_| Error::Corrupt)?);
    let manifest = Digest(bytes[20..52].try_into().map_err(|_| Error::Corrupt)?);
    if Digest::of(&bytes[..TOMBSTONE_LEN - 32]).0.as_slice() != &bytes[TOMBSTONE_LEN - 32..] {
        return Err(Error::Corrupt);
    }
    Ok((generation, manifest))
}

/// Append-mode handle over an established WAL. Writes are fsynced before the
/// caller may acknowledge a transition.
pub(crate) struct Wal {
    file: std::fs::File,
    pub(crate) generation: u64,
    pub(crate) seq: u64,
    /// Valid state bytes after the header (base frame plus transactions).
    pub(crate) logical: u64,
}

impl Wal {
    /// Create a WAL from a checkpoint snapshot. The header and base frame are
    /// fsynced before the first transaction is appended. Never overwrites an
    /// established WAL; callers remove torn empty files first.
    pub(crate) fn create(
        path: &Path,
        generation: u64,
        manifest_digest: Digest,
        anchor: Digest,
        base: &[u8],
    ) -> Result<Self, Error> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        let mut header = Vec::with_capacity(WAL_HEADER_LEN);
        header.extend_from_slice(WAL_MAGIC);
        put_u32(&mut header, WAL_VERSION);
        put_u64(&mut header, generation);
        header.extend_from_slice(&manifest_digest.0);
        header.extend_from_slice(&anchor.0);
        header.extend_from_slice(&Digest::of(&header).0);
        let mut frame = Vec::with_capacity(base.len() + 53);
        frame.push(KIND_BASE);
        put_u64(&mut frame, generation);
        put_u64(&mut frame, 0);
        put_u32(&mut frame, u32::try_from(base.len()).map_err(|_| Error::LimitExceeded)?);
        frame.extend_from_slice(base);
        frame.extend_from_slice(&Digest::of(&frame).0);
        file.write_all(&header)?;
        file.write_all(&frame)?;
        file.sync_all()?;
        Ok(Self {
            file,
            generation,
            seq: 0,
            logical: frame.len() as u64,
        })
    }

    pub(crate) fn open_append(path: &Path, generation: u64, seq: u64, logical: u64) -> Result<Self, Error> {
        let file = OpenOptions::new().append(true).open(path)?;
        Ok(Self {
            file,
            generation,
            seq,
            logical,
        })
    }

    /// Append and fsync pre-encoded transactions, assigning the next monotonic
    /// sequences. Nothing is acknowledged until the sync completes.
    pub(crate) fn append_encoded(&mut self, frames: &[(u8, Vec<u8>)]) -> Result<(), Error> {
        if frames.is_empty() {
            return Ok(());
        }
        let mut buf = Vec::new();
        let mut added: u64 = 0;
        for (kind, payload) in frames {
            self.seq = self.seq.checked_add(1).ok_or(Error::LimitExceeded)?;
            let mut frame = Vec::with_capacity(payload.len() + FRAME_ENVELOPE as usize);
            frame.push(*kind);
            put_u64(&mut frame, self.generation);
            put_u64(&mut frame, self.seq);
            put_u32(
                &mut frame,
                u32::try_from(payload.len()).map_err(|_| Error::LimitExceeded)?,
            );
            frame.extend_from_slice(payload);
            frame.extend_from_slice(&Digest::of(&frame).0);
            added += frame.len() as u64;
            buf.extend_from_slice(&frame);
        }
        self.file.write_all(&buf)?;
        self.file.sync_all()?;
        self.logical += added;
        Ok(())
    }
}
