//! Authenticated, bounded, uncompressed stream framing for sustained work contracts.
//!
//! Frames are plaintext. The standalone codec requires externally durable nonce
//! high-water marks when a pairwise key is reused. TCP is loopback-only and derives
//! a fresh authenticated session key on every connection.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use angryier_types::FidelityProfile;
use sha2::{Digest as _, Sha256};

use crate::contracts::{
    BranchDecision, BranchPoint, CampaignManifest, CampaignSpec, ContractError, Digest, ExplorationLimits, NamedDigest,
    Successor, WorkUnit,
};

pub const WIRE_VERSION: u16 = 2;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAGIC: &[u8; 4] = b"AWN1";
const TAG_BYTES: usize = 32;
const MIN_FRAME_BYTES: usize = 4 + 2 + 1 + 8 + 8 + 32 + 2 + 2 + TAG_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Truncated,
    Oversize,
    Malformed,
    UnsupportedVersion,
    UnauthorizedPeer,
    InvalidMac,
    Replay,
    StaleEpoch,
    CampaignMismatch,
    Contract(ContractError),
}

impl From<ContractError> for TransportError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TransportError {}

/// Status is a statement by a remote peer, not proof of durable ledger commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteStatus {
    Accepted,
    Completed,
    Rejected,
    Retryable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Manifest(Box<CampaignManifest>),
    Work(WorkUnit),
    Status {
        work: WorkUnit,
        status: RemoteStatus,
    },
    /// Bounded opaque runtime grant/result. Only the runtime may interpret it;
    /// a coordinator must validate its fence and evidence before ledger admission.
    Grant {
        work: WorkUnit,
        payload: Vec<u8>,
    },
    Outcome {
        work: WorkUnit,
        payload: Vec<u8>,
    },
}

/// One authenticated message, with a verified sender identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    pub sender: String,
    pub message: Message,
}

/// Ordered frame codec. Direct `encode`/`feed` callers must durably preserve
/// nonce high-water marks before reusing a key; `TcpSession` rekeys on reconnect.
pub struct Transport {
    manifest: CampaignManifest,
    epoch: u64,
    local_peer: String,
    keys: HashMap<String, [u8; 32]>,
    next_nonce: HashMap<String, u64>,
    received_nonce: HashMap<String, u64>,
    pending: Vec<u8>,
}

impl Transport {
    /// `keys` maps authorized remote peer IDs to unique pairwise secret keys.
    /// Direct codec users must durably preserve nonce state across key reuse.
    pub fn new(
        manifest: CampaignManifest,
        epoch: u64,
        local_peer: String,
        keys: HashMap<String, [u8; 32]>,
    ) -> Result<Self, TransportError> {
        manifest.validate()?;
        let mut unique_keys = HashSet::new();
        if epoch == 0
            || keys.values().any(|key| !unique_keys.insert(*key))
            || !valid_peer(&local_peer)
            || keys.is_empty()
            || keys
                .iter()
                .any(|(peer, key)| !valid_peer(peer) || peer == &local_peer || *key == [0; 32])
        {
            return Err(TransportError::Malformed);
        }
        Ok(Self {
            manifest,
            epoch,
            local_peer,
            keys,
            next_nonce: HashMap::new(),
            received_nonce: HashMap::new(),
            pending: Vec::new(),
        })
    }

    /// Supply durable high-water marks before sending or receiving with a reused key.
    /// A new key must be used if that state is lost.
    pub fn set_nonce_high_water(&mut self, peer: &str, sent: u64, received: u64) -> Result<(), TransportError> {
        if !self.keys.contains_key(peer)
            || self.next_nonce.get(peer).is_some_and(|n| sent < *n)
            || self.received_nonce.get(peer).is_some_and(|n| received < *n)
        {
            return Err(TransportError::UnauthorizedPeer);
        }
        self.next_nonce.insert(peer.to_owned(), sent);
        self.received_nonce.insert(peer.to_owned(), received);
        Ok(())
    }

    pub fn nonce_high_water(&self, peer: &str) -> Option<(u64, u64)> {
        self.keys.get(peer).map(|_| {
            (
                *self.next_nonce.get(peer).unwrap_or(&0),
                *self.received_nonce.get(peer).unwrap_or(&0),
            )
        })
    }

    /// Encode one message; write the returned bytes to the destination stream.
    pub fn encode(&mut self, peer: &str, message: &Message) -> Result<Vec<u8>, TransportError> {
        let key = *self.keys.get(peer).ok_or(TransportError::UnauthorizedPeer)?;
        let mut body = Vec::new();
        let kind = match message {
            Message::Manifest(m) => {
                m.validate_resume(&self.manifest)?;
                encode_manifest(&mut body, m)?;
                1
            }
            Message::Work(w) => {
                w.validate(&self.manifest, self.epoch)?;
                encode_work(&mut body, w)?;
                2
            }
            Message::Status { work, status } => {
                work.validate(&self.manifest, self.epoch)?;
                encode_work(&mut body, work)?;
                body.push(match status {
                    RemoteStatus::Accepted => 1,
                    RemoteStatus::Completed => 2,
                    RemoteStatus::Rejected => 3,
                    RemoteStatus::Retryable => 4,
                });
                3
            }
            Message::Grant { work, payload } | Message::Outcome { work, payload } => {
                work.validate(&self.manifest, self.epoch)?;
                encode_work(&mut body, work)?;
                put_u32(
                    &mut body,
                    u32::try_from(payload.len()).map_err(|_| TransportError::Oversize)?,
                );
                body.extend_from_slice(payload);
                if matches!(message, Message::Grant { .. }) { 4 } else { 5 }
            }
        };
        let nonce = self
            .next_nonce
            .get(peer)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(TransportError::Replay)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(MAGIC);
        put_u16(&mut bytes, WIRE_VERSION);
        bytes.push(kind);
        put_u64(&mut bytes, nonce);
        put_u64(&mut bytes, self.epoch);
        bytes.extend_from_slice(&self.manifest.campaign_digest.0);
        put_peer(&mut bytes, &self.local_peer);
        put_peer(&mut bytes, peer);
        bytes.extend_from_slice(&body);
        let frame_len = bytes
            .len()
            .checked_sub(4)
            .and_then(|n| n.checked_add(TAG_BYTES))
            .ok_or(TransportError::Oversize)?;
        if frame_len > MAX_FRAME_BYTES {
            return Err(TransportError::Oversize);
        }
        bytes[..4].copy_from_slice(&(frame_len as u32).to_be_bytes());
        let tag = mac(&key, &bytes);
        bytes.extend_from_slice(&tag);
        self.next_nonce.insert(peer.to_owned(), nonce);
        Ok(bytes)
    }

    /// Feed partial or multiple frames. On error the buffer is cleared; discard
    /// the connection and do not treat earlier returned messages as delivered.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<Received>, TransportError> {
        let mut messages = Vec::new();
        let mut offset = 0;
        while offset < chunk.len() {
            let target = if self.pending.len() < 4 {
                4
            } else {
                let len =
                    u32::from_be_bytes(self.pending[..4].try_into().map_err(|_| TransportError::Malformed)?) as usize;
                if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&len) {
                    self.pending.clear();
                    return Err(TransportError::Oversize);
                }
                4 + len
            };
            let take = (target - self.pending.len()).min(chunk.len() - offset);
            self.pending.extend_from_slice(&chunk[offset..offset + take]);
            offset += take;
            if self.pending.len() == 4 {
                let len =
                    u32::from_be_bytes(self.pending[..4].try_into().map_err(|_| TransportError::Malformed)?) as usize;
                if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&len) {
                    self.pending.clear();
                    return Err(TransportError::Oversize);
                }
                continue;
            }
            if self.pending.len() == target && target > 4 {
                let result = self.decode_pending();
                self.pending.clear();
                messages.push(result?);
            }
        }
        Ok(messages)
    }

    /// Reject a stream that ends with an incomplete length or body.
    pub fn finish(&mut self) -> Result<(), TransportError> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            self.pending.clear();
            Err(TransportError::Truncated)
        }
    }

    fn decode_pending(&mut self) -> Result<Received, TransportError> {
        let bytes = &self.pending;
        let data_end = bytes.len().checked_sub(TAG_BYTES).ok_or(TransportError::Malformed)?;
        let mut r = Reader::new(&bytes[4..data_end]);
        if r.take(4)? != MAGIC {
            return Err(TransportError::Malformed);
        }
        if r.u16()? != WIRE_VERSION {
            return Err(TransportError::UnsupportedVersion);
        }
        let kind = r.u8()?;
        let nonce = r.u64()?;
        let epoch = r.u64()?;
        let campaign = r.digest()?;
        let sender = r.peer()?;
        let recipient = r.peer()?;
        if recipient != self.local_peer {
            return Err(TransportError::UnauthorizedPeer);
        }
        let key = self.keys.get(&sender).ok_or(TransportError::UnauthorizedPeer)?;
        if !constant_time_eq(&mac(key, &bytes[..data_end]), &bytes[data_end..]) {
            return Err(TransportError::InvalidMac);
        }
        if epoch != self.epoch {
            return Err(TransportError::StaleEpoch);
        }
        if campaign != self.manifest.campaign_digest {
            return Err(TransportError::CampaignMismatch);
        }
        if nonce == 0 || nonce <= self.received_nonce.get(&sender).copied().unwrap_or(0) {
            return Err(TransportError::Replay);
        }
        let message = match kind {
            1 => {
                let m = decode_manifest(&mut r)?;
                m.validate_resume(&self.manifest)?;
                Message::Manifest(Box::new(m))
            }
            2 => {
                let w = decode_work(&mut r)?;
                w.validate(&self.manifest, self.epoch)?;
                Message::Work(w)
            }
            3 => {
                let work = decode_work(&mut r)?;
                work.validate(&self.manifest, self.epoch)?;
                let status = match r.u8()? {
                    1 => RemoteStatus::Accepted,
                    2 => RemoteStatus::Completed,
                    3 => RemoteStatus::Rejected,
                    4 => RemoteStatus::Retryable,
                    _ => return Err(TransportError::Malformed),
                };
                Message::Status { work, status }
            }
            4 | 5 => {
                let work = decode_work(&mut r)?;
                work.validate(&self.manifest, self.epoch)?;
                let len = r.u32()? as usize;
                if len > MAX_FRAME_BYTES {
                    return Err(TransportError::Oversize);
                }
                let payload = r.take(len)?.to_vec();
                if kind == 4 {
                    Message::Grant { work, payload }
                } else {
                    Message::Outcome { work, payload }
                }
            }
            _ => return Err(TransportError::Malformed),
        };
        r.finish()?;
        self.received_nonce.insert(sender.clone(), nonce);
        Ok(Received { sender, message })
    }
}

/// Raw TCP is restricted to loopback. A separately authenticated and confidential
/// tunnel (for example, SSH or mTLS) is required to cross hosts.
#[derive(Debug)]
pub enum TcpError {
    Io(io::Error),
    InsecureEndpoint,
    Protocol(TransportError),
}

impl std::fmt::Display for TcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "TCP I/O: {e}"),
            Self::InsecureEndpoint => write!(f, "raw TCP requires loopback endpoints"),
            Self::Protocol(e) => write!(f, "transport: {e}"),
        }
    }
}

impl std::error::Error for TcpError {}

/// One authenticated TCP connection; frames and nonce state stay in `transport`.
pub struct TcpSession {
    stream: TcpStream,
    transport: Transport,
    peer: String,
    pairwise_key: [u8; 32],
    deadline: Option<Instant>,
}

impl TcpSession {
    pub fn connect<A: ToSocketAddrs>(addr: A, transport: Transport, peer: &str) -> Result<Self, TcpError> {
        Self::connect_inner(addr, transport, peer, None)
    }

    /// Bound connection establishment, authentication, and subsequent frame I/O by one instant.
    pub fn connect_until<A: ToSocketAddrs>(
        addr: A,
        transport: Transport,
        peer: &str,
        deadline: Instant,
    ) -> Result<Self, TcpError> {
        Self::connect_inner(addr, transport, peer, Some(deadline))
    }

    fn connect_inner<A: ToSocketAddrs>(
        addr: A,
        transport: Transport,
        peer: &str,
        deadline: Option<Instant>,
    ) -> Result<Self, TcpError> {
        let addrs: Vec<_> = addr.to_socket_addrs().map_err(TcpError::Io)?.collect();
        if addrs.is_empty() || addrs.iter().any(|addr| !addr.ip().is_loopback()) {
            return Err(TcpError::InsecureEndpoint);
        }
        let stream = if let Some(deadline) = deadline {
            let mut last_error = None;
            let mut connected = None;
            for addr in addrs {
                let remaining = remaining(deadline)?;
                match TcpStream::connect_timeout(&addr, remaining) {
                    Ok(stream) => {
                        connected = Some(stream);
                        break;
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            connected.ok_or_else(|| {
                TcpError::Io(last_error.unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::AddrNotAvailable, "no connection address was attempted")
                }))
            })?
        } else {
            TcpStream::connect(addrs.as_slice()).map_err(TcpError::Io)?
        };
        Self::from_stream_inner(stream, transport, peer, deadline)
    }

    pub fn from_stream(stream: TcpStream, transport: Transport, peer: &str) -> Result<Self, TcpError> {
        Self::from_stream_inner(stream, transport, peer, None)
    }

    fn from_stream_inner(
        mut stream: TcpStream,
        mut transport: Transport,
        peer: &str,
        deadline: Option<Instant>,
    ) -> Result<Self, TcpError> {
        if !stream.peer_addr().map_err(TcpError::Io)?.ip().is_loopback()
            || !stream.local_addr().map_err(TcpError::Io)?.ip().is_loopback()
        {
            return Err(TcpError::InsecureEndpoint);
        }
        let key = *transport
            .keys
            .get(peer)
            .ok_or(TcpError::Protocol(TransportError::UnauthorizedPeer))?;
        let handshake_deadline = Instant::now() + Duration::from_secs(10);
        let handshake_deadline = deadline.map_or(handshake_deadline, |limit| limit.min(handshake_deadline));
        let result = handshake(&mut stream, &transport, peer, &key, handshake_deadline);
        let session_key = match result {
            Ok(key) => key,
            Err(error) => {
                let _ = stream.shutdown(Shutdown::Both);
                return Err(error);
            }
        };
        transport.keys.insert(peer.to_owned(), session_key);
        transport.next_nonce.insert(peer.to_owned(), 0);
        transport.received_nonce.insert(peer.to_owned(), 0);
        Ok(Self {
            stream,
            transport,
            peer: peer.to_owned(),
            pairwise_key: key,
            deadline,
        })
    }

    /// A failed write closes this connection; the consumed outbound nonce must
    /// not be rolled back if the peer may have received part of the frame.
    pub fn send(&mut self, message: &Message) -> Result<(), TcpError> {
        let frame = self.transport.encode(&self.peer, message).map_err(TcpError::Protocol)?;
        let result = write_all(&mut self.stream, &frame, self.deadline);
        if result.is_err() {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        result
    }

    /// Read exactly one bounded frame. EOF mid-frame closes this connection;
    /// an idle EOF is also reported as truncation to the caller.
    pub fn receive(&mut self) -> Result<Received, TcpError> {
        let result = self.receive_frame().and_then(|received| {
            if received.sender != self.peer {
                Err(TcpError::Protocol(TransportError::UnauthorizedPeer))
            } else {
                Ok(received)
            }
        });
        if result.is_err() {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
        result
    }

    fn receive_frame(&mut self) -> Result<Received, TcpError> {
        if !self.transport.pending.is_empty() {
            return Err(TcpError::Protocol(TransportError::Malformed));
        }
        let mut header = [0u8; 4];
        read_exact(&mut self.stream, &mut header, self.deadline)?;
        let len = u32::from_be_bytes(header) as usize;
        if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&len) {
            return Err(TcpError::Protocol(TransportError::Oversize));
        }
        let mut frame = Vec::with_capacity(4 + len);
        frame.extend_from_slice(&header);
        frame.resize(4 + len, 0);
        read_exact(&mut self.stream, &mut frame[4..], self.deadline)?;
        let mut messages = self.transport.feed(&frame).map_err(TcpError::Protocol)?;
        if let Some(deadline) = self.deadline {
            remaining(deadline)?;
        }
        messages.pop().ok_or(TcpError::Protocol(TransportError::Malformed))
    }

    /// Applies an absolute deadline to all subsequent frame I/O. A late complete frame is rejected.
    pub fn set_deadline(&mut self, deadline: Option<Instant>) {
        self.deadline = deadline;
    }

    /// Bound idle peers and stalled writes; this does not bound computation.
    pub fn set_timeouts(&mut self, timeout: std::time::Duration) -> Result<(), TcpError> {
        if timeout.is_zero() {
            return Err(TcpError::Protocol(TransportError::Malformed));
        }
        self.stream.set_read_timeout(Some(timeout)).map_err(TcpError::Io)?;
        self.stream.set_write_timeout(Some(timeout)).map_err(TcpError::Io)
    }

    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    pub fn into_transport(mut self) -> Transport {
        self.transport.keys.insert(self.peer.clone(), self.pairwise_key);
        self.transport
    }
}

/// Both sides prove possession of the provisioned pairwise key over a fresh
/// nonce exchange, exchange their campaign digests, and bind their roles, wire
/// version, both campaign digests (including semantic/build inputs), and epoch.
/// Session keys are fresh even if a caller reconstructs Transport after a crash.
///
/// The proof authenticates the peer digest, and the digests are compared only
/// after that proof verifies, so a legitimate peer holding a different manifest
/// reports `CampaignMismatch` instead of an indistinguishable `InvalidMac`.
fn handshake(
    stream: &mut TcpStream,
    transport: &Transport,
    peer: &str,
    key: &[u8; 32],
    deadline: Instant,
) -> Result<[u8; 32], TcpError> {
    let old_read = stream.read_timeout().map_err(TcpError::Io)?;
    let old_write = stream.write_timeout().map_err(TcpError::Io)?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(TcpError::Io)?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(TcpError::Io)?;
    let result = (|| {
        let local_digest = transport.manifest.campaign_digest.0;
        let mut local_nonce = [0u8; 32];
        // The appliance runs on Linux. If OS entropy is unavailable, do not
        // substitute a predictable nonce or permit an unauthenticated session.
        File::open("/dev/urandom")
            .and_then(|mut entropy| entropy.read_exact(&mut local_nonce))
            .map_err(TcpError::Io)?;
        write_all(stream, &local_nonce, Some(deadline))?;
        write_all(stream, &local_digest, Some(deadline))?;
        let mut remote_nonce = [0u8; 32];
        read_exact(stream, &mut remote_nonce, Some(deadline))?;
        let mut remote_digest = [0u8; 32];
        read_exact(stream, &mut remote_digest, Some(deadline))?;
        let local_side = ProofSide {
            peer: &transport.local_peer,
            digest: &local_digest,
            nonce: &local_nonce,
        };
        let remote_side = ProofSide {
            peer,
            digest: &remote_digest,
            nonce: &remote_nonce,
        };
        let local_tag = handshake_tag(key, transport.epoch, &local_side, &remote_side);
        write_all(stream, &local_tag, Some(deadline))?;
        let mut remote_tag = [0u8; 32];
        read_exact(stream, &mut remote_tag, Some(deadline))?;
        let expected = handshake_tag(key, transport.epoch, &remote_side, &local_side);
        // Verify the proof covers the peer digest before that digest is trusted;
        // a mismatch reported from unauthenticated bytes would be a forgery oracle.
        if !constant_time_eq(&remote_tag, &expected) {
            return Err(TcpError::Protocol(TransportError::InvalidMac));
        }
        if remote_digest != local_digest {
            return Err(TcpError::Protocol(TransportError::CampaignMismatch));
        }
        let mut context = Vec::with_capacity(128);
        context.extend_from_slice(b"AWN1 session key v2");
        if transport.local_peer.as_str() < peer {
            context.extend_from_slice(&local_tag);
            context.extend_from_slice(&remote_tag);
        } else {
            context.extend_from_slice(&remote_tag);
            context.extend_from_slice(&local_tag);
        }
        remaining(deadline)?;
        Ok(mac(key, &context))
    })();
    let restore_read = stream.set_read_timeout(old_read);
    let restore_write = stream.set_write_timeout(old_write);
    if result.is_ok() {
        restore_read.map_err(TcpError::Io)?;
        restore_write.map_err(TcpError::Io)?;
    }
    result
}

/// One role in the handshake proof: its peer ID, campaign digest, and nonce.
struct ProofSide<'a> {
    peer: &'a str,
    digest: &'a [u8; 32],
    nonce: &'a [u8; 32],
}

/// The proof is role-ordered: the sender's campaign digest, the recipient's
/// digest, then the peer IDs and nonces in the same sender/recipient roles.
fn handshake_tag(key: &[u8; 32], epoch: u64, sender: &ProofSide<'_>, recipient: &ProofSide<'_>) -> [u8; 32] {
    let mut context = Vec::with_capacity(256);
    context.extend_from_slice(b"AWN1 handshake v2");
    put_u16(&mut context, WIRE_VERSION);
    put_u64(&mut context, epoch);
    context.extend_from_slice(sender.digest);
    context.extend_from_slice(recipient.digest);
    put_peer(&mut context, sender.peer);
    put_peer(&mut context, recipient.peer);
    context.extend_from_slice(sender.nonce);
    context.extend_from_slice(recipient.nonce);
    mac(key, &context)
}

fn remaining(deadline: Instant) -> Result<Duration, TcpError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or_else(|| TcpError::Io(io::Error::new(io::ErrorKind::TimedOut, "TCP deadline elapsed")))
}

fn bound_timeout(stream: &TcpStream, deadline: Instant, read: bool) -> Result<(), TcpError> {
    let time = remaining(deadline)?;
    let idle = if read {
        stream.read_timeout()
    } else {
        stream.write_timeout()
    }
    .map_err(TcpError::Io)?;
    let timeout = idle.map_or(time, |idle| idle.min(time));
    if read {
        stream.set_read_timeout(Some(timeout))
    } else {
        stream.set_write_timeout(Some(timeout))
    }
    .map_err(TcpError::Io)
}

fn read_exact(stream: &mut TcpStream, mut bytes: &mut [u8], deadline: Option<Instant>) -> Result<(), TcpError> {
    while !bytes.is_empty() {
        if let Some(deadline) = deadline {
            bound_timeout(stream, deadline, true)?;
        }
        match stream.read(bytes) {
            Ok(0) => return Err(TcpError::Protocol(TransportError::Truncated)),
            Ok(n) => bytes = &mut bytes[n..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(TcpError::Io(error)),
        }
    }
    if let Some(deadline) = deadline {
        remaining(deadline)?;
    }
    Ok(())
}

fn write_all(stream: &mut TcpStream, mut bytes: &[u8], deadline: Option<Instant>) -> Result<(), TcpError> {
    while !bytes.is_empty() {
        if let Some(deadline) = deadline {
            bound_timeout(stream, deadline, false)?;
        }
        match stream.write(bytes) {
            Ok(0) => return Err(TcpError::Io(io::Error::from(io::ErrorKind::WriteZero))),
            Ok(n) => bytes = &bytes[n..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(TcpError::Io(error)),
        }
    }
    if let Some(deadline) = deadline {
        remaining(deadline)?;
    }
    Ok(())
}

/// Loopback-only listener; each accepted connection negotiates a fresh MAC key.
/// Use an authenticated confidential tunnel for connections between hosts.
pub struct TcpServer(TcpListener);

impl TcpServer {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let addrs: Vec<_> = addr.to_socket_addrs()?.collect();
        if addrs.is_empty() || addrs.iter().any(|addr| !addr.ip().is_loopback()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "raw TCP requires loopback bind",
            ));
        }
        TcpListener::bind(addrs.as_slice()).map(Self)
    }

    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.0.local_addr()
    }

    pub fn accept(&self, transport: Transport, peer: &str) -> Result<TcpSession, TcpError> {
        let (stream, _) = self.0.accept().map_err(TcpError::Io)?;
        TcpSession::from_stream(stream, transport, peer)
    }
}

fn valid_peer(peer: &str) -> bool {
    !peer.is_empty() && peer.len() <= 128 && peer.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn put_u16(b: &mut Vec<u8>, n: u16) {
    b.extend_from_slice(&n.to_be_bytes());
}
fn put_u32(b: &mut Vec<u8>, n: u32) {
    b.extend_from_slice(&n.to_be_bytes());
}
fn put_u64(b: &mut Vec<u8>, n: u64) {
    b.extend_from_slice(&n.to_be_bytes());
}
fn put_peer(b: &mut Vec<u8>, peer: &str) {
    put_u16(b, peer.len() as u16);
    b.extend_from_slice(peer.as_bytes());
}
fn put_str(b: &mut Vec<u8>, text: &str) -> Result<(), TransportError> {
    let n = u32::try_from(text.len()).map_err(|_| TransportError::Oversize)?;
    if b.len()
        .checked_add(4 + text.len())
        .is_none_or(|size| size > MAX_FRAME_BYTES)
    {
        return Err(TransportError::Oversize);
    }
    put_u32(b, n);
    b.extend_from_slice(text.as_bytes());
    Ok(())
}
fn put_named(b: &mut Vec<u8>, entries: &[NamedDigest]) -> Result<(), TransportError> {
    if entries.len() > MAX_FRAME_BYTES / 36 {
        return Err(TransportError::Oversize);
    }
    put_u32(b, u32::try_from(entries.len()).map_err(|_| TransportError::Oversize)?);
    for item in entries {
        put_str(b, &item.name)?;
        if b.len() > MAX_FRAME_BYTES - 32 {
            return Err(TransportError::Oversize);
        }
        b.extend_from_slice(&item.digest.0);
    }
    Ok(())
}
fn encode_manifest(b: &mut Vec<u8>, m: &CampaignManifest) -> Result<(), TransportError> {
    put_u32(b, m.schema_version);
    b.extend_from_slice(&m.campaign_digest.0);
    let s = &m.spec;
    b.extend_from_slice(&s.binary_digest.0);
    put_str(b, &s.architecture)?;
    put_u64(b, s.entry_pc);
    put_str(b, &s.semantic_version)?;
    for d in [s.semantic_profile_digest, s.script_digest, s.policy_digest] {
        b.extend_from_slice(&d.0);
    }
    put_named(b, &s.inputs)?;
    put_named(b, &s.stubs)?;
    put_str(b, &s.solver_version)?;
    b.extend_from_slice(&s.solver_policy_digest.0);
    b.push(match s.fidelity {
        FidelityProfile::Prove => 0,
        FidelityProfile::Explore => 1,
        FidelityProfile::Hunt => 2,
    });
    let l = &s.limits;
    for n in [
        l.max_steps,
        l.max_path_steps,
        l.max_active_states,
        l.max_path_depth,
        l.max_loop_visits,
        l.max_solver_millis,
        l.max_wall_millis,
        l.max_ram_bytes,
        l.max_disk_bytes,
        l.max_trace_bytes,
    ] {
        put_u64(b, n);
    }
    Ok(())
}
fn encode_work(b: &mut Vec<u8>, w: &WorkUnit) -> Result<(), TransportError> {
    put_u32(b, w.schema_version);
    b.extend_from_slice(&w.campaign_digest.0);
    put_u64(b, w.contract_epoch);
    if w.prefix.len() > (MAX_FRAME_BYTES - b.len()) / 105 {
        return Err(TransportError::Oversize);
    }
    put_u32(b, u32::try_from(w.prefix.len()).map_err(|_| TransportError::Oversize)?);
    for decision in &w.prefix {
        let p = &decision.branch;
        for n in [
            p.branch_pc,
            p.visit_index,
            p.false_target,
            p.true_target,
            p.prefix_constraints,
        ] {
            put_u64(b, n);
        }
        b.extend_from_slice(&p.trace_digest.0);
        b.extend_from_slice(&p.predicate_digest.0);
        b.push(match decision.successor {
            Successor::False => 0,
            Successor::True => 1,
        });
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], TransportError> {
        let end = self.pos.checked_add(n).ok_or(TransportError::Malformed)?;
        let out = self.bytes.get(self.pos..end).ok_or(TransportError::Truncated)?;
        self.pos = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, TransportError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, TransportError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| TransportError::Malformed)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, TransportError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| TransportError::Malformed)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, TransportError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| TransportError::Malformed)?,
        ))
    }
    fn digest(&mut self) -> Result<Digest, TransportError> {
        Ok(Digest(
            self.take(32)?.try_into().map_err(|_| TransportError::Malformed)?,
        ))
    }
    fn string(&mut self) -> Result<String, TransportError> {
        let len = self.u32()? as usize;
        if len > MAX_FRAME_BYTES {
            return Err(TransportError::Oversize);
        }
        String::from_utf8(self.take(len)?.to_vec()).map_err(|_| TransportError::Malformed)
    }
    fn peer(&mut self) -> Result<String, TransportError> {
        let len = self.u16()? as usize;
        if len > 128 {
            return Err(TransportError::Malformed);
        }
        let peer = std::str::from_utf8(self.take(len)?).map_err(|_| TransportError::Malformed)?;
        if !valid_peer(peer) {
            return Err(TransportError::Malformed);
        }
        Ok(peer.to_owned())
    }
    fn named(&mut self) -> Result<Vec<NamedDigest>, TransportError> {
        let count = self.u32()? as usize;
        if count > self.bytes.len() / 36 {
            return Err(TransportError::Malformed);
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(NamedDigest {
                name: self.string()?,
                digest: self.digest()?,
            });
        }
        Ok(entries)
    }
    fn finish(&self) -> Result<(), TransportError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(TransportError::Malformed)
        }
    }
}
fn decode_manifest(r: &mut Reader<'_>) -> Result<CampaignManifest, TransportError> {
    let schema_version = r.u32()?;
    let campaign_digest = r.digest()?;
    let binary_digest = r.digest()?;
    let architecture = r.string()?;
    let entry_pc = r.u64()?;
    let semantic_version = r.string()?;
    let semantic_profile_digest = r.digest()?;
    let script_digest = r.digest()?;
    let policy_digest = r.digest()?;
    let inputs = r.named()?;
    let stubs = r.named()?;
    let solver_version = r.string()?;
    let solver_policy_digest = r.digest()?;
    let fidelity = match r.u8()? {
        0 => FidelityProfile::Prove,
        1 => FidelityProfile::Explore,
        2 => FidelityProfile::Hunt,
        _ => return Err(TransportError::Malformed),
    };
    let limits = ExplorationLimits {
        max_steps: r.u64()?,
        max_path_steps: r.u64()?,
        max_active_states: r.u64()?,
        max_path_depth: r.u64()?,
        max_loop_visits: r.u64()?,
        max_solver_millis: r.u64()?,
        max_wall_millis: r.u64()?,
        max_ram_bytes: r.u64()?,
        max_disk_bytes: r.u64()?,
        max_trace_bytes: r.u64()?,
    };
    Ok(CampaignManifest {
        schema_version,
        campaign_digest,
        spec: CampaignSpec {
            binary_digest,
            architecture,
            entry_pc,
            semantic_version,
            semantic_profile_digest,
            script_digest,
            policy_digest,
            inputs,
            stubs,
            solver_version,
            solver_policy_digest,
            fidelity,
            limits,
        },
    })
}
fn decode_work(r: &mut Reader<'_>) -> Result<WorkUnit, TransportError> {
    let schema_version = r.u32()?;
    let campaign_digest = r.digest()?;
    let contract_epoch = r.u64()?;
    let count = r.u32()? as usize;
    if count > r.bytes.len() / 105 {
        return Err(TransportError::Malformed);
    }
    let mut prefix = Vec::with_capacity(count);
    for _ in 0..count {
        let branch = BranchPoint {
            branch_pc: r.u64()?,
            visit_index: r.u64()?,
            false_target: r.u64()?,
            true_target: r.u64()?,
            prefix_constraints: r.u64()?,
            trace_digest: r.digest()?,
            predicate_digest: r.digest()?,
        };
        let successor = match r.u8()? {
            0 => Successor::False,
            1 => Successor::True,
            _ => return Err(TransportError::Malformed),
        };
        prefix.push(BranchDecision { branch, successor });
    }
    Ok(WorkUnit {
        schema_version,
        campaign_digest,
        contract_epoch,
        prefix,
    })
}

// RFC 2104 HMAC-SHA-256, over the length prefix and every frame byte except tag.
fn mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut inner = Sha256::new();
    let mut outer = Sha256::new();
    let mut block = [0x36; 64];
    for (dst, src) in block.iter_mut().zip(key) {
        *dst ^= src;
    }
    inner.update(block);
    inner.update(data);
    for dst in &mut block {
        *dst ^= 0x36 ^ 0x5c;
    }
    outer.update(block);
    outer.update(inner.finalize());
    outer.finalize().into()
}
fn constant_time_eq(expected: &[u8; 32], received: &[u8]) -> bool {
    if received.len() != 32 {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in expected.iter().zip(received) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::mac;

    #[test]
    fn hmac_sha256_matches_known_vector() {
        assert_eq!(
            mac(&[0x42; 32], b"authenticated frame"),
            [
                0x0a, 0x3d, 0x4a, 0x1b, 0xcf, 0xea, 0xa2, 0xee, 0x67, 0x00, 0x69, 0x2b, 0x31, 0x97, 0x29, 0x80, 0xaa,
                0x83, 0xc6, 0x91, 0x26, 0x6f, 0x9b, 0x5f, 0xcd, 0xfe, 0x42, 0x6a, 0xec, 0x13, 0x04, 0x37,
            ]
        );
    }
}
