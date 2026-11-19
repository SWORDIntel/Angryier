//! Crash-recoverable human-readable projection of the authoritative campaign ledger.
use angryier_distribution::contracts::Digest;
use angryier_ledger::evidence::{AcceptedEvidence, PathDisposition, ReplayVerification};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    path::{Component, Path, PathBuf},
};

const MAX_PCS: usize = 16;
const MAX_LINE_BYTES: usize = 16 * 1024;
// Separate from the authoritative ledger disk limit: at most 64 MiB of JSONL projection.
const MAX_PROGRESS_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) struct ProgressJournal {
    path: PathBuf,
    ledger: PathBuf,
    file: File,
    bytes: u64,
    rows: usize,
    recovered: bool,
}

impl ProgressJournal {
    pub(crate) fn recovered(&self) -> bool {
        self.recovered
    }
}

pub(crate) fn default_path(ledger: &Path) -> PathBuf {
    let mut name = ledger.as_os_str().to_os_string();
    name.push(".progress.jsonl");
    PathBuf::from(name)
}

fn normalized(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut result = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    Ok(result)
}

fn resolved(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut ancestor = absolute.as_path();
    loop {
        match fs::canonicalize(ancestor) {
            Ok(base) => {
                let relative = absolute.strip_prefix(ancestor).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "resolved ancestor is not a path prefix")
                })?;
                return normalized(&base.join(relative));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                ancestor = ancestor.parent().ok_or(error)?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn validate_path(path: &Path, ledger: &Path) -> io::Result<()> {
    let journal = resolved(path)?;
    let mut protected = vec![
        ledger.to_path_buf(),
        ledger.with_extension("frontier.lock"),
        ledger.with_extension("snap.wal"),
    ];
    let mut wal = ledger.as_os_str().to_os_string();
    wal.push(".wal");
    protected.push(PathBuf::from(wal));
    for candidate in protected {
        if journal == resolved(&candidate)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "progress journal path must differ from ledger, lock and WAL sidecars",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            match (fs::metadata(path), fs::metadata(&candidate)) {
                (Ok(a), Ok(b)) if a.dev() == b.dev() && a.ino() == b.ino() => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "progress journal hardlinks a protected ledger file",
                    ));
                }
                (Err(a), _) if a.kind() != io::ErrorKind::NotFound => return Err(a),
                (_, Err(b)) if b.kind() != io::ErrorKind::NotFound => return Err(b),
                _ => {}
            }
        }
    }
    Ok(())
}

// Refuse unsupported platforms rather than silently falling back to a symlink-following open.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_progress(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NOFOLLOW on Linux/Android; the descriptor is retained for every later append.
    OpenOptions::new()
        .read(true)
        .append(true)
        .custom_flags(0o400000)
        .open(path)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn open_progress(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "safe progress append is unsupported on this platform",
    ))
}

fn verify_file(path: &Path, ledger: &Path, file: &File) -> io::Result<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let actual = file.metadata()?;
        let named = fs::symlink_metadata(path)?;
        if !actual.is_file()
            || !named.is_file()
            || named.file_type().is_symlink()
            || (actual.dev(), actual.ino()) != (named.dev(), named.ino())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "progress path changed or is not a regular file",
            ));
        }
        let mut protected = vec![
            ledger.to_path_buf(),
            ledger.with_extension("frontier.lock"),
            ledger.with_extension("snap.wal"),
        ];
        let mut wal = ledger.as_os_str().to_os_string();
        wal.push(".wal");
        protected.push(PathBuf::from(wal));
        for candidate in protected {
            match fs::metadata(candidate) {
                Ok(meta) if (actual.dev(), actual.ino()) == (meta.dev(), meta.ino()) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "progress file aliases a protected ledger file",
                    ));
                }
                Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
                _ => {}
            }
        }
        Ok(actual.len())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, ledger, file);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "safe progress append is unsupported on this platform",
        ))
    }
}

fn projection_bytes(campaign: Digest, events: &[AcceptedEvidence], start: usize) -> io::Result<u64> {
    let mut bytes = 0u64;
    for (index, event) in events.iter().enumerate().skip(start) {
        let len = event_json(campaign, index, event).len();
        if len > MAX_LINE_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "progress row exceeds bound"));
        }
        bytes = bytes
            .checked_add(len as u64)
            .filter(|&value| value <= MAX_PROGRESS_BYTES)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "progress projection exceeds 64 MiB bound"))?;
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}

fn quoted(value: &str, out: &mut String) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1f}' => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn reason(disposition: PathDisposition) -> (&'static str, String) {
    match disposition {
        PathDisposition::Terminal => ("terminal", String::new()),
        PathDisposition::ExcludedByPolicy => ("excluded_by_policy", String::new()),
        PathDisposition::SolverInfeasible => ("solver_infeasible", String::new()),
        PathDisposition::Pending(value) => ("pending", format!("{value:?}")),
        PathDisposition::Failed(value) => ("failed", format!("{value:?}")),
    }
}

pub(crate) fn event_json(campaign: Digest, index: usize, event: &AcceptedEvidence) -> String {
    use std::fmt::Write as _;
    let path = &event.delta.path;
    let (disposition, why) = reason(path.disposition);
    let mut out = String::with_capacity(2048);
    let _ = write!(
        out,
        "{{\"event_id\":\"{}:{}\",\"path_id\":\"{}\",\"status\":",
        hex(&campaign.0),
        index,
        hex(&path.path_id)
    );
    quoted(&format!("{:?}", event.status), &mut out);
    let _ = write!(
        out,
        ",\"attempt\":{},\"sequence\":{},\"disposition\":",
        event.attempt, event.delta.sequence
    );
    quoted(disposition, &mut out);
    out.push_str(",\"reason\":");
    quoted(&why, &mut out);
    out.push_str(",\"block_pcs\":[");
    for (i, block) in path.blocks.iter().take(MAX_PCS).enumerate() {
        if i != 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{:#x}\"", block.pc);
    }
    out.push_str("],\"branch_pcs\":[");
    for (i, branch) in path.branches.iter().take(MAX_PCS).enumerate() {
        if i != 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{:#x}\"", branch.pc);
    }
    let truncated = path.blocks.len() > MAX_PCS || path.branches.len() > MAX_PCS;
    let verified = path
        .witness
        .as_ref()
        .is_some_and(|w| matches!(w.replay, ReplayVerification::Verified { .. }));
    let _ = writeln!(
        out,
        "],\"pcs_truncated\":{truncated},\"witness_replay_verified\":{verified},\"semantic_debt\":{} }}",
        path.semantic_debt.len()
    );
    out
}

fn write_rows<W: Write>(writer: &mut W, campaign: Digest, events: &[AcceptedEvidence], start: usize) -> io::Result<()> {
    for (index, event) in events.iter().enumerate().skip(start) {
        let value = event_json(campaign, index, event);
        if value.len() > MAX_LINE_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "progress row exceeds bound"));
        }
        writer.write_all(value.as_bytes())?;
    }
    Ok(())
}

fn matches_rows(file: &File, campaign: Digest, events: &[AcceptedEvidence]) -> io::Result<bool> {
    let mut reader = BufReader::new(file);
    let mut actual = Vec::with_capacity(1024);
    for (index, event) in events.iter().enumerate() {
        actual.clear();
        let read = reader
            .by_ref()
            .take((MAX_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut actual)?;
        if read == 0 || read > MAX_LINE_BYTES || actual != event_json(campaign, index, event).as_bytes() {
            return Ok(false);
        }
    }
    actual.clear();
    Ok(reader
        .take((MAX_LINE_BYTES + 1) as u64)
        .read_until(b'\n', &mut actual)?
        == 0)
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()
}

fn regenerate(path: &Path, campaign: Digest, events: &[AcceptedEvidence]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temp_name = path.as_os_str().to_os_string();
    temp_name.push(format!(".{}.tmp", std::process::id()));
    let temp = PathBuf::from(temp_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .or_else(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                fs::remove_file(&temp)?;
                OpenOptions::new().write(true).create_new(true).open(&temp)
            } else {
                Err(e)
            }
        })?;
    let result = (|| {
        write_rows(&mut file, campaign, events, 0)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

impl ProgressJournal {
    /// Validates the entire projection against ledger history; any missing, corrupt,
    /// or lagging journal is atomically rebuilt before new work is dispatched.
    pub(crate) fn reconcile(
        path: PathBuf,
        ledger: &Path,
        campaign: Digest,
        events: &[AcceptedEvidence],
    ) -> io::Result<Self> {
        validate_path(&path, ledger)?;
        let bytes = projection_bytes(campaign, events, 0)?;
        let existing = match open_progress(&path) {
            Ok(file) => {
                verify_file(&path, ledger, &file)?;
                Some(file)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let recovered = match &existing {
            Some(file) => !matches_rows(file, campaign, events)?,
            None => true,
        };
        let file = if recovered {
            drop(existing);
            regenerate(&path, campaign, events)?;
            open_progress(&path)?
        } else {
            existing.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "matching progress projection has no open file",
                )
            })?
        };
        if verify_file(&path, ledger, &file)? != bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "progress projection changed during reconciliation",
            ));
        }
        Ok(Self {
            path,
            ledger: ledger.to_path_buf(),
            file,
            bytes,
            rows: events.len(),
            recovered,
        })
    }

    /// Append only events committed since the previous successful ledger commit.
    pub(crate) fn append_new(
        &mut self,
        campaign: Digest,
        events: &[AcceptedEvidence],
    ) -> io::Result<std::ops::Range<usize>> {
        if events.len() < self.rows {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "accepted ledger history shrank",
            ));
        }
        let start = self.rows;
        if start == events.len() {
            return Ok(start..start);
        }
        let added = projection_bytes(campaign, events, start)?;
        let next = self
            .bytes
            .checked_add(added)
            .filter(|&bytes| bytes <= MAX_PROGRESS_BYTES)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "progress projection exceeds 64 MiB bound"))?;
        if verify_file(&self.path, &self.ledger, &self.file)? != self.bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "progress projection changed before append",
            ));
        }
        let mut writer = BufWriter::new(&mut self.file);
        write_rows(&mut writer, campaign, events, start)?;
        writer.flush()?;
        drop(writer);
        self.file.sync_all()?;
        self.bytes = next;
        self.rows = events.len();
        Ok(start..events.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escaping_handles_controls_and_quotes() {
        let mut out = String::new();
        quoted("a\"\\\n\r\t\u{1}", &mut out);
        assert_eq!(out, "\"a\\\"\\\\\\n\\r\\t\\u0001\"");
    }

    fn accepted(path_id: u8, status: angryier_ledger::sustained::Status) -> AcceptedEvidence {
        use angryier_ledger::evidence::{EvidenceDelta, PathEvidence};
        use angryier_types::FidelityProfile;
        AcceptedEvidence {
            work_index: 0,
            attempt: 1,
            replay_digest: Digest([1; 32]),
            status,
            delta: EvidenceDelta {
                sequence: 1,
                path: PathEvidence {
                    path_id: [path_id; 32],
                    provenance_digest: [2; 32],
                    fidelity: FidelityProfile::Explore,
                    blocks: vec![],
                    edges: vec![],
                    branches: vec![],
                    witness: None,
                    semantic_debt: vec![],
                    disposition: PathDisposition::Terminal,
                },
            },
        }
    }

    #[test]
    fn recovery_repairs_truncated_and_lagging_journals_without_duplicates() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("angryier-progress-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let ledger = root.join("campaign.ledger");
        let path = default_path(&ledger);
        let campaign = Digest([9; 32]);
        let one = accepted(1, angryier_ledger::sustained::Status::Completed);
        let two = accepted(2, angryier_ledger::sustained::Status::Deferred);
        let mut journal = ProgressJournal::reconcile(path.clone(), &ledger, campaign, std::slice::from_ref(&one))?;
        assert_eq!(journal.append_new(campaign, std::slice::from_ref(&one))?, 1..1);
        let appended = journal.append_new(campaign, &[one.clone(), two.clone()])?;
        assert_eq!(appended, 1..2);
        assert_eq!(fs::read_to_string(&path)?.lines().count(), 2);

        // A truncated final record is rebuilt from the complete ledger history.
        fs::write(&path, "{\\\"event_id\\\":truncated")?;
        let journal = ProgressJournal::reconcile(path.clone(), &ledger, campaign, &[one.clone(), two.clone()])?;
        assert!(journal.recovered());
        let recovered = fs::read_to_string(&path)?;
        assert_eq!(
            recovered,
            format!("{}{}", event_json(campaign, 0, &one), event_json(campaign, 1, &two))
        );

        // A valid but lagging journal is also completed; subsequent append is empty.
        let _ = ProgressJournal::reconcile(path.clone(), &ledger, campaign, std::slice::from_ref(&one))?;
        let events = [one, two];
        let mut journal = ProgressJournal::reconcile(path.clone(), &ledger, campaign, &events)?;
        assert!(journal.recovered());
        assert_eq!(journal.append_new(campaign, &events)?, 2..2);
        assert_eq!(fs::read_to_string(&path)?, recovered);
        let row = event_json(campaign, 0, &events[0]);
        assert!(row.contains("\"witness_replay_verified\":false"));
        assert!(row.contains("\"semantic_debt\":0"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn swapped_progress_path_never_appends_to_wal() -> io::Result<()> {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("angryier-progress-swap-{}", std::process::id()));
        fs::create_dir_all(&root)?;
        let ledger = root.join("campaign.db");
        let wal = PathBuf::from(format!("{}.wal", ledger.display()));
        let campaign = Digest([7; 32]);
        let one = accepted(1, angryier_ledger::sustained::Status::Completed);
        let two = accepted(2, angryier_ledger::sustained::Status::Deferred);
        fs::write(&ledger, b"authoritative ledger")?;
        fs::write(&wal, b"authoritative WAL")?;
        let ledger_before = fs::read(&ledger)?;
        let wal_before = fs::read(&wal)?;
        for hardlink in [false, true] {
            let path = root.join(if hardlink { "hardlink.jsonl" } else { "symlink.jsonl" });
            let mut journal = ProgressJournal::reconcile(path.clone(), &ledger, campaign, std::slice::from_ref(&one))?;
            fs::remove_file(&path)?;
            if hardlink {
                fs::hard_link(&wal, &path)?;
            } else {
                symlink(&wal, &path)?;
            }
            let Err(error) = journal.append_new(campaign, &[one.clone(), two.clone()]) else {
                return Err(io::Error::other("swapped progress name must not be writable"));
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(journal.rows, 1);
            assert_eq!(fs::read(&wal)?, wal_before);
            assert_eq!(fs::read(&ledger)?, ledger_before);
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn projection_limit_rejects_append_without_partial_row() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("angryier-progress-bound-{}", std::process::id()));
        fs::create_dir_all(&root)?;
        let ledger = root.join("campaign.db");
        let path = default_path(&ledger);
        let campaign = Digest([7; 32]);
        let event = accepted(1, angryier_ledger::sustained::Status::Completed);
        let mut journal = ProgressJournal::reconcile(path.clone(), &ledger, campaign, &[])?;
        journal.bytes = MAX_PROGRESS_BYTES;
        assert!(matches!(
            journal.append_new(campaign, &[event]),
            Err(error) if error.kind() == io::ErrorKind::InvalidData
        ));
        assert_eq!(journal.rows, 0);
        assert!(fs::read(&path)?.is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn progress_paths_cannot_alias_ledger_lock_or_wal() -> io::Result<()> {
        let root = std::env::temp_dir().join(format!("angryier-progress-path-{}", std::process::id()));
        fs::create_dir_all(&root)?;
        let ledger = root.join("campaign.db");
        let wal = PathBuf::from(format!("{}.wal", ledger.display()));
        let protected = [
            ledger.clone(),
            ledger.with_extension("frontier.lock"),
            ledger.with_extension("snap.wal"),
            wal,
        ];
        for target in &protected {
            let Err(error) = ProgressJournal::reconcile(target.clone(), &ledger, Digest([0; 32]), &[]) else {
                return Err(io::Error::other("absent protected path must be rejected"));
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(!target.exists());
        }
        for (index, target) in protected.iter().enumerate() {
            let contents = format!("protected-{index}");
            fs::write(target, &contents)?;
            let check = |path: PathBuf| -> io::Result<()> {
                let Err(error) = ProgressJournal::reconcile(path, &ledger, Digest([0; 32]), &[]) else {
                    return Err(io::Error::other("protected path must be rejected"));
                };
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                Ok(())
            };
            check(target.clone())?;
            let file_name = target
                .file_name()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "protected path has no file name"))?;
            check(root.join("subdir").join("..").join(file_name))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::symlink;
                let link = root.join(format!("alias-{index}"));
                symlink(target, &link)?;
                check(link)?;
                let hardlink = root.join(format!("hardlink-{index}"));
                fs::hard_link(target, &hardlink)?;
                check(hardlink)?;
            }
            assert_eq!(fs::read_to_string(target)?, contents);
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
