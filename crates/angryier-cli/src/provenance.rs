//! Native run provenance and host-checkout comparison.
//! Paths are masked by default: explicit --show-paths is needed for the
//! directory strings; audit logs should normally use SHA-256 identities.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::process::Command;

fn sha256_file(path: &std::path::Path) -> Result<String, String> {
    let mut reader = std::io::BufReader::new(
        std::fs::File::open(path).map_err(|e| format!("binary open failed: {e}"))?,
    );
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buffer).map_err(|e| format!("binary read failed: {e}"))?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn git_head(directory: &std::path::Path) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8(out.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

pub fn doctor(args: &[String]) -> Result<String, String> {
    let show_paths = match args {
        [] => false,
        [flag] if flag == "--show-paths" => true,
        _ => return Err("usage: angryier doctor [--show-paths]".to_string()),
    };
    let binary = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| format!("cannot resolve running executable: {e}"))?;
    let binary_hash = sha256_file(&binary)?;
    let cwd = std::env::current_dir().map_err(|e| format!("cannot access current directory: {e}"))?;
    let cwd_sha = git_head(&cwd);
    let compiled_sha = env!("ANGRYIER_BUILD_SHA");
    let verdict = match cwd_sha.as_deref() {
        Some(sha) if compiled_sha == "unknown" => "unknown-compiled-revision",
        Some(sha) if sha == compiled_sha => "matching-revisions",
        Some(_) => "mismatched-checkout-and-binary",
        None => "no-git-checkout-in-working-directory",
    };

    let mut out = format!(
        "provenance_schema=1\npackage={}\ncompiled_revision={}\nworking_checkout_revision={}\nverdict={}\nbinary_sha256={}\nfeatures=run:{},inspect:{}",
        env!("CARGO_PKG_VERSION"),
        compiled_sha,
        cwd_sha.as_deref().unwrap_or("unknown"),
        verdict,
        binary_hash,
        cfg!(feature = "run"),
        cfg!(feature = "inspect"),
    );
    if show_paths {
        out.push_str(&format!("\nbinary_path={}\nworking_directory={}", binary.display(), cwd.display()));
    } else {
        out.push_str("\npaths=redacted (use --show-paths for local diagnosis)");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_paths_in_default_diagnostics() -> Result<(), String> {
        let out = doctor(&[])?;
        assert!(out.contains("compiled_revision="));
        assert!(out.contains("binary_sha256="));
        assert!(out.contains("paths=redacted"));
        assert!(!out.contains("binary_path="));
        assert!(doctor(&["--invalid".to_string()]).is_err());
        Ok(())
    }
}
