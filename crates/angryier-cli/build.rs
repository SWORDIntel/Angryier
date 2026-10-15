//! Bind the compiled CLI to a precise source revision. No git requirement:
//! exported source archives identify themselves explicitly as unknown.
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let result = Command::new("git")
        .arg("-C")
        .arg(manifest)
        .args(args)
        .output()
        .ok()?;
    if !result.status.success() {
        return None;
    }
    let value = String::from_utf8(result.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn main() {
    println!("cargo:rerun-if-env-changed=ANGRYIER_BUILD_SHA");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/packed-refs");
    let source_sha = std::env::var("ANGRYIER_BUILD_SHA")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| git(&["rev-parse", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=ANGRYIER_BUILD_SHA={source_sha}");
}
