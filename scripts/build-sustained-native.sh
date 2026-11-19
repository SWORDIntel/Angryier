#!/usr/bin/env bash
# Usage: scripts/build-sustained-native.sh [--patch-only] ABS_CARGO_HOME ABS_TARGET_DIR [ABS_RUSTC ABS_CARGO]
# Alternatively set RUSTC and CARGO to absolute paths. Use the same canonical paths,
# staged source, and isolated cache on each node; this script does not stage either.
# --patch-only validates and patches the isolated xed-sys copy without building.
set -euo pipefail

fail() { printf 'sustained native build: %s\n' "$*" >&2; exit 1; }
patch_only=0
if [[ ${1:-} == --patch-only ]]; then patch_only=1; shift; fi
[[ $# -ge 2 && $# -le 4 ]] || fail 'expected ABS_CARGO_HOME ABS_TARGET_DIR [ABS_RUSTC ABS_CARGO]'
[[ -z ${3:-} || -n ${4:-} ]] || fail 'supply both positional tool paths'
cargo_home=$1
target_dir=$2
rustc=${3:-${RUSTC:-}}
cargo=${4:-${CARGO:-}}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd -- "$script_dir/.." && pwd -P)
patch_file=$script_dir/sustained-xed-repro.patch
[[ -f $repo/Cargo.lock && -f $repo/crates/angryier-campaign/Cargo.toml && -f $patch_file ]] || fail 'missing staged source or recipe'
for tool in sha256sum realpath patch; do command -v "$tool" >/dev/null || fail "missing $tool"; done
[[ $cargo_home == /* && -d $cargo_home && ! -L $cargo_home ]] || fail 'CARGO_HOME must be an existing absolute isolated directory'
[[ $(realpath -e -- "$cargo_home") == "$cargo_home" ]] || fail 'CARGO_HOME must be canonical'
[[ $target_dir == /* && $(realpath -m -- "$target_dir") == "$target_dir" ]] || fail 'TARGET_DIR must be absolute and canonical'
if (( ! patch_only )); then
    [[ ! -e $target_dir && ! -L $target_dir ]] || fail 'TARGET_DIR already exists; choose a fresh, previously nonexistent target path for each full build'
fi
[[ $target_dir != "$cargo_home" && $target_dir != "$repo" ]] || fail 'TARGET_DIR must be separate from cache and source'
case "$target_dir/" in "$repo/"*|"$cargo_home/"*) fail 'TARGET_DIR must be outside cache and staged source' ;; esac
case "$cargo_home/" in "$repo/"*) fail 'CARGO_HOME must be outside staged source' ;; esac
default_home=$(realpath -m -- "${HOME:?}/.cargo")
case "$cargo_home/" in "$default_home/"*) fail 'refusing default ~/.cargo registry' ;; esac
for tool in "$rustc" "$cargo"; do
    [[ $tool == /* && -x $tool && ! -L $tool && $(realpath -e -- "$tool") == "$tool" ]] || fail 'Rust tool paths must be absolute canonical executable files'
done
hash() { sha256sum -- "$1" | cut -d ' ' -f 1; }
[[ $(hash "$rustc") == 3690cc576ede140504698405d5d8fa3826aaadbe71699c6c4ed0a565d6f493e2 ]] || fail 'rustc binary does not match pinned 1.98.0 bytes'
[[ $(hash "$cargo") == ff3022fcbd13b08434ea7afde9a0ef9d5b3f5c17b5fc7a40031be3ee000a6a24 ]] || fail 'cargo binary does not match pinned 1.98.0 bytes'
[[ $("$rustc" --version) == 'rustc 1.98.0 (88d9e12ae 2026-08-18)' ]] || fail 'rustc version mismatch'
[[ $("$cargo" --version) == 'cargo 1.98.0 (797e8a9bc 2026-08-05)' ]] || fail 'cargo version mismatch'
[[ $(/usr/bin/gcc -dumpfullversion) == 14.2.0 ]] || fail 'expected /usr/bin/gcc 14.2.0'
[[ $(/usr/bin/ld --version) == 'GNU ld (GNU Binutils for Debian) 2.44'* ]] || fail 'expected /usr/bin/ld 2.44'

crate=$cargo_home/registry/src/index.crates.io-1949cf8c6b5b557f/xed-sys-0.6.0+xed-2024.05.20
file=$crate/xed/xed_mbuild.py
backup=$file.sustained-original
original=fd4568183cc2b2607068e277bf0c564a04ff36572289bf8f4d065f8b14f9d651
patched=7029b412b65fed05f2bf13b745e44aa935c2c6b417d84abbcd8d57c88c8c4478
[[ -f $file && ! -L $file && -d $crate && $(realpath -e -- "$file") == "$file" ]] || fail 'missing or redirected pinned xed-sys source in isolated cache'
if [[ -e $backup || -L $backup ]]; then
    [[ -f $backup && ! -L $backup && $(hash "$backup") == "$original" ]] || fail 'existing dependency backup differs from pinned original'
fi
current=$(hash "$file")
if [[ $current == "$original" ]]; then
    (cd -- "$crate" && patch -p1 --fuzz=0 --batch --dry-run -i "$patch_file") || fail 'xed patch dry-run failed'
    if [[ ! -e $backup ]]; then cp -p -- "$file" "$backup"; fi
    [[ $(hash "$backup") == "$original" ]] || fail 'dependency backup verification failed'
    (cd -- "$crate" && patch -p1 --fuzz=0 --batch -i "$patch_file") || fail 'xed patch failed'
elif [[ $current == "$patched" ]]; then
    [[ -f $backup ]] || fail 'patched dependency lacks original backup'
else
    fail 'xed-sys source differs from pinned original and patched hashes'
fi
[[ $(hash "$file") == "$patched" ]] || fail 'xed patch hash mismatch'
if (( patch_only )); then exit 0; fi
if ! { mkdir -p -- "$(dirname -- "$target_dir")" && mkdir -- "$target_dir"; }; then fail 'TARGET_DIR already exists or cannot be created; choose a fresh target path for each full build'; fi
cd -- "$repo"
exec env -i HOME="${HOME:?}" CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$target_dir" \
    RUSTC="$rustc" RUSTFLAGS=-Cdebuginfo=0 PYTHONHASHSEED=0 PATH=/usr/bin:/bin \
    "$cargo" build --locked --offline --release -p angryier-campaign --jobs 2
