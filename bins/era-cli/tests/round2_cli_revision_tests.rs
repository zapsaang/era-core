//! Round-2 revision regression tests for the CLI.
//!
//! Covers the findings from the independent round-2 review:
//! - R2-STOR-01: a relative bare output file name must not trigger a bogus
//!   "failed to open storage parent directory" warning (the parent of
//!   "backup.era" is the current directory, not the empty path).
//! - R2-CLI-02: create must offer an explicit "--skip-symlinks" policy that
//!   skips (and counts) symlinks found in walked trees while the default stays
//!   fail-closed; explicitly named symlink inputs keep follow semantics.
//! - R2-02: "era extract --max-output-bytes" must plumb a decoded-output budget
//!   into ExtractOptions::max_total_output_bytes.
//! - R2-VERIFY-01: degraded verify warnings must be printed once, not repeated in
//!   the bail reason.
//! - R2-REPAIR-02: the repair exit-code contract is documented in --help.

mod common;

use common::{corrupt_header_magic, create_test_file, era_binary_path};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

const PASSWORD: &str = "round2-cli-revision-password";

fn run_era(args: &[&str]) -> Output {
    Command::new(era_binary_path())
        .args(args)
        .output()
        .expect("failed to launch era binary")
}

/// Run the binary with a specific working directory (needed for relative output paths).
fn run_era_in(dir: &Path, args: &[&str]) -> Output {
    Command::new(era_binary_path())
        .current_dir(dir)
        .args(args)
        .output()
        .expect("failed to launch era binary")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn create_simple_archive(src_dir: &Path, archive: &Path, extra_args: &[&str]) {
    let mut args = vec![
        "create",
        src_dir.to_str().unwrap(),
        "--output",
        archive.to_str().unwrap(),
        "--password",
        PASSWORD,
    ];
    args.extend_from_slice(extra_args);
    let output = run_era(&args);
    assert!(
        output.status.success(),
        "fixture archive creation failed: {}",
        stderr_of(&output)
    );
}

#[cfg(unix)]
fn create_symlink_tree(root: &Path) -> std::path::PathBuf {
    let src = root.join("src");
    create_test_file(&src, "a.txt", b"payload through the archive");
    std::os::unix::fs::symlink("a.txt", src.join("link_file.txt")).unwrap();
    std::os::unix::fs::symlink(&src, src.join("link_dir")).unwrap();
    std::os::unix::fs::symlink("missing-target", src.join("broken_link")).unwrap();
    src
}

// ---------------------------------------------------------------------------
// R2-STOR-01: relative bare output file names must not warn about fsync
// ---------------------------------------------------------------------------

#[test]
fn r2_stor_01_relative_bare_output_does_not_warn_about_parent_fsync() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    create_test_file(&src, "a.txt", b"payload");

    // The Quick Start form: "era create -o backup.era ..." with a bare relative
    // output name whose parent is the current directory (""), not the empty path.
    let output = run_era_in(
        temp.path(),
        &[
            "create",
            src.to_str().unwrap(),
            "-o",
            "rel.era",
            "-p",
            PASSWORD,
        ],
    );

    let stderr = stderr_of(&output);
    assert!(
        output.status.success(),
        "relative bare output create failed: {stderr}"
    );
    assert!(
        temp.path().join("rel.era").exists(),
        "archive must be created for a relative bare output name"
    );
    assert!(
        !stderr.contains("failed to open storage parent directory"),
        "the parent directory of a bare relative path is '.', not the empty path; \
         directory fsync must not fail (R2-STOR-01): {stderr}"
    );
    assert!(
        !stderr.contains("failed to fsync storage parent directory"),
        "directory fsync of '.' must succeed: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// R2-CLI-02: explicit symlink policy for create
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn r2_cli_02_skip_symlinks_skips_and_counts_them() {
    let temp = TempDir::new().unwrap();
    let src = create_symlink_tree(temp.path());
    let archive = temp.path().join("skip-links.era");

    let output = run_era(&[
        "create",
        src.to_str().unwrap(),
        "--output",
        archive.to_str().unwrap(),
        "--password",
        PASSWORD,
        "--skip-symlinks",
    ]);

    let stderr = stderr_of(&output);
    assert!(
        output.status.success(),
        "create --skip-symlinks must succeed on a tree containing symlinks; stderr: {stderr}"
    );
    assert!(
        archive.exists(),
        "an archive must be produced when symlinks are skipped"
    );
    assert!(
        stderr.contains("Skipped 3 symbolic links"),
        "skipped symlinks must be counted in a warning: {stderr}"
    );
    assert!(
        stderr.contains("link_file.txt") && stderr.contains("broken_link"),
        "each skipped symlink path must be reported: {stderr}"
    );

    let list = run_era(&["list", archive.to_str().unwrap(), "--password", PASSWORD]);
    assert!(list.status.success(), "list failed: {}", stderr_of(&list));
    let listing = format!("{}{}", stdout_of(&list), stderr_of(&list));
    assert!(
        listing.contains("a.txt"),
        "regular files must still be archived: {listing}"
    );
    assert!(
        !listing.contains("link_file.txt"),
        "skipped symlinks must not appear in the archive: {listing}"
    );
}

#[cfg(unix)]
#[test]
fn r2_cli_02_default_policy_still_rejects_symlinks() {
    let temp = TempDir::new().unwrap();
    let src = create_symlink_tree(temp.path());
    let archive = temp.path().join("reject-links.era");

    let output = run_era(&[
        "create",
        src.to_str().unwrap(),
        "--output",
        archive.to_str().unwrap(),
        "--password",
        PASSWORD,
    ]);

    let stderr = stderr_of(&output);
    assert!(
        !output.status.success(),
        "without --skip-symlinks the default policy must stay fail-closed: {stderr}"
    );
    assert!(
        stderr.contains("link_file.txt")
            || stderr.contains("link_dir")
            || stderr.contains("broken_link"),
        "the offending symlink path must be named: {stderr}"
    );
    assert!(
        stderr.contains("--skip-symlinks"),
        "the error must point at the escape hatch: {stderr}"
    );
    assert!(!archive.exists(), "no archive must be created on rejection");
}

// ---------------------------------------------------------------------------
// R2-02: extract --max-output-bytes
// ---------------------------------------------------------------------------

#[test]
fn r2_02_extract_max_output_bytes_rejects_oversized_output() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    create_test_file(&src, "payload.bin", &vec![0x5A; 256 * 1024]);
    let archive = temp.path().join("budget.era");
    create_simple_archive(&src, &archive, &["--no-compression", "--erasure", "none"]);
    let out_dir = temp.path().join("out");

    let output = run_era(&[
        "extract",
        archive.to_str().unwrap(),
        "--output",
        out_dir.to_str().unwrap(),
        "--password",
        PASSWORD,
        "--max-output-bytes",
        "1024",
    ]);

    let stderr = stderr_of(&output);
    assert!(
        !output.status.success(),
        "extraction must fail when the decoded output budget is exceeded; stderr: {stderr}"
    );
    assert!(
        stderr.contains("output budget exceeded"),
        "the failure must name the output budget (from ExtractOptions::max_total_output_bytes): {stderr}"
    );
}

#[test]
fn r2_02_extract_max_output_bytes_allows_within_budget() {
    let temp = TempDir::new().unwrap();
    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    let src = temp.path().join("src");
    create_test_file(&src, "payload.bin", &payload);
    let archive = temp.path().join("within-budget.era");
    create_simple_archive(&src, &archive, &["--no-compression", "--erasure", "none"]);
    let out_dir = temp.path().join("out");

    let output = run_era(&[
        "extract",
        archive.to_str().unwrap(),
        "--output",
        out_dir.to_str().unwrap(),
        "--password",
        PASSWORD,
        "--max-output-bytes",
        "10000000",
    ]);

    let stderr = stderr_of(&output);
    assert!(
        output.status.success(),
        "a generous --max-output-bytes must allow extraction; stderr: {stderr}"
    );
    // The archive entry keeps the walked path ("src/payload.bin").
    assert_eq!(
        fs::read(out_dir.join("src").join("payload.bin")).unwrap(),
        payload,
        "extracted bytes must match the archived payload"
    );
}

#[test]
fn r2_02_extract_rejects_invalid_max_output_bytes_value() {
    let output = run_era(&[
        "extract",
        "whatever.era",
        "--max-output-bytes",
        "not-a-number",
    ]);

    let stderr = stderr_of(&output);
    assert!(
        !output.status.success(),
        "an unparsable --max-output-bytes must be rejected; stderr: {stderr}"
    );
    assert!(
        stderr.contains("max-output-bytes"),
        "the error must name the offending option: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// R2-VERIFY-01: degraded warnings must be printed once
// ---------------------------------------------------------------------------

#[test]
fn r2_verify_01_degraded_warning_is_not_duplicated() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    create_test_file(&src, "payload.bin", &vec![0x5A; 64 * 1024]);
    let archive = temp.path().join("degraded.era");
    create_simple_archive(&src, &archive, &["--erasure", "none", "--no-compression"]);
    corrupt_header_magic(&archive);

    let output = run_era(&["verify", archive.to_str().unwrap(), "--password", PASSWORD]);
    let stderr = stderr_of(&output);
    assert!(
        !output.status.success(),
        "verify must fail on a degraded archive; stderr: {stderr}"
    );
    // The CLI prints the warning detail in its Warnings list and used to repeat the
    // same text in the bail reason; the error must only carry a summary.
    let warning_lines = stderr
        .lines()
        .filter(|line| {
            line.contains("1. Volume 0: using backup header; primary header still requires repair")
        })
        .count();
    assert_eq!(
        warning_lines, 1,
        "the degraded warning must appear exactly once in the CLI warnings list; stderr: {stderr}"
    );
    let bail_line = stderr
        .lines()
        .find(|line| line.contains("Archive verification degraded"))
        .unwrap_or_default();
    assert!(
        !bail_line.contains("primary header still requires repair"),
        "the bail reason must not repeat the warning detail (it is already listed above): {bail_line}"
    );
}

// ---------------------------------------------------------------------------
// Help/documentation contract for the round-2 additions
// ---------------------------------------------------------------------------

#[test]
fn r2_help_documents_symlink_policy_budget_and_repair_exit_codes() {
    let create_help = stdout_of(&run_era(&["create", "--help"]));
    assert!(
        create_help.contains("--skip-symlinks"),
        "create --help must document the symlink policy flag: {create_help}"
    );

    let extract_help = stdout_of(&run_era(&["extract", "--help"]));
    assert!(
        extract_help.contains("--max-output-bytes"),
        "extract --help must document the output budget flag: {extract_help}"
    );

    let repair_help = stdout_of(&run_era(&["repair", "--help"]));
    assert!(
        repair_help.contains("Exit status"),
        "repair --help must document the exit-code contract: {repair_help}"
    );
    assert!(
        repair_help.to_lowercase().contains("non-zero")
            || repair_help.contains("exits 1")
            || repair_help.contains("exit code 1"),
        "repair --help must state that a missing/unrepairable archive exits non-zero: {repair_help}"
    );
}
