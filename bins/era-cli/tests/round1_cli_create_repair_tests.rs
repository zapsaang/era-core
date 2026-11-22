//! Round-1 audit regression tests for the CLI.
//!
//! Covers:
//! - ENG-RC-03: `era create` must not silently drop symlinks, special files or
//!   unreadable subtrees; empty directories must be reported, not silently lost.
//! - ENG-RC-05: `era repair` on a nonexistent archive must exit non-zero.
//! - ENG-RC-06: the `verify` Degraded error must distinguish missing volumes from
//!   other degraded states (e.g. backup header in use) and carry the warning detail.
//! - ENG-RC-07: the dead `Healthy && needs_repair()` repair branch is gone; repair
//!   output on a degraded archive is produced by the reachable Degraded path.

mod common;

use common::{corrupt_header_magic, create_test_file, era_binary_path};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

const PASSWORD: &str = "round1-cli-audit-password";

/// Run the compiled `era` binary without panicking, so failure paths cannot leave
/// permission-restricted fixtures behind before cleanup.
fn run_era(args: &[&str]) -> Output {
    Command::new(era_binary_path())
        .args(args)
        .output()
        .expect("failed to launch era binary")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn create_simple_archive(src_dir: &Path, archive: &Path, extra_args: &[&str]) {
    let src = src_dir.to_str().unwrap();
    let out = archive.to_str().unwrap();
    let mut args = vec!["create", src, "--output", out, "--password", PASSWORD];
    args.extend_from_slice(extra_args);
    let output = run_era(&args);
    assert!(
        output.status.success(),
        "fixture archive creation failed: {}",
        stderr_of(&output)
    );
}

// ---------------------------------------------------------------------------
// ENG-RC-03: create input collection must fail loudly
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn eng_rc_03_create_fails_on_symlink_in_input_tree() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    create_test_file(&src, "a.txt", b"payload");
    std::os::unix::fs::symlink("a.txt", src.join("link.txt")).unwrap();
    let archive = temp.path().join("symlink.era");

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
        "create must not silently skip a symlink and exit 0; stderr: {stderr}"
    );
    assert!(
        stderr.contains("link.txt"),
        "error must name the offending symlink path: {stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("symbolic link")
            || stderr.to_lowercase().contains("symlink"),
        "error must explain that symlinks are rejected: {stderr}"
    );
    assert!(
        !archive.exists(),
        "no archive should be created when input collection fails"
    );
}

#[cfg(unix)]
#[test]
fn eng_rc_03_create_fails_on_unreadable_subtree() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    let blocked = src.join("blocked");
    fs::create_dir_all(&blocked).unwrap();
    create_test_file(&src, "a.txt", b"payload");
    create_test_file(&blocked, "hidden.txt", b"hidden");
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).unwrap();

    let archive = temp.path().join("unreadable.era");
    let output = run_era(&[
        "create",
        src.to_str().unwrap(),
        "--output",
        archive.to_str().unwrap(),
        "--password",
        PASSWORD,
    ]);

    // Restore before asserting so a failing assertion still leaves a removable tree.
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o755)).unwrap();

    let stderr = stderr_of(&output);
    assert!(
        !output.status.success(),
        "create must not silently drop an unreadable subtree and exit 0; stderr: {stderr}"
    );
    assert!(
        stderr.contains("blocked"),
        "error must include the path of the unreadable subtree: {stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("permission denied")
            || stderr.to_lowercase().contains("denied"),
        "error must include the underlying traversal error: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn eng_rc_03_create_fails_on_special_file() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    create_test_file(&src, "a.txt", b"payload");
    let _listener = std::os::unix::net::UnixListener::bind(src.join("not-a-file.sock")).unwrap();
    let archive = temp.path().join("special.era");

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
        "create must not silently skip a socket and exit 0; stderr: {stderr}"
    );
    assert!(
        stderr.contains("not-a-file.sock"),
        "error must name the unsupported entry: {stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("regular file")
            || stderr.to_lowercase().contains("unsupported"),
        "error must explain that special files cannot be archived: {stderr}"
    );
}

#[test]
fn eng_rc_03_create_warns_about_empty_directories() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    let empty = src.join("empty_dir");
    fs::create_dir_all(&empty).unwrap();
    create_test_file(&src, "a.txt", b"payload");
    let archive = temp.path().join("emptydir.era");

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
        output.status.success(),
        "empty directories must not abort file archiving; stderr: {stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("empty director"),
        "create must explicitly report skipped empty directories instead of losing them silently: {stderr}"
    );
    assert!(
        stderr.contains("empty_dir"),
        "the skipped empty directory path must be reported: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// ENG-RC-05: repair on a nonexistent path must fail
// ---------------------------------------------------------------------------

#[test]
fn eng_rc_05_repair_missing_archive_fails() {
    let temp = TempDir::new().unwrap();
    let missing = temp.path().join("does-not-exist.era");

    let output = run_era(&["repair", missing.to_str().unwrap(), "--password", PASSWORD]);

    let stderr = stderr_of(&output);
    assert!(
        !output.status.success(),
        "repair on a nonexistent archive must exit non-zero; stderr: {stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("not found"),
        "error must state the archive was not found: {stderr}"
    );
    assert!(
        stderr.contains("does-not-exist.era"),
        "error must include the requested path: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// ENG-RC-06: Degraded diagnostics must distinguish the degraded reason
// ---------------------------------------------------------------------------

#[test]
fn eng_rc_06_verify_degraded_without_missing_volumes_does_not_claim_missing_volumes() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    create_test_file(&src, "payload.bin", &vec![0x5A; 64 * 1024]);
    let archive = temp.path().join("backup-header.era");
    create_simple_archive(&src, &archive, &["--erasure", "none", "--no-compression"]);

    corrupt_header_magic(&archive);

    let output = run_era(&["verify", archive.to_str().unwrap(), "--password", PASSWORD]);
    let stderr = stderr_of(&output);
    assert!(
        !output.status.success(),
        "verify must fail when the primary header is damaged (backup in use); stderr: {stderr}"
    );
    assert!(
        stderr.contains("backup header"),
        "degraded error must carry the actual warning reason (backup header in use): {stderr}"
    );
    assert!(
        !stderr.to_lowercase().contains("missing sequence"),
        "all volumes are present; degraded message must not claim missing volume sequences: {stderr}"
    );
}

#[test]
fn eng_rc_06_verify_degraded_with_missing_volumes_reports_them() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    create_test_file(&src, "payload.bin", &vec![0xCD; 256 * 1024]);
    let archive = temp.path().join("missing-volume.era");
    create_simple_archive(
        &src,
        &archive,
        &["--erasure", "4:2", "--volumes", "6", "--no-compression"],
    );

    let missing_volume = archive.with_extension("era.002");
    assert!(missing_volume.exists(), "expected volume 2 to exist");
    fs::remove_file(&missing_volume).unwrap();

    let output = run_era(&["verify", archive.to_str().unwrap(), "--password", PASSWORD]);
    let stderr = stderr_of(&output);
    assert!(
        !output.status.success(),
        "verify with a missing volume must exit non-zero; stderr: {stderr}"
    );
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("missing volume"),
        "degraded error must describe missing volume files: {stderr}"
    );
    assert!(
        lower.contains("missing sequence"),
        "degraded error must include the missing volume sequences: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// ENG-RC-07: repair dead branch removal is observable through the degraded path
// ---------------------------------------------------------------------------

#[test]
fn eng_rc_07_repair_reports_degraded_reason_from_reachable_path() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    create_test_file(&src, "payload.bin", &vec![0xA5; 64 * 1024]);
    let archive = temp.path().join("repair-degraded.era");
    create_simple_archive(&src, &archive, &["--erasure", "none", "--no-compression"]);

    corrupt_header_magic(&archive);

    let output = run_era(&["repair", archive.to_str().unwrap(), "--password", PASSWORD]);
    let stderr = stderr_of(&output);

    // A degraded archive is not "intact": repair must surface the degraded state
    // (reachable Degraded arm) instead of claiming no repair is needed.
    assert!(
        stderr.to_lowercase().contains("degraded")
            || stderr.to_lowercase().contains("backup header"),
        "repair must surface the degraded reason instead of a no-op success: {stderr}"
    );
    assert!(
        !stderr.contains("Archive is intact. No repair needed."),
        "a degraded archive must not be reported as intact: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// ENG-RC-03 (behavior preservation): explicitly named symlinks are still
// followed, as they were before the fix. Only symlink entries discovered while
// walking a directory are rejected.
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn eng_rc_03_explicit_symlink_inputs_keep_follow_semantics() {
    let temp = TempDir::new().unwrap();
    let src = temp.path().join("src");
    create_test_file(&src, "a.txt", b"payload through link");
    let file_link = temp.path().join("link_file.txt");
    std::os::unix::fs::symlink(src.join("a.txt"), &file_link).unwrap();
    let dir_link = temp.path().join("link_dir");
    std::os::unix::fs::symlink(&src, &dir_link).unwrap();

    let archive = temp.path().join("explicit-links.era");
    let create_output = run_era(&[
        "create",
        file_link.to_str().unwrap(),
        dir_link.to_str().unwrap(),
        "--output",
        archive.to_str().unwrap(),
        "--password",
        PASSWORD,
    ]);
    assert!(
        create_output.status.success(),
        "explicitly named symlinks must keep being followed: {}",
        stderr_of(&create_output)
    );

    let list_output = run_era(&["list", archive.to_str().unwrap(), "--password", PASSWORD]);
    assert!(
        list_output.status.success(),
        "list failed: {}",
        stderr_of(&list_output)
    );
    let list_text = format!(
        "{}{}",
        String::from_utf8_lossy(&list_output.stdout),
        stderr_of(&list_output)
    );
    assert!(
        list_text.contains("link_file.txt"),
        "explicit symlink to a file must be archived under its own name: {list_text}"
    );
    assert!(
        list_text.contains("link_dir/a.txt"),
        "explicit symlink to a directory must be walked: {list_text}"
    );
}
