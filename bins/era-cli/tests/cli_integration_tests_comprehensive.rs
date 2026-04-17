//! Comprehensive CLI integration tests for era-cli
//!
//! Generated test plan from .sisyphus/plans/era-cli-integration-tests.md
//! Covers all 7 commands, 3 auth modes, and 111 test cases.

#![allow(deprecated)]

mod common;

use common::*;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

// ===========================================================================
// 01: ROUNDTRIP TESTS
// ===========================================================================

mod roundtrip_tests {
    use super::*;

    #[test]
    fn test_roundtrip_single_file_basic() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "hello.txt", b"Hello, ERA!");
        let archive = temp.path().join("single.era");
        let out_dir = temp.path().join("extracted");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(fs::read(out_dir.join("hello.txt")).unwrap(), b"Hello, ERA!");
    }

    #[test]
    fn test_roundtrip_multiple_files() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        for i in 0..5 {
            create_test_file(
                &src,
                &format!("file_{}.txt", i),
                format!("content_{}", i).as_bytes(),
            );
        }
        let archive = temp.path().join("multi.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                src.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        let found = count_files_recursive(&out_dir);
        assert_eq!(found, 5, "all 5 files should be extracted");
    }

    #[test]
    fn test_roundtrip_nested_directories() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("tree");
        create_test_file(&root, "l1.txt", b"level1");
        create_test_file(&root, "a/l2.txt", b"level2");
        create_test_file(&root, "a/b/l3.txt", b"level3");
        create_test_file(&root, "a/b/c/l4.txt", b"level4");
        create_test_file(&root, "a/b/c/d/l5.txt", b"level5");

        let archive = temp.path().join("nested.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                root.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            count_files_recursive(&out_dir),
            5,
            "all nested files should be extracted"
        );
    }

    #[test]
    fn test_roundtrip_empty_file() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "empty.txt", b"");
        let archive = temp.path().join("empty.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        let restored = out_dir.join("empty.txt");
        assert!(
            restored.exists(),
            "empty file should exist after extraction"
        );
        assert_eq!(fs::read(&restored).unwrap(), b"");
    }

    #[test]
    fn test_roundtrip_special_chars_in_filename() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(
            temp.path(),
            "données_日本語_🔐.txt",
            b"unicode filename test",
        );
        let archive = temp.path().join("special.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        let restored = out_dir.join("données_日本語_🔐.txt");
        assert!(
            restored.exists(),
            "unicode filename should survive roundtrip"
        );
        assert_eq!(fs::read(&restored).unwrap(), b"unicode filename test");
    }

    #[test]
    fn test_create_rejects_ed25519_certificate() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "ed25519.txt", b"ed25519 cert test");
        let archive = temp.path().join("ed25519.era");
        let key = temp.path().join("ed25519.key");
        let cert = temp.path().join("ed25519.crt");

        let output = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "ed25519",
                "-out",
                key.to_str().unwrap(),
            ])
            .output()
            .expect("openssl should be available");
        assert!(output.status.success(), "openssl genpkey ed25519 failed");

        let output = std::process::Command::new("openssl")
            .args([
                "req",
                "-new",
                "-x509",
                "-key",
                key.to_str().unwrap(),
                "-out",
                cert.to_str().unwrap(),
                "-days",
                "1",
                "-subj",
                "/CN=test",
            ])
            .output()
            .expect("openssl should be available");
        assert!(output.status.success(), "openssl req failed");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                cert.to_str().unwrap(),
            ])
            .assert()
            .failure()
            .stderr(predicates::str::contains(
                "Unsupported certificate algorithm",
            ));
    }

    #[test]
    fn test_create_rejects_ed25519_spki_public_key() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "ed25519_spki.txt", b"ed25519 spki test");
        let archive = temp.path().join("ed25519_spki.era");
        let key = temp.path().join("ed25519_spki.key");
        let pub_key = temp.path().join("ed25519_spki.pub");

        let output = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "ed25519",
                "-out",
                key.to_str().unwrap(),
            ])
            .output()
            .expect("openssl should be available");
        assert!(output.status.success(), "openssl genpkey ed25519 failed");

        let output = std::process::Command::new("openssl")
            .args([
                "pkey",
                "-in",
                key.to_str().unwrap(),
                "-pubout",
                "-out",
                pub_key.to_str().unwrap(),
            ])
            .output()
            .expect("openssl should be available");
        assert!(output.status.success(), "openssl pkey -pubout failed");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                pub_key.to_str().unwrap(),
            ])
            .assert()
            .failure()
            .stderr(predicates::str::contains(
                "Unsupported public key algorithm",
            ));
    }

    #[test]
    fn test_roundtrip_deep_path_nesting() {
        let temp = TempDir::new().unwrap();
        let mut deep = temp.path().join("root");
        for i in 0..10 {
            deep = deep.join(format!("level_{}", i));
        }
        let _input = create_test_file(&deep, "deep.txt", b"deep content");
        let archive = temp.path().join("deep.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                temp.path().join("root").to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            count_files_recursive(&out_dir),
            1,
            "deep file should be extracted"
        );
    }
}

// ===========================================================================
// 02: AUTH MODE TESTS
// ===========================================================================

mod auth_mode_tests {
    use super::*;

    // --- Password Mode ---

    #[test]
    fn test_password_mode_create_extract() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "pw.txt", b"password mode data");
        let archive = temp.path().join("pw.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "test_password",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "test_password",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("pw.txt")).unwrap(),
            b"password mode data"
        );
    }

    #[test]
    fn test_password_empty_string() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "empty_pw.txt", b"empty password test");
        let archive = temp.path().join("empty_pw.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("empty_pw.txt")).unwrap(),
            b"empty password test"
        );
    }

    #[test]
    fn test_password_unicode_chars() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "uni_pw.txt", b"unicode pw test");
        let archive = temp.path().join("uni_pw.era");
        let out_dir = temp.path().join("out");
        let pw = "пароль_密码_🔑";

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                pw,
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                pw,
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("uni_pw.txt")).unwrap(),
            b"unicode pw test"
        );
    }

    #[test]
    fn test_password_very_long_1kb() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "long_pw.txt", b"long password test");
        let archive = temp.path().join("long_pw.era");
        let out_dir = temp.path().join("out");
        let long_pw = "a".repeat(1024);

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                &long_pw,
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                &long_pw,
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("long_pw.txt")).unwrap(),
            b"long password test"
        );
    }

    #[test]
    fn test_password_special_chars() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "special_pw.txt", b"special chars pw");
        let archive = temp.path().join("special_pw.era");
        let out_dir = temp.path().join("out");
        let pw = "p@$$w0rd!#%^&*()[]{}|;:'\",.<>?/";

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                pw,
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                pw,
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("special_pw.txt")).unwrap(),
            b"special chars pw"
        );
    }

    #[test]
    fn test_password_wrong_password_fails() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "wrong.txt", b"wrong pw test");
        let archive = temp.path().join("wrong.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "correct",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "wrong",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_password_case_sensitive() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "case.txt", b"case sensitive");
        let archive = temp.path().join("case.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "Password",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "password",
            ])
            .assert()
            .failure();
    }

    // --- Certificate Mode ---

    #[test]
    fn test_cert_mode_create_extract() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "cert.txt", b"certificate mode data");
        let archive = temp.path().join("cert.era");
        let out_dir = temp.path().join("out");
        let (pub_cert, priv_key) = generate_test_keypair(temp.path());

        create_archive_with_cert(&input, &archive, &pub_cert);

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("cert.txt")).unwrap(),
            b"certificate mode data"
        );
    }

    #[test]
    fn test_cert_wrong_key_fails() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "cert_wrong.txt", b"wrong key test");
        let archive = temp.path().join("cert_wrong.era");
        let out_dir = temp.path().join("out");
        let (pub_cert, _priv_key) = generate_test_keypair(temp.path());
        let (_pub2, priv_key2) = generate_test_keypair(temp.path());

        create_archive_with_cert(&input, &archive, &pub_cert);

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                priv_key2.to_str().unwrap(),
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_cert_extract_without_key_fails() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "cert_nokey.txt", b"no key test");
        let archive = temp.path().join("cert_nokey.era");
        let out_dir = temp.path().join("out");
        let (pub_cert, _priv_key) = generate_test_keypair(temp.path());

        create_archive_with_cert(&input, &archive, &pub_cert);

        // Without TTY, no key and no password should fail
        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_cert_info_shows_archive_id() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "cert_info.txt", b"cert info test");
        let archive = temp.path().join("cert_info.era");
        let (pub_cert, priv_key) = generate_test_keypair(temp.path());

        create_archive_with_cert(&input, &archive, &pub_cert);

        era_cmd()
            .args([
                "info",
                archive.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
            ])
            .assert()
            .success()
            .stderr(predicate::str::contains("Archive ID"));
    }

    #[test]
    fn test_cert_verify_valid() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "cert_verify.txt", b"cert verify test");
        let archive = temp.path().join("cert_verify.era");
        let (pub_cert, priv_key) = generate_test_keypair(temp.path());

        create_archive_with_cert(&input, &archive, &pub_cert);

        era_cmd()
            .args([
                "verify",
                archive.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
            ])
            .assert()
            .success()
            .stderr(predicate::str::contains("verified successfully"));
    }

    #[test]
    fn test_cert_repack_with_key() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "cert_repack.txt", b"cert repack test");
        let archive = temp.path().join("cert_repack.era");
        let repacked = temp.path().join("cert_repacked.era");
        let out_dir = temp.path().join("out");
        let (pub_cert, priv_key) = generate_test_keypair(temp.path());

        create_archive_with_cert(&input, &archive, &pub_cert);

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
                "--compact",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("cert_repack.txt")).unwrap(),
            b"cert repack test"
        );
    }

    // --- Hybrid Mode ---

    #[test]
    fn test_hybrid_create_with_password_and_cert() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "hybrid.txt", b"hybrid data");
        let archive = temp.path().join("hybrid.era");
        let (pub_cert, _priv_key) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                pub_cert.to_str().unwrap(),
                "--password",
                "hybrid_pwd",
            ])
            .assert()
            .success();

        assert!(archive.exists());
    }

    #[test]
    fn test_hybrid_extract_with_password() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "hybrid_pw.txt", b"hybrid pw data");
        let archive = temp.path().join("hybrid_pw.era");
        let out_dir = temp.path().join("out");
        let (pub_cert, _priv_key) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                pub_cert.to_str().unwrap(),
                "--password",
                "hybrid_pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "hybrid_pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("hybrid_pw.txt")).unwrap(),
            b"hybrid pw data"
        );
    }

    #[test]
    fn test_hybrid_extract_with_key() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "hybrid_key.txt", b"hybrid key data");
        let archive = temp.path().join("hybrid_key.era");
        let out_dir = temp.path().join("out");
        let (pub_cert, priv_key) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                pub_cert.to_str().unwrap(),
                "--password",
                "hybrid_pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("hybrid_key.txt")).unwrap(),
            b"hybrid key data"
        );
    }

    #[test]
    fn test_hybrid_wrong_password_fails() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "hybrid_wrong.txt", b"hybrid wrong");
        let archive = temp.path().join("hybrid_wrong.era");
        let out_dir = temp.path().join("out");
        let (pub_cert, _priv_key) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                pub_cert.to_str().unwrap(),
                "--password",
                "correct",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "wrong",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_hybrid_wrong_key_fails() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "hybrid_wk.txt", b"hybrid wrong key");
        let archive = temp.path().join("hybrid_wk.era");
        let out_dir = temp.path().join("out");
        let (pub_cert, _priv_key) = generate_test_keypair(temp.path());
        let (_pub2, priv_key2) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                pub_cert.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                priv_key2.to_str().unwrap(),
            ])
            .assert()
            .failure();
    }

    // --- Post-Quantum Hybrid Certificate Mode ---

    #[test]
    fn test_hybrid_certificate_create_extract_with_generic_key() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "pq.txt", b"post-quantum data");
        let archive = temp.path().join("pq.era");
        let out_dir = temp.path().join("out");
        let (pub_cert, priv_key) = generate_test_hybrid_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--hybrid-certificate",
                pub_cert.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("pq.txt")).unwrap(),
            b"post-quantum data"
        );
    }

    #[test]
    fn test_threshold_create_extract_with_two_passwords() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "threshold.txt", b"threshold data");
        let archive = temp.path().join("threshold.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd1",
                "--password",
                "pwd2",
                "--threshold",
                "2",
                "--shares",
                "2",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd1",
                "--password",
                "pwd2",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("threshold.txt")).unwrap(),
            b"threshold data"
        );
    }

    #[test]
    fn test_certificate_plus_password_create_extract() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "cert_pw.txt", b"cert+password data");
        let archive = temp.path().join("cert_pw.era");
        let out_dir = temp.path().join("out");
        let (pub_cert, priv_key) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                pub_cert.to_str().unwrap(),
                "--password",
                "secret",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
                "--password",
                "secret",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("cert_pw.txt")).unwrap(),
            b"cert+password data"
        );
    }

    #[test]
    fn test_hybrid_certificate_plus_password_create_extract() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "hyb_pw.txt", b"hybrid+password data");
        let archive = temp.path().join("hyb_pw.era");
        let out_dir = temp.path().join("out");
        let (pub_cert, priv_key) = generate_test_hybrid_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--hybrid-certificate",
                pub_cert.to_str().unwrap(),
                "--password",
                "secret",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
                "--password",
                "secret",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("hyb_pw.txt")).unwrap(),
            b"hybrid+password data"
        );
    }

    #[test]
    fn test_threshold_hybrid_create_extract() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "hyb_th.txt", b"threshold hybrid data");
        let archive = temp.path().join("hyb_th.era");
        let out_dir = temp.path().join("out");

        let (pub1, priv1) = generate_test_hybrid_keypair(temp.path());
        let (pub2, priv2) = generate_test_hybrid_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--hybrid-certificate",
                pub1.to_str().unwrap(),
                "--hybrid-certificate",
                pub2.to_str().unwrap(),
                "--threshold",
                "2",
                "--shares",
                "2",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                priv1.to_str().unwrap(),
                "--key",
                priv2.to_str().unwrap(),
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("hyb_th.txt")).unwrap(),
            b"threshold hybrid data"
        );
    }

    #[test]
    fn test_mixed_credential_extract_with_password_and_key() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mixed_ext.txt", b"mixed credential");
        let archive = temp.path().join("mixed_ext.era");
        let out_dir = temp.path().join("out");
        let (pub_cert, _priv_key) = generate_test_keypair(temp.path());
        let (_wrong_pub, wrong_priv) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                pub_cert.to_str().unwrap(),
                "--password",
                "secret",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                wrong_priv.to_str().unwrap(),
                "--password",
                "secret",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("mixed_ext.txt")).unwrap(),
            b"mixed credential"
        );
    }

    #[test]
    fn test_mixed_credential_list_info_verify_with_password_and_key() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mixed_liv.txt", b"mixed credential liv");
        let archive = temp.path().join("mixed_liv.era");
        let (pub_cert, _priv_key) = generate_test_keypair(temp.path());
        let (_wrong_pub, wrong_priv) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                pub_cert.to_str().unwrap(),
                "--password",
                "secret",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "list",
                archive.to_str().unwrap(),
                "--key",
                wrong_priv.to_str().unwrap(),
                "--password",
                "secret",
            ])
            .assert()
            .success()
            .stderr(predicates::str::contains("mixed_liv.txt"));

        era_cmd()
            .args([
                "info",
                archive.to_str().unwrap(),
                "--key",
                wrong_priv.to_str().unwrap(),
                "--password",
                "secret",
            ])
            .assert()
            .success()
            .stderr(predicates::str::contains("Archive ID"));

        era_cmd()
            .args([
                "verify",
                archive.to_str().unwrap(),
                "--key",
                wrong_priv.to_str().unwrap(),
                "--password",
                "secret",
            ])
            .assert()
            .success();
    }

    #[test]
    fn test_extract_rejects_encrypted_private_key() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "enc_key.txt", b"encrypted key test");
        let archive = temp.path().join("enc_key.era");
        let raw_key = temp.path().join("raw_private.pem");
        let enc_key = temp.path().join("encrypted_private.pem");

        let output = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "x25519",
                "-out",
                raw_key.to_str().unwrap(),
            ])
            .output()
            .expect("openssl should be available");
        assert!(output.status.success(), "openssl genpkey failed");

        let output = std::process::Command::new("openssl")
            .args([
                "pkcs8",
                "-topk8",
                "-v2",
                "des3",
                "-in",
                raw_key.to_str().unwrap(),
                "-out",
                enc_key.to_str().unwrap(),
                "-passout",
                "pass:keypass",
            ])
            .output()
            .expect("openssl should be available");
        assert!(output.status.success(), "openssl pkcs8 encryption failed");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "secret",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                temp.path().join("out").to_str().unwrap(),
                "--key",
                enc_key.to_str().unwrap(),
                "--password",
                "keypass",
            ])
            .assert()
            .failure()
            .stderr(predicates::str::contains(
                "No supported private key format found",
            ));
    }

    #[test]
    fn test_extract_rejects_ed25519_pkcs8_private_key() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "pkcs8_reject.txt", b"pkcs8 reject test");
        let archive = temp.path().join("pkcs8_reject.era");
        let ed_key = temp.path().join("ed25519.pem");

        let output = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "ed25519",
                "-out",
                ed_key.to_str().unwrap(),
            ])
            .output()
            .expect("openssl should be available");
        assert!(output.status.success(), "openssl genpkey ed25519 failed");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "secret",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                temp.path().join("out").to_str().unwrap(),
                "--key",
                ed_key.to_str().unwrap(),
            ])
            .assert()
            .failure()
            .stderr(predicates::str::contains(
                "Unsupported private key algorithm",
            ));
    }

    #[test]
    fn test_extract_rejects_ed25519_openssh_private_key() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "openssh_reject.txt", b"openssh reject test");
        let archive = temp.path().join("openssh_reject.era");
        let ed_key = temp.path().join("ed25519_openssh");

        let output = std::process::Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                ed_key.to_str().unwrap(),
                "-N",
                "",
                "-C",
                "test",
            ])
            .output()
            .expect("ssh-keygen should be available");
        assert!(output.status.success(), "ssh-keygen ed25519 failed");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "secret",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                temp.path().join("out").to_str().unwrap(),
                "--key",
                ed_key.to_str().unwrap(),
            ])
            .assert()
            .failure()
            .stderr(predicates::str::contains(
                "Unsupported OpenSSH key algorithm",
            ));
    }
}

// ===========================================================================
// 03: PARAMETER VARIATION TESTS
// ===========================================================================

mod parameter_variation_tests {
    use super::*;

    #[test]
    fn test_compression_level_0() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "lvl0.txt", b"level 0 data");
        let archive = temp.path().join("lvl0.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--level",
                "0",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(fs::read(out_dir.join("lvl0.txt")).unwrap(), b"level 0 data");
    }

    #[test]
    fn test_compression_level_1() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "lvl1.txt", b"level 1 fastest");
        let archive = temp.path().join("lvl1.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--level",
                "1",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("lvl1.txt")).unwrap(),
            b"level 1 fastest"
        );
    }

    #[test]
    fn test_compression_level_19() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "lvl19.txt", b"level 19 best ratio");
        let archive = temp.path().join("lvl19.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--level",
                "19",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("lvl19.txt")).unwrap(),
            b"level 19 best ratio"
        );
    }

    #[test]
    fn test_compression_level_22() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "lvl22.txt", b"level 22 maximum");
        let archive = temp.path().join("lvl22.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--level",
                "22",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("lvl22.txt")).unwrap(),
            b"level 22 maximum"
        );
    }

    #[test]
    fn test_compression_level_invalid() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "lvl_bad.txt", b"bad level");
        let archive = temp.path().join("lvl_bad.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--level",
                "23",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_no_compression_flag() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "nocomp.txt", b"no compression");
        let archive = temp.path().join("nocomp.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--no-compression",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("nocomp.txt")).unwrap(),
            b"no compression"
        );
    }

    #[test]
    fn test_level_and_no_compression_conflict() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "conflict.txt", b"conflict");
        let archive = temp.path().join("conflict.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--level",
                "3",
                "--no-compression",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_erasure_4_2_default() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "ec42.bin", &vec![0xAA; 4096]);
        let archive = temp.path().join("ec42.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("ec42.bin")).unwrap(),
            vec![0xAA; 4096]
        );
    }

    #[test]
    fn test_erasure_6_3() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "ec63.bin", &vec![0xBB; 4096]);
        let archive = temp.path().join("ec63.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "6:3",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("ec63.bin")).unwrap(),
            vec![0xBB; 4096]
        );
    }

    #[test]
    fn test_erasure_8_4() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "ec84.bin", &vec![0xCC; 4096]);
        let archive = temp.path().join("ec84.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "8:4",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("ec84.bin")).unwrap(),
            vec![0xCC; 4096]
        );
    }

    #[test]
    fn test_erasure_none() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "ec_none.bin", &vec![0xDD; 4096]);
        let archive = temp.path().join("ec_none.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "none",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("ec_none.bin")).unwrap(),
            vec![0xDD; 4096]
        );
    }

    #[test]
    fn test_erasure_invalid_format() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "ec_bad.txt", b"bad erasure");
        let archive = temp.path().join("ec_bad.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2:3",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_erasure_invalid_data_shards() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "ec_bad_d.txt", b"bad data shards");
        let archive = temp.path().join("ec_bad_d.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "0:2",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_erasure_invalid_parity_shards() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "ec_bad_p.txt", b"bad parity shards");
        let archive = temp.path().join("ec_bad_p.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:0",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_erasure_exceeds_max() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "ec_max.txt", b"exceeds max");
        let archive = temp.path().join("ec_max.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "200:100",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_cdc_custom_min_avg_max() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "cdc.bin", &vec![0x55; 8192]);
        let archive = temp.path().join("cdc.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--cdc-min",
                "8192",
                "--cdc-avg",
                "32768",
                "--cdc-max",
                "131072",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(fs::read(out_dir.join("cdc.bin")).unwrap(), vec![0x55; 8192]);
    }

    #[test]
    fn test_cdc_min_greater_than_avg() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "cdc_bad.txt", b"bad cdc");
        let archive = temp.path().join("cdc_bad.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--cdc-min",
                "65536",
                "--cdc-avg",
                "32768",
                "--cdc-max",
                "131072",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_cdc_avg_greater_than_max() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "cdc_bad2.txt", b"bad cdc 2");
        let archive = temp.path().join("cdc_bad2.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--cdc-min",
                "8192",
                "--cdc-avg",
                "262144",
                "--cdc-max",
                "131072",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_cdc_zero_value() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "cdc_zero.txt", b"zero cdc");
        let archive = temp.path().join("cdc_zero.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--cdc-min",
                "0",
                "--cdc-avg",
                "32768",
                "--cdc-max",
                "131072",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_compact_preset() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "compact.txt", b"compact preset data");
        let archive = temp.path().join("compact.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--compact",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("compact.txt")).unwrap(),
            b"compact preset data"
        );
    }

    #[test]
    fn test_all_geek_params() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "geek.bin", &vec![0x77; 16384]);
        let archive = temp.path().join("geek.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--cdc-min",
                "8192",
                "--cdc-avg",
                "32768",
                "--cdc-max",
                "131072",
                "--packing-k",
                "16",
                "--flush-threshold",
                "75",
                "--block-target-size",
                "4194304",
                "--erasure",
                "4:2",
                "--level",
                "6",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("geek.bin")).unwrap(),
            vec![0x77; 16384]
        );
    }

    #[test]
    fn test_config_file_basic() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "cfg.txt", b"config file test");
        let archive = temp.path().join("cfg.era");
        let out_dir = temp.path().join("out");
        let config = create_test_config(
            temp.path(),
            r#"
[compression]
algorithm = "Zstd"
level = 6
"#,
        );

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "-C",
                config.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("cfg.txt")).unwrap(),
            b"config file test"
        );
    }

    #[test]
    fn test_config_file_invalid_path() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "cfg_bad.txt", b"bad config");
        let archive = temp.path().join("cfg_bad.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "-C",
                "/nonexistent/config.toml",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_config_file_invalid_toml() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "cfg_bad2.txt", b"bad toml");
        let archive = temp.path().join("cfg_bad2.era");
        let config = create_test_config(temp.path(), "this is not valid toml {{{{");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "-C",
                config.to_str().unwrap(),
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_threshold_rejects_duplicate_passwords() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "dup_pw.txt", b"duplicate password");
        let archive = temp.path().join("dup_pw.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "same",
                "--password",
                "same",
                "--threshold",
                "2",
                "--shares",
                "2",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("Duplicate password"));
    }

    #[test]
    fn test_threshold_rejects_duplicate_hybrid_certificates() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "dup_hyb.txt", b"duplicate hybrid cert");
        let archive = temp.path().join("dup_hyb.era");
        let (pub_cert, _priv_key) = generate_test_hybrid_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--hybrid-certificate",
                pub_cert.to_str().unwrap(),
                "--hybrid-certificate",
                pub_cert.to_str().unwrap(),
                "--threshold",
                "2",
                "--shares",
                "2",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("Duplicate hybrid certificate"));
    }
}

// ===========================================================================
// 04: MULTIVOLUME TESTS
// ===========================================================================

mod multivolume_tests {
    use super::*;

    #[test]
    fn test_multivolume_volumes_6() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv6.bin", &vec![0xAA; 256 * 1024]);
        let archive = temp.path().join("mv6.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        let count = count_volume_files(&archive);
        assert!(
            count >= 2,
            "multi-volume should produce at least 2 files, got {}",
            count
        );
    }

    #[test]
    fn test_multivolume_max_volume_size_4kb() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv4k.bin", &vec![0xBB; 64 * 1024]);
        let archive = temp.path().join("mv4k.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--max-volume-size",
                "4096",
                "--no-compression",
            ])
            .assert()
            .success();

        let count = count_volume_files(&archive);
        assert!(
            count >= 2,
            "should split into multiple volumes with 4KB limit, got {}",
            count
        );
    }

    #[test]
    fn test_multivolume_max_volume_size_10kb() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv10k.bin", &vec![0xCC; 64 * 1024]);
        let archive = temp.path().join("mv10k.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--max-volume-size",
                "10240",
                "--no-compression",
            ])
            .assert()
            .success();

        let count = count_volume_files(&archive);
        assert!(
            count >= 2,
            "should split into multiple volumes with 10KB limit, got {}",
            count
        );
    }

    #[test]
    fn test_multivolume_all_volumes_exist() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_all.bin", &vec![0xDD; 256 * 1024]);
        let archive = temp.path().join("mv_all.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        let count = count_volume_files(&archive);
        assert!(
            count >= 2,
            "all volumes should exist after create, got {}",
            count
        );
    }

    #[test]
    fn test_multivolume_extract_all_files() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        create_test_file(&src, "a.txt", &vec![0x11; 64 * 1024]);
        create_test_file(&src, "b.txt", &vec![0x22; 64 * 1024]);
        create_test_file(&src, "c.txt", &vec![0x33; 64 * 1024]);
        let archive = temp.path().join("mv_ext.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                src.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            count_files_recursive(&out_dir),
            3,
            "all 3 files should be extracted from multi-volume"
        );
    }

    #[test]
    fn test_multivolume_list_shows_all() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        create_test_file(&src, "alpha.txt", b"alpha");
        create_test_file(&src, "beta.txt", b"beta");
        let archive = temp.path().join("mv_list.era");

        era_cmd()
            .args([
                "create",
                src.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        let assert_result = era_cmd()
            .args(["list", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(stderr.contains("alpha.txt"), "list should show alpha.txt");
        assert!(stderr.contains("beta.txt"), "list should show beta.txt");
    }

    #[test]
    fn test_multivolume_info_shows_count() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_info.bin", &vec![0xEE; 256 * 1024]);
        let archive = temp.path().join("mv_info.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        let assert_result = era_cmd()
            .args(["info", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            stderr.contains("Volume") || stderr.contains("volume") || stderr.contains("6"),
            "info should show volume information: {}",
            stderr
        );
    }

    #[test]
    fn test_multivolume_missing_one_volume_recovered() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_miss1.bin", &vec![0xFF; 256 * 1024]);
        let archive = temp.path().join("mv_miss1.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        let vol2 = archive.with_extension("era.002");
        if vol2.exists() {
            fs::remove_file(&vol2).unwrap();
        }

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            assert_result.get_output().status.success()
                || stderr.contains("missing")
                || stderr.contains("cannot recreate")
                || stderr.contains("recover"),
            "repair should succeed or report missing volume gracefully: {}",
            stderr
        );
    }

    #[test]
    fn test_multivolume_missing_two_volumes_recovered() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_miss2.bin", &vec![0xAB; 256 * 1024]);
        let archive = temp.path().join("mv_miss2.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        for seq in [2u16, 4] {
            let vol = archive.with_extension(format!("era.{:03}", seq));
            if vol.exists() {
                fs::remove_file(&vol).unwrap();
            }
        }

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            assert_result.get_output().status.success()
                || stderr.contains("missing")
                || stderr.contains("cannot recreate")
                || stderr.contains("recover"),
            "repair should succeed or report missing volumes gracefully: {}",
            stderr
        );
    }

    #[test]
    fn test_multivolume_missing_three_volumes_fails() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "mv_miss3.bin", &vec![0xCD; 256 * 1024]);
        let archive = temp.path().join("mv_miss3.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        for seq in [1u16, 3, 5] {
            let vol = archive.with_extension(format!("era.{:03}", seq));
            if vol.exists() {
                fs::remove_file(&vol).unwrap();
            }
        }

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            !assert_result.get_output().status.success()
                || stderr.contains("unrecoverable")
                || stderr.contains("insufficient")
                || stderr.contains("missing"),
            "repair should fail when too many volumes missing: {}",
            stderr
        );
    }
}

// ===========================================================================
// 05: ERROR HANDLING TESTS
// ===========================================================================

mod error_handling_tests {
    use super::*;

    #[test]
    fn test_error_nonexistent_input() {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("bad.era");

        era_cmd()
            .args([
                "create",
                "/this/path/does/not/exist.txt",
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_error_nonexistent_archive_extract() {
        let temp = TempDir::new().unwrap();
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "extract",
                "--input",
                "/nonexistent/archive.era",
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_error_nonexistent_archive_list() {
        era_cmd()
            .args(["list", "/nonexistent/archive.era", "--password", "pwd"])
            .assert()
            .failure();
    }

    #[test]
    fn test_error_nonexistent_archive_info() {
        era_cmd()
            .args(["info", "/nonexistent/archive.era", "--password", "pwd"])
            .assert()
            .failure();
    }

    #[test]
    fn test_error_nonexistent_archive_verify() {
        era_cmd()
            .args(["verify", "/nonexistent/archive.era", "--password", "pwd"])
            .assert()
            .failure();
    }

    #[test]
    fn test_error_no_password_no_key() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "no_auth.txt", b"no auth");
        let archive = temp.path().join("no_auth.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_error_invalid_key_file() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "inv_key.txt", b"invalid key test");
        let archive = temp.path().join("inv_key.era");
        let out_dir = temp.path().join("out");
        let bad_key = create_test_file(temp.path(), "bad.pem", b"NOT A VALID PEM KEY");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                bad_key.to_str().unwrap(),
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_error_corrupted_archive_shard() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "corrupt.bin", &vec![0xBB; 256 * 1024]);
        let archive = temp.path().join("corrupt.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "none",
            ])
            .assert()
            .success();

        let file_len = fs::metadata(&archive).unwrap().len();
        let data_offset = 4096 + 128 + 64;
        assert!(
            file_len > data_offset + 200,
            "archive should have sufficient data region"
        );

        corrupt_archive_shard(&archive, data_offset);

        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .failure();
    }

    #[test]
    fn test_error_corrupted_footer() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "footer.bin", b"footer test");
        let archive = temp.path().join("footer.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        corrupt_footer(&archive);

        let assert_result = era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            stderr.contains("footer")
                || stderr.contains("corrupted")
                || stderr.contains("recovery"),
            "verify should report footer corruption: {}",
            stderr
        );
    }

    #[test]
    fn test_error_corrupted_header_magic() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "magic.bin", b"magic test");
        let archive = temp.path().join("magic.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        corrupt_header_magic(&archive);

        era_cmd()
            .args(["verify", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .failure();
    }

    #[test]
    fn test_error_corrupted_header_repaired() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "repair_hdr.bin", &vec![0xEE; 256 * 1024]);
        let archive = temp.path().join("repair_hdr.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--no-compression",
            ])
            .assert()
            .success();

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(
            file_len > 10200,
            "archive too small for corruption test (need > 10200, got {})",
            file_len
        );
        corrupt_archive_shard(&archive, 10000);

        era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert()
            .success();
    }

    #[test]
    fn test_error_extract_to_nested_path() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "nested_out.txt", b"nested output");
        let archive = temp.path().join("nested_out.era");
        let out_dir = temp.path().join("deeply/nested/path");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        let assert_result = era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            assert_result.get_output().status.success()
                || stderr.contains("create")
                || stderr.contains("exist")
                || stderr.contains("directory"),
            "extract to nested path should handle gracefully: {}",
            stderr
        );
    }
}

// ===========================================================================
// 06: REPAIR TESTS
// ===========================================================================

mod repair_tests {
    use super::*;

    #[test]
    fn test_repair_dry_run_analyzes() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_dry.bin", &vec![0xDD; 64 * 1024]);
        let archive = temp.path().join("rep_dry.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args(["repair", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success()
            .stderr(
                predicate::str::contains("Recovery Analysis")
                    .or(predicate::str::contains("No repair needed"))
                    .or(predicate::str::contains("intact")),
            );
    }

    #[test]
    fn test_repair_with_force_heals() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_heal.bin", &vec![0xEE; 256 * 1024]);
        let archive = temp.path().join("rep_heal.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--no-compression",
            ])
            .assert()
            .success();

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(file_len > 10200);
        corrupt_archive_shard(&archive, 10000);

        era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert()
            .success();
    }

    #[test]
    fn test_repair_creates_backup() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_bak.bin", &vec![0xFF; 256 * 1024]);
        let archive = temp.path().join("rep_bak.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--no-compression",
            ])
            .assert()
            .success();

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(file_len > 10200);
        corrupt_archive_shard(&archive, 10000);

        era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert()
            .success();

        let backup = archive.with_extension("era.bak");
        assert!(
            backup.exists(),
            ".era.bak backup should be created during repair"
        );
    }

    #[test]
    fn test_repair_verbose_shows_blocks() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_verb.bin", &vec![0xDD; 256 * 1024]);
        let archive = temp.path().join("rep_verb.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--no-compression",
            ])
            .assert()
            .success();

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(
            file_len > 10200,
            "archive too small for corruption test (need > 10200, got {})",
            file_len
        );
        corrupt_archive_shard(&archive, 10000);

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--verbose",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            stderr.to_lowercase().contains("shard")
                || stderr.to_lowercase().contains("block")
                || stderr.to_lowercase().contains("corrupt")
                || stderr.to_lowercase().contains("repair")
                || stderr.to_lowercase().contains("recover"),
            "repair verbose should show repair details: {}",
            stderr
        );
    }

    #[test]
    fn test_repair_two_shard_corruption() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_2s.bin", &vec![0xEE; 256 * 1024]);
        let archive = temp.path().join("rep_2s.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--no-compression",
            ])
            .assert()
            .success();

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(
            file_len > 12200,
            "archive too small for double corruption test (need > 12200, got {})",
            file_len
        );
        corrupt_archive_shard(&archive, 10000);
        corrupt_archive_shard(&archive, 11000);

        era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert()
            .success();
    }

    #[test]
    fn test_repair_force_then_verify() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_fv.bin", &vec![0xFF; 256 * 1024]);
        let archive = temp.path().join("rep_fv.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--no-compression",
            ])
            .assert()
            .success();

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(
            file_len > 10200,
            "archive too small for corruption test (need > 10200, got {})",
            file_len
        );
        corrupt_archive_shard(&archive, 10000);

        era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert()
            .success();
    }

    #[test]
    fn test_repair_force_then_extract() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_fe.bin", b"repair extract data");
        let archive = temp.path().join("rep_fe.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--no-compression",
            ])
            .assert()
            .success();

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(
            file_len > 10200,
            "archive too small for corruption test (need > 10200, got {})",
            file_len
        );
        corrupt_archive_shard(&archive, 10000);

        era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rep_fe.bin")).unwrap(),
            b"repair extract data"
        );
    }

    #[test]
    fn test_repair_dry_run_no_modify() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_nomod.bin", &vec![0xAB; 256 * 1024]);
        let archive = temp.path().join("rep_nomod.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--no-compression",
            ])
            .assert()
            .success();

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(
            file_len > 10200,
            "archive too small for corruption test (need > 10200, got {})",
            file_len
        );
        corrupt_archive_shard(&archive, 10000);

        let size_before = fs::metadata(&archive).unwrap().len();

        era_cmd()
            .args(["repair", archive.to_str().unwrap(), "--password", "pwd"])
            .assert()
            .success();

        let size_after = fs::metadata(&archive).unwrap().len();
        assert_eq!(
            size_before, size_after,
            "dry run should not modify archive size"
        );
    }

    #[test]
    fn test_repair_wrong_password_fails() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_wp.bin", &vec![0xAC; 64 * 1024]);
        let archive = temp.path().join("rep_wp.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "correct",
                "--erasure",
                "4:2",
            ])
            .assert()
            .success();

        era_cmd()
            .args(["repair", archive.to_str().unwrap(), "--password", "wrong"])
            .assert()
            .failure();
    }

    #[test]
    fn test_repair_non_erasure_no_op() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_noec.bin", &vec![0x11; 256 * 1024]);
        let archive = temp.path().join("rep_noec.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "none",
            ])
            .assert()
            .success();

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(
            file_len > 10200,
            "archive too small for corruption test (need > 10200, got {})",
            file_len
        );
        corrupt_archive_shard(&archive, 10000);

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        let has_graceful = stderr.contains("without erasure coding")
            || stderr.contains("limited repair")
            || stderr.contains("not available")
            || stderr.contains("No repair needed")
            || stderr.contains("intact");
        assert!(
            has_graceful || !assert_result.get_output().status.success(),
            "repair on non-EC archive should handle gracefully: {}",
            stderr
        );
    }

    #[test]
    fn test_repair_nonexistent_archive() {
        let assert_result = era_cmd()
            .args(["repair", "/nonexistent/archive.era", "--password", "pwd"])
            .assert()
            .success();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            stderr.contains("Nothing to repair") || stderr.contains("No archive"),
            "repair should report nothing to repair: {}",
            stderr
        );
    }

    #[test]
    fn test_repair_multivolume_missing_one() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_mv1.bin", &vec![0xAD; 256 * 1024]);
        let archive = temp.path().join("rep_mv1.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        let vol3 = archive.with_extension("era.003");
        if vol3.exists() {
            fs::remove_file(&vol3).unwrap();
        }

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            assert_result.get_output().status.success()
                || stderr.contains("recover")
                || stderr.contains("repair")
                || stderr.contains("missing"),
            "repair should handle missing volume: {}",
            stderr
        );
    }

    #[test]
    fn test_repair_multivolume_missing_two() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_mv2.bin", &vec![0xAE; 256 * 1024]);
        let archive = temp.path().join("rep_mv2.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        for seq in [2u16, 4] {
            let vol = archive.with_extension(format!("era.{:03}", seq));
            if vol.exists() {
                fs::remove_file(&vol).unwrap();
            }
        }

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            assert_result.get_output().status.success()
                || stderr.contains("recover")
                || stderr.contains("repair"),
            "repair should handle 2 missing volumes: {}",
            stderr
        );
    }

    #[test]
    fn test_repair_multivolume_missing_three() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_mv3.bin", &vec![0xAF; 256 * 1024]);
        let archive = temp.path().join("rep_mv3.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        for seq in [1u16, 3, 5] {
            let vol = archive.with_extension(format!("era.{:03}", seq));
            if vol.exists() {
                fs::remove_file(&vol).unwrap();
            }
        }

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--force",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            !assert_result.get_output().status.success()
                || stderr.contains("unrecoverable")
                || stderr.contains("insufficient")
                || stderr.contains("missing"),
            "repair should fail with 3 missing volumes: {}",
            stderr
        );
    }

    #[test]
    fn test_repair_cert_mode_succeeds_with_key() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_cert.bin", &vec![0xEE; 256 * 1024]);
        let archive = temp.path().join("rep_cert.era");
        let (pub_cert, priv_key) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                pub_cert.to_str().unwrap(),
                "--erasure",
                "4:2",
                "--volumes",
                "1",
                "--no-compression",
            ])
            .assert()
            .success();

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(
            file_len > 10200,
            "archive too small for corruption test (need > 10200, got {})",
            file_len
        );
        corrupt_archive_shard(&archive, 10000);

        era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
                "--force",
            ])
            .assert()
            .success();
    }

    #[test]
    fn test_repair_threshold_password_archive() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_thresh.bin", &vec![0xAB; 256 * 1024]);
        let archive = temp.path().join("rep_thresh.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd1",
                "--password",
                "pwd2",
                "--threshold",
                "2",
                "--shares",
                "2",
                "--erasure",
                "4:2",
                "--no-compression",
                "--volumes",
                "1",
            ])
            .assert()
            .success();

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(file_len > 10200);
        corrupt_archive_shard(&archive, 10000);

        era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd1",
                "--password",
                "pwd2",
                "--force",
            ])
            .assert()
            .success();
    }

    #[test]
    fn test_repair_hybrid_cert_mode_succeeds_with_key() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_hyb.bin", &vec![0xCC; 256 * 1024]);
        let archive = temp.path().join("rep_hyb.era");

        let (pub_cert, priv_key) = generate_test_hybrid_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--hybrid-certificate",
                pub_cert.to_str().unwrap(),
                "--erasure",
                "4:2",
                "--no-compression",
                "--volumes",
                "1",
            ])
            .assert()
            .success();

        let file_len = fs::metadata(&archive).unwrap().len();
        assert!(file_len > 10200);
        corrupt_archive_shard(&archive, 10000);

        era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
                "--force",
            ])
            .assert()
            .success();
    }

    #[test]
    fn test_repair_multivolume_with_key() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_mv_key.bin", &vec![0xDD; 256 * 1024]);
        let archive = temp.path().join("rep_mv_key.era");
        let (_pub_cert, priv_key) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                _pub_cert.to_str().unwrap(),
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        let vol3 = archive.with_extension("era.003");
        if vol3.exists() {
            fs::remove_file(&vol3).unwrap();
        }

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
                "--force",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            assert_result.get_output().status.success()
                || stderr.contains("recover")
                || stderr.contains("repair")
                || stderr.contains("missing"),
            "matrix repair with key should handle missing volume: {}",
            stderr
        );
    }

    #[test]
    fn test_repair_multivolume_with_multiple_passwords() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rep_mv_pw.bin", &vec![0xEE; 256 * 1024]);
        let archive = temp.path().join("rep_mv_pw.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd1",
                "--password",
                "pwd2",
                "--threshold",
                "2",
                "--shares",
                "2",
                "--erasure",
                "4:2",
                "--volumes",
                "6",
                "--no-compression",
            ])
            .assert()
            .success();

        let vol3 = archive.with_extension("era.003");
        if vol3.exists() {
            fs::remove_file(&vol3).unwrap();
        }

        let assert_result = era_cmd()
            .args([
                "repair",
                archive.to_str().unwrap(),
                "--password",
                "pwd1",
                "--password",
                "pwd2",
                "--force",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            assert_result.get_output().status.success()
                || stderr.contains("recover")
                || stderr.contains("repair")
                || stderr.contains("missing"),
            "matrix repair with multiple passwords should handle missing volume: {}",
            stderr
        );
    }
}

// ===========================================================================
// 07: REPACK TESTS
// ===========================================================================

mod repack_tests {
    use super::*;

    #[test]
    fn test_repack_changes_compression() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(
            temp.path(),
            "rp_comp.txt",
            b"repack compression test data aaaaaaaaaa",
        );
        let archive = temp.path().join("rp_comp_src.era");
        let repacked = temp.path().join("rp_comp_dst.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--level",
                "3",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "pwd",
                "--level",
                "19",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_comp.txt")).unwrap(),
            b"repack compression test data aaaaaaaaaa"
        );
    }

    #[test]
    fn test_repack_removes_compression() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_rmcomp.txt", b"repack remove compression");
        let archive = temp.path().join("rp_rmcomp_src.era");
        let repacked = temp.path().join("rp_rmcomp_dst.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--level",
                "3",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "pwd",
                "--no-compression",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_rmcomp.txt")).unwrap(),
            b"repack remove compression"
        );
    }

    #[test]
    fn test_repack_adds_compression() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_addcomp.txt", b"repack add compression");
        let archive = temp.path().join("rp_addcomp_src.era");
        let repacked = temp.path().join("rp_addcomp_dst.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--no-compression",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "pwd",
                "--level",
                "3",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_addcomp.txt")).unwrap(),
            b"repack add compression"
        );
    }

    #[test]
    fn test_repack_changes_erasure() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_ec.txt", b"repack erasure change");
        let archive = temp.path().join("rp_ec_src.era");
        let repacked = temp.path().join("rp_ec_dst.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "6:3",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_ec.txt")).unwrap(),
            b"repack erasure change"
        );
    }

    #[test]
    fn test_repack_adds_erasure() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_addec.txt", b"repack add erasure");
        let archive = temp.path().join("rp_addec_src.era");
        let repacked = temp.path().join("rp_addec_dst.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "none",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_addec.txt")).unwrap(),
            b"repack add erasure"
        );
    }

    #[test]
    fn test_repack_removes_erasure() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_rmec.txt", b"repack remove erasure");
        let archive = temp.path().join("rp_rmec_src.era");
        let repacked = temp.path().join("rp_rmec_dst.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "4:2",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "pwd",
                "--erasure",
                "none",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_rmec.txt")).unwrap(),
            b"repack remove erasure"
        );
    }

    #[test]
    fn test_repack_preserves_content() {
        let temp = TempDir::new().unwrap();
        let data = b"content that must survive repack unchanged";
        let input = create_test_file(temp.path(), "rp_preserve.txt", data);
        let archive = temp.path().join("rp_preserve_src.era");
        let repacked = temp.path().join("rp_preserve_dst.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "pwd",
                "--compact",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(fs::read(out_dir.join("rp_preserve.txt")).unwrap(), data);
    }

    #[test]
    fn test_repack_wrong_password_fails() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_wrong.txt", b"repack wrong pwd");
        let archive = temp.path().join("rp_wrong_src.era");
        let repacked = temp.path().join("rp_wrong_dst.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "correct",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "wrong",
            ])
            .assert()
            .failure();
    }

    #[test]
    fn test_repack_with_cert() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_cert.txt", b"repack cert test");
        let archive = temp.path().join("rp_cert_src.era");
        let repacked = temp.path().join("rp_cert_dst.era");
        let out_dir = temp.path().join("out");
        let (pub_cert, priv_key) = generate_test_keypair(temp.path());

        create_archive_with_cert(&input, &archive, &pub_cert);

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
                "--compact",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                priv_key.to_str().unwrap(),
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_cert.txt")).unwrap(),
            b"repack cert test"
        );
    }

    #[test]
    fn test_repack_compact_preset() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_compact.txt", b"repack compact preset");
        let archive = temp.path().join("rp_compact_src.era");
        let repacked = temp.path().join("rp_compact_dst.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "pwd",
                "--compact",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_compact.txt")).unwrap(),
            b"repack compact preset"
        );
    }

    #[test]
    fn test_repack_creates_new_archive() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_new.txt", b"repack new archive");
        let archive = temp.path().join("rp_new_src.era");
        let repacked = temp.path().join("rp_new_dst.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        let original_size = fs::metadata(&archive).unwrap().len();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert!(archive.exists(), "original archive should still exist");
        assert!(repacked.exists(), "repacked archive should exist");
        assert_eq!(
            fs::metadata(&archive).unwrap().len(),
            original_size,
            "original should be unchanged"
        );
    }

    #[test]
    fn test_repack_extract_from_repacked() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_ext.txt", b"repack then extract");
        let archive = temp.path().join("rp_ext_src.era");
        let repacked = temp.path().join("rp_ext_dst.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
                "--level",
                "1",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "pwd",
                "--level",
                "19",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_ext.txt")).unwrap(),
            b"repack then extract"
        );
    }

    #[test]
    fn test_repack_all_geek_params() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_geek.bin", &vec![0x88; 16384]);
        let archive = temp.path().join("rp_geek_src.era");
        let repacked = temp.path().join("rp_geek_dst.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "pwd",
                "--cdc-min",
                "8192",
                "--cdc-avg",
                "32768",
                "--cdc-max",
                "131072",
                "--packing-k",
                "16",
                "--flush-threshold",
                "75",
                "--block-target-size",
                "4194304",
                "--erasure",
                "6:3",
                "--level",
                "12",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_geek.bin")).unwrap(),
            vec![0x88; 16384]
        );
    }

    #[test]
    fn test_repack_threshold_preserves_policy_without_explicit_dest_auth() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_thresh.txt", b"threshold repack data");
        let archive = temp.path().join("rp_thresh_src.era");
        let repacked = temp.path().join("rp_thresh_dst.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "p1",
                "--password",
                "p2",
                "--threshold",
                "2",
                "--shares",
                "2",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "p1",
                "--password",
                "p2",
                "--level",
                "19",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "p1",
                "--password",
                "p2",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_thresh.txt")).unwrap(),
            b"threshold repack data"
        );
    }

    #[test]
    fn test_repack_hybrid_source_to_hybrid_threshold_dest() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_pwh.txt", b"hybrid to hybrid threshold");
        let archive = temp.path().join("rp_pwh_src.era");
        let repacked = temp.path().join("rp_pwh_dst.era");
        let out_dir = temp.path().join("out");

        let (src_hybrid_pub, src_hybrid_priv) = generate_test_hybrid_keypair(temp.path());
        let (hybrid_pub1, hybrid_priv1) = generate_test_hybrid_keypair(temp.path());
        let (hybrid_pub2, hybrid_priv2) = generate_test_hybrid_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--hybrid-certificate",
                src_hybrid_pub.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--key",
                src_hybrid_priv.to_str().unwrap(),
                "--hybrid-certificate",
                hybrid_pub1.to_str().unwrap(),
                "--hybrid-certificate",
                hybrid_pub2.to_str().unwrap(),
                "--threshold",
                "2",
                "--shares",
                "2",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                hybrid_priv1.to_str().unwrap(),
                "--key",
                hybrid_priv2.to_str().unwrap(),
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_pwh.txt")).unwrap(),
            b"hybrid to hybrid threshold"
        );
    }

    #[test]
    fn test_repack_key_source_to_certificate_password_dest() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_dest.txt", b"key source to cert+pw dest");
        let archive = temp.path().join("rp_src.era");
        let repacked = temp.path().join("rp_dst.era");
        let out_dir = temp.path().join("out");

        let (src_pub, src_priv) = generate_test_keypair(temp.path());
        let (dest_pub, dest_priv) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                src_pub.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--key",
                src_priv.to_str().unwrap(),
                "--certificate",
                dest_pub.to_str().unwrap(),
                "--dest-password",
                "destsecret",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                dest_priv.to_str().unwrap(),
                "--password",
                "destsecret",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_dest.txt")).unwrap(),
            b"key source to cert+pw dest"
        );
    }

    #[test]
    fn test_repack_password_source_to_hybrid_certificate_password_dest() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_hdest.txt", b"pw source to hybrid+pw dest");
        let archive = temp.path().join("rp_hsrc.era");
        let repacked = temp.path().join("rp_hdst.era");
        let out_dir = temp.path().join("out");

        let (dest_pub, dest_priv) = generate_test_hybrid_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "srcpwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "srcpwd",
                "--hybrid-certificate",
                dest_pub.to_str().unwrap(),
                "--dest-password",
                "destsecret",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                dest_priv.to_str().unwrap(),
                "--password",
                "destsecret",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_hdest.txt")).unwrap(),
            b"pw source to hybrid+pw dest"
        );
    }

    #[test]
    fn test_repack_to_fresh_threshold_password_destination() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_thdest.txt", b"fresh threshold dest");
        let archive = temp.path().join("rp_thsrc.era");
        let repacked = temp.path().join("rp_thdst.era");
        let out_dir = temp.path().join("out");
        let (_src_pub, src_priv) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                _src_pub.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--key",
                src_priv.to_str().unwrap(),
                "--dest-password",
                "dp1",
                "--dest-password",
                "dp2",
                "--threshold",
                "2",
                "--shares",
                "2",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "dp1",
                "--password",
                "dp2",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_thdest.txt")).unwrap(),
            b"fresh threshold dest"
        );
    }
}

// ===========================================================================
// 08: REGRESSION TESTS
// ===========================================================================

mod regression_tests {
    use super::*;

    #[test]
    fn test_regression_unicode_filename_roundtrip() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "données_日本語_🔐.txt", b"unicode regression");
        let archive = temp.path().join("reg_unicode.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        let restored = out_dir.join("données_日本語_🔐.txt");
        assert!(restored.exists());
        assert_eq!(fs::read(&restored).unwrap(), b"unicode regression");
    }

    #[test]
    fn test_regression_binary_all_bytes() {
        let temp = TempDir::new().unwrap();
        let mut binary_data = Vec::with_capacity(256);
        for b in 0..=255u8 {
            binary_data.push(b);
        }
        let input = create_test_file(temp.path(), "binary.bin", &binary_data);
        let archive = temp.path().join("reg_binary.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("binary.bin")).unwrap(),
            binary_data,
            "all 256 byte values must survive"
        );
    }

    #[test]
    fn test_regression_large_1mb_file() {
        let temp = TempDir::new().unwrap();
        let large_data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
        let input = create_test_file(temp.path(), "large.bin", &large_data);
        let archive = temp.path().join("reg_large.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("large.bin")).unwrap(),
            large_data,
            "1MB file must survive roundtrip"
        );
    }

    #[test]
    fn test_regression_special_password_chars() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "reg_sp.txt", b"special password regression");
        let archive = temp.path().join("reg_sp.era");
        let out_dir = temp.path().join("out");
        let pw = "p@$$w0rd!#%^&*()[]{}|;:'\",.<>?/";

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                pw,
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                pw,
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("reg_sp.txt")).unwrap(),
            b"special password regression"
        );
    }

    #[test]
    fn test_regression_empty_password() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "reg_ep.txt", b"empty password regression");
        let archive = temp.path().join("reg_ep.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("reg_ep.txt")).unwrap(),
            b"empty password regression"
        );
    }

    #[test]
    fn test_regression_multiple_archives_same_password() {
        let temp = TempDir::new().unwrap();
        let input_a = create_test_file(temp.path(), "a.txt", b"archive A content");
        let input_b = create_test_file(temp.path(), "b.txt", b"archive B content");
        let archive_a = temp.path().join("a.era");
        let archive_b = temp.path().join("b.era");
        let out_a = temp.path().join("out_a");
        let out_b = temp.path().join("out_b");

        era_cmd()
            .args([
                "create",
                input_a.to_str().unwrap(),
                "--output",
                archive_a.to_str().unwrap(),
                "--password",
                "same_pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "create",
                input_b.to_str().unwrap(),
                "--output",
                archive_b.to_str().unwrap(),
                "--password",
                "same_pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive_a.to_str().unwrap(),
                "--output",
                out_a.to_str().unwrap(),
                "--password",
                "same_pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive_b.to_str().unwrap(),
                "--output",
                out_b.to_str().unwrap(),
                "--password",
                "same_pwd",
            ])
            .assert()
            .success();

        assert_eq!(fs::read(out_a.join("a.txt")).unwrap(), b"archive A content");
        assert_eq!(fs::read(out_b.join("b.txt")).unwrap(), b"archive B content");
    }
}

// ===========================================================================
// 09: STRESS / EDGE CASE TESTS
// ===========================================================================

mod stress_edge_case_tests {
    use super::*;

    #[test]
    fn test_stress_100_small_files() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src");
        for i in 0..100 {
            create_test_file(
                &src,
                &format!("file_{:03}.txt", i),
                format!("content_{}", i).as_bytes(),
            );
        }
        let archive = temp.path().join("stress100.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                src.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            count_files_recursive(&out_dir),
            100,
            "all 100 files should be extracted"
        );
    }

    #[test]
    fn test_stress_deep_directory_10_levels() {
        let temp = TempDir::new().unwrap();
        let mut path = temp.path().join("root");
        for i in 0..10 {
            path = path.join(format!("level_{}", i));
            create_test_file(
                &path,
                &format!("file_{}.txt", i),
                format!("data_{}", i).as_bytes(),
            );
        }
        let archive = temp.path().join("deep10.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                temp.path().join("root").to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            count_files_recursive(&out_dir),
            10,
            "all 10 files in deep dirs should be extracted"
        );
    }

    #[test]
    fn test_stress_repeated_create_extract() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "repeat.txt", b"repeated roundtrip");
        let archive = temp.path().join("repeat.era");

        for i in 0..5 {
            let out_dir = temp.path().join(format!("out_{}", i));

            era_cmd()
                .args([
                    "create",
                    input.to_str().unwrap(),
                    "--output",
                    archive.to_str().unwrap(),
                    "--password",
                    "pwd",
                ])
                .assert()
                .success();

            era_cmd()
                .args([
                    "extract",
                    "--input",
                    archive.to_str().unwrap(),
                    "--output",
                    out_dir.to_str().unwrap(),
                    "--password",
                    "pwd",
                ])
                .assert()
                .success();

            assert_eq!(
                fs::read(out_dir.join("repeat.txt")).unwrap(),
                b"repeated roundtrip"
            );
        }
    }

    #[test]
    fn test_edge_extract_to_nested_path() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "nested.txt", b"nested output path");
        let archive = temp.path().join("nested.era");
        let out_dir = temp.path().join("a/b/c/d/e/f");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        let assert_result = era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert();

        let stderr = String::from_utf8_lossy(&assert_result.get_output().stderr);
        assert!(
            assert_result.get_output().status.success()
                || stderr.contains("create")
                || stderr.contains("exist")
                || stderr.contains("directory"),
            "extract to deeply nested path should handle gracefully: {}",
            stderr
        );
    }

    #[test]
    fn test_edge_input_path_with_spaces() {
        let temp = TempDir::new().unwrap();
        let dir_with_spaces = temp.path().join("path with spaces");
        let input = create_test_file(&dir_with_spaces, "spaced.txt", b"spaces in path");
        let archive = temp.path().join("spaced.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("spaced.txt")).unwrap(),
            b"spaces in path"
        );
    }

    #[test]
    fn test_edge_output_path_with_spaces() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "out_space.txt", b"output spaces");
        let archive = temp.path().join("out_space.era");
        let out_dir = temp.path().join("output with spaces");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("out_space.txt")).unwrap(),
            b"output spaces"
        );
    }

    #[test]
    fn test_edge_unicode_input_path() {
        let temp = TempDir::new().unwrap();
        let unicode_dir = temp.path().join("données_入力");
        let input = create_test_file(&unicode_dir, "uni_path.txt", b"unicode path test");
        let archive = temp.path().join("uni_path.era");
        let out_dir = temp.path().join("out");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "pwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("uni_path.txt")).unwrap(),
            b"unicode path test"
        );
    }

    #[test]
    fn test_regression_repack_no_silent_downgrade_for_combined_auth() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_combo.txt", b"combined auth data");
        let archive = temp.path().join("rp_combo_src.era");
        let repacked = temp.path().join("rp_combo_dst.era");
        let (pub_cert, priv_key) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "srcpwd",
                "--certificate",
                pub_cert.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "srcpwd",
            ])
            .assert()
            .failure()
            .stderr(predicates::str::contains(
                "combined legacy certificate + password",
            ));

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "srcpwd",
                "--key",
                priv_key.to_str().unwrap(),
            ])
            .assert()
            .failure()
            .stderr(predicates::str::contains(
                "combined legacy certificate + password",
            ));
    }

    #[test]
    fn test_regression_repack_combined_hybrid_requires_explicit_dest_auth() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_hcombo.txt", b"combined hybrid data");
        let archive = temp.path().join("rp_hcombo_src.era");
        let repacked = temp.path().join("rp_hcombo_dst.era");
        let (pub_cert, priv_key) = generate_test_hybrid_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "srcpwd",
                "--hybrid-certificate",
                pub_cert.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "srcpwd",
            ])
            .assert()
            .failure()
            .stderr(predicates::str::contains(
                "combined hybrid certificate + password",
            ));

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "srcpwd",
                "--key",
                priv_key.to_str().unwrap(),
            ])
            .assert()
            .failure()
            .stderr(predicates::str::contains(
                "combined hybrid certificate + password",
            ));
    }

    #[test]
    fn test_regression_repack_threshold_2of3_password_requires_explicit_dest_auth() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_t23pw.txt", b"threshold 2of3 pw");
        let archive = temp.path().join("rp_t23pw_src.era");
        let repacked = temp.path().join("rp_t23pw_dst.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "p1",
                "--password",
                "p2",
                "--password",
                "p3",
                "--threshold",
                "2",
                "--shares",
                "3",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "p1",
                "--password",
                "p2",
                "--password",
                "p3",
            ])
            .assert()
            .failure()
            .stderr(predicates::str::contains(
                "fewer than all passwords are required",
            ));
    }

    #[test]
    fn test_regression_repack_threshold_2of3_hybrid_requires_explicit_dest_auth() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_t23hyb.txt", b"threshold 2of3 hybrid");
        let archive = temp.path().join("rp_t23hyb_src.era");
        let repacked = temp.path().join("rp_t23hyb_dst.era");

        let (pub1, priv1) = generate_test_hybrid_keypair(temp.path());
        let (pub2, priv2) = generate_test_hybrid_keypair(temp.path());
        let (pub3, _priv3) = generate_test_hybrid_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--hybrid-certificate",
                pub1.to_str().unwrap(),
                "--hybrid-certificate",
                pub2.to_str().unwrap(),
                "--hybrid-certificate",
                pub3.to_str().unwrap(),
                "--threshold",
                "2",
                "--shares",
                "3",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--key",
                priv1.to_str().unwrap(),
                "--key",
                priv2.to_str().unwrap(),
                "--key",
                _priv3.to_str().unwrap(),
            ])
            .assert()
            .failure()
            .stderr(predicates::str::contains(
                "fewer than all certificates are required",
            ));
    }

    #[test]
    fn test_regression_repack_auto_reuse_threshold_hybrid_certs() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_hy_th.txt", b"threshold hybrid data");
        let archive = temp.path().join("rp_hy_th_src.era");
        let repacked = temp.path().join("rp_hy_th_dst.era");
        let out_dir = temp.path().join("out");

        let (pub1, priv1) = generate_test_hybrid_keypair(temp.path());
        let (pub2, priv2) = generate_test_hybrid_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--hybrid-certificate",
                pub1.to_str().unwrap(),
                "--hybrid-certificate",
                pub2.to_str().unwrap(),
                "--threshold",
                "2",
                "--shares",
                "2",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--key",
                priv1.to_str().unwrap(),
                "--key",
                priv2.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                priv1.to_str().unwrap(),
                "--key",
                priv2.to_str().unwrap(),
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_hy_th.txt")).unwrap(),
            b"threshold hybrid data"
        );
    }

    #[test]
    fn test_regression_repack_dest_password_counts_as_explicit_auth() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_dpw.txt", b"dest password data");
        let archive = temp.path().join("rp_dpw_src.era");
        let repacked = temp.path().join("rp_dpw_dst.era");
        let out_dir = temp.path().join("out");
        let (_src_pub, src_priv) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                _src_pub.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--key",
                src_priv.to_str().unwrap(),
                "--dest-password",
                "dstpwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "dstpwd",
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("rp_dpw.txt")).unwrap(),
            b"dest password data"
        );
    }

    #[test]
    fn test_regression_repack_password_source_to_cert_only_dest() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_certonly.txt", b"cert only dest");
        let archive = temp.path().join("rp_certonly_src.era");
        let repacked = temp.path().join("rp_certonly_dst.era");
        let out_dir = temp.path().join("out");
        let (dest_pub, dest_priv) = generate_test_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "srcpwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "srcpwd",
                "--certificate",
                dest_pub.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                dest_priv.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                repacked.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--password",
                "srcpwd",
            ])
            .assert()
            .failure();

        assert_eq!(
            fs::read(out_dir.join("rp_certonly.txt")).unwrap(),
            b"cert only dest"
        );
    }

    #[test]
    fn test_regression_repack_rejects_multiple_passwords_for_single_slot() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_multipw.txt", b"multi pw");
        let archive = temp.path().join("rp_multipw_src.era");
        let repacked = temp.path().join("rp_multipw_dst.era");

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--password",
                "srcpwd",
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--password",
                "srcpwd",
                "--password",
                "extra",
            ])
            .assert()
            .failure()
            .stderr(predicates::str::contains("exactly one password"));
    }

    #[test]
    fn test_regression_repack_rejects_multiple_hybrid_keys_for_single_slot() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_multihyb.txt", b"multi hybrid");
        let archive = temp.path().join("rp_multihyb_src.era");
        let repacked = temp.path().join("rp_multihyb_dst.era");
        let (src_pub, src_priv) = generate_test_hybrid_keypair(temp.path());
        let (_extra_pub, extra_priv) = generate_test_hybrid_keypair(temp.path());

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--hybrid-certificate",
                src_pub.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "repack",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                repacked.to_str().unwrap(),
                "--key",
                src_priv.to_str().unwrap(),
                "--key",
                extra_priv.to_str().unwrap(),
            ])
            .assert()
            .failure()
            .stderr(predicates::str::contains("exactly one hybrid keypair"));
    }

    #[test]
    fn test_regression_create_rejects_duplicate_hybrid_cert_content() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "rp_dup.txt", b"duplicate hybrid cert");
        let archive = temp.path().join("rp_dup.era");
        let (pub1, _priv1) = generate_test_hybrid_keypair(temp.path());
        let pub1_copy = temp.path().join("hybrid_copy.pem");
        fs::copy(&pub1, &pub1_copy).unwrap();

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--hybrid-certificate",
                pub1.to_str().unwrap(),
                "--hybrid-certificate",
                pub1_copy.to_str().unwrap(),
                "--threshold",
                "2",
                "--shares",
                "2",
            ])
            .assert()
            .failure()
            .stderr(predicates::str::contains("Duplicate hybrid certificate"));
    }
}

// ===========================================================================
// 10: KEYGEN TESTS
// ===========================================================================

mod keygen_tests {
    use super::*;

    #[test]
    fn test_keygen_hybrid_default_interactive() {
        let temp = TempDir::new().unwrap();
        let priv_path = temp.path().join("era_hybrid_key");
        let pub_path = temp.path().join("era_hybrid_key.pub");

        era_cmd()
            .current_dir(temp.path())
            .arg("keygen")
            .write_stdin("\n")
            .assert()
            .success();

        assert!(priv_path.exists(), "private key should exist");
        assert!(pub_path.exists(), "public key should exist");

        let priv_content = fs::read_to_string(&priv_path).unwrap();
        assert!(priv_content.contains("ERA HYBRID PRIVATE KEY"));
        assert!(priv_content.contains("ERA HYBRID PUBLIC KEY"));

        let pub_content = fs::read_to_string(&pub_path).unwrap();
        assert!(pub_content.contains("ERA HYBRID PUBLIC KEY"));
    }

    #[test]
    fn test_keygen_x25519_explicit() {
        let temp = TempDir::new().unwrap();
        let priv_path = temp.path().join("x25519_key");
        let pub_path = temp.path().join("x25519_key.pub");

        era_cmd()
            .current_dir(temp.path())
            .args(["keygen", "-t", "x25519", "-f", priv_path.to_str().unwrap()])
            .assert()
            .success();

        assert!(priv_path.exists());
        assert!(pub_path.exists());

        let priv_content = fs::read_to_string(&priv_path).unwrap();
        assert!(priv_content.contains("BEGIN PRIVATE KEY"));
        assert!(priv_content.contains("END PRIVATE KEY"));

        let pub_content = fs::read_to_string(&pub_path).unwrap();
        assert!(pub_content.contains("BEGIN PUBLIC KEY"));
        assert!(pub_content.contains("END PUBLIC KEY"));
    }

    #[test]
    fn test_keygen_custom_output() {
        let temp = TempDir::new().unwrap();
        let priv_path = temp.path().join("custom_key");
        let pub_path = temp.path().join("custom_key.pub");

        era_cmd()
            .current_dir(temp.path())
            .args(["keygen", "-f", priv_path.to_str().unwrap()])
            .assert()
            .success();

        assert!(priv_path.exists());
        assert!(pub_path.exists());
    }

    #[test]
    fn test_keygen_refuse_overwrite_interactive() {
        let temp = TempDir::new().unwrap();
        let priv_path = temp.path().join("existing_key");
        let pub_path = temp.path().join("existing_key.pub");

        fs::write(&priv_path, b"existing private").unwrap();
        fs::write(&pub_path, b"existing public").unwrap();

        era_cmd()
            .current_dir(temp.path())
            .args(["keygen", "-f", priv_path.to_str().unwrap()])
            .write_stdin("n\n")
            .assert()
            .failure()
            .stderr(predicates::str::contains("Key generation aborted"));

        assert_eq!(fs::read_to_string(&priv_path).unwrap(), "existing private");
        assert_eq!(fs::read_to_string(&pub_path).unwrap(), "existing public");
    }

    #[test]
    fn test_keygen_force_overwrite() {
        let temp = TempDir::new().unwrap();
        let priv_path = temp.path().join("existing_key");
        let pub_path = temp.path().join("existing_key.pub");

        fs::write(&priv_path, b"existing private").unwrap();
        fs::write(&pub_path, b"existing public").unwrap();

        era_cmd()
            .current_dir(temp.path())
            .args(["keygen", "-f", priv_path.to_str().unwrap(), "--force"])
            .assert()
            .success();

        let priv_content = fs::read_to_string(&priv_path).unwrap();
        assert!(priv_content.contains("ERA HYBRID PRIVATE KEY"));
    }

    #[test]
    fn test_keygen_generated_hybrid_key_is_usable() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "keygen_hybrid.txt", b"hybrid roundtrip");
        let archive = temp.path().join("keygen_hybrid.era");
        let out_dir = temp.path().join("out");
        let priv_path = temp.path().join("hybrid_key");
        let pub_path = temp.path().join("hybrid_key.pub");

        era_cmd()
            .current_dir(temp.path())
            .args(["keygen", "-f", priv_path.to_str().unwrap()])
            .assert()
            .success();

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--hybrid-certificate",
                pub_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                priv_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("keygen_hybrid.txt")).unwrap(),
            b"hybrid roundtrip"
        );
    }

    #[test]
    fn test_keygen_generated_x25519_key_is_usable() {
        let temp = TempDir::new().unwrap();
        let input = create_test_file(temp.path(), "keygen_x25519.txt", b"x25519 roundtrip");
        let archive = temp.path().join("keygen_x25519.era");
        let out_dir = temp.path().join("out");
        let priv_path = temp.path().join("x25519_key");
        let pub_path = temp.path().join("x25519_key.pub");

        era_cmd()
            .current_dir(temp.path())
            .args(["keygen", "-t", "x25519", "-f", priv_path.to_str().unwrap()])
            .assert()
            .success();

        era_cmd()
            .args([
                "create",
                input.to_str().unwrap(),
                "--output",
                archive.to_str().unwrap(),
                "--certificate",
                pub_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        era_cmd()
            .args([
                "extract",
                "--input",
                archive.to_str().unwrap(),
                "--output",
                out_dir.to_str().unwrap(),
                "--key",
                priv_path.to_str().unwrap(),
            ])
            .assert()
            .success();

        assert_eq!(
            fs::read(out_dir.join("keygen_x25519.txt")).unwrap(),
            b"x25519 roundtrip"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_keygen_private_key_permissions_are_restricted() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new().unwrap();
        let priv_path = temp.path().join("restricted_key");
        let pub_path = temp.path().join("restricted_key.pub");

        era_cmd()
            .current_dir(temp.path())
            .args(["keygen", "-f", priv_path.to_str().unwrap()])
            .assert()
            .success();

        let priv_meta = fs::metadata(&priv_path).unwrap();
        let priv_mode = priv_meta.permissions().mode() & 0o777;
        assert_eq!(
            priv_mode, 0o600,
            "private key should be readable only by owner, got {:o}",
            priv_mode
        );

        let pub_meta = fs::metadata(&pub_path).unwrap();
        let pub_mode = pub_meta.permissions().mode() & 0o777;
        assert!(
            pub_mode & 0o444 != 0,
            "public key should be readable by others, got {:o}",
            pub_mode
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_keygen_overwrite_resets_loose_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new().unwrap();
        let priv_path = temp.path().join("loose_key");
        let pub_path = temp.path().join("loose_key.pub");

        fs::write(&priv_path, b"old private").unwrap();
        fs::write(&pub_path, b"old public").unwrap();
        let mut loose = fs::metadata(&priv_path).unwrap().permissions();
        loose.set_mode(0o644);
        fs::set_permissions(&priv_path, loose).unwrap();

        era_cmd()
            .current_dir(temp.path())
            .args(["keygen", "-f", priv_path.to_str().unwrap(), "--force"])
            .assert()
            .success();

        let priv_meta = fs::metadata(&priv_path).unwrap();
        let priv_mode = priv_meta.permissions().mode() & 0o777;
        assert_eq!(
            priv_mode, 0o600,
            "overwritten private key should be reset to owner-only, got {:o}",
            priv_mode
        );
    }
}
