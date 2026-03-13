use std::fs;
use std::path::PathBuf;

#[test]
fn fuzz_workspace_registers_compact_targets() {
    let fuzz_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fuzz");
    let manifest_path = fuzz_root.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path).expect("read fuzz Cargo.toml");

    for (target, rel_path, required_snippet) in [
        (
            "fuzz_compact_header_parse",
            "fuzz_targets/fuzz_compact_header_parse.rs",
            "CompactSuperHeader::from_bytes",
        ),
        (
            "fuzz_compact_footer_parse",
            "fuzz_targets/fuzz_compact_footer_parse.rs",
            "CompactVolumeFooter::from_bytes",
        ),
        (
            "fuzz_compact_stripe_parse",
            "fuzz_targets/fuzz_compact_stripe_parse.rs",
            "CompactShardRecordHeader::from_bytes",
        ),
        (
            "fuzz_compact_directory_parse",
            "fuzz_targets/fuzz_compact_directory_parse.rs",
            "CompactDirectory::new",
        ),
        (
            "fuzz_compact_bundle_roundtrip",
            "fuzz_targets/fuzz_compact_bundle_roundtrip.rs",
            "CompactSuperHeader::new",
        ),
    ] {
        assert!(
            manifest.contains(target),
            "fuzz Cargo.toml must register target {target}"
        );
        let target_path = fuzz_root.join(rel_path);
        assert!(
            target_path.exists(),
            "registered compact fuzz target must exist: {rel_path}"
        );
        let src = fs::read_to_string(&target_path)
            .unwrap_or_else(|e| panic!("read target {} failed: {e}", target_path.display()));
        assert!(
            src.contains("#![no_main]")
                && src.contains("fuzz_target!(|data: &[u8]|")
                && src.contains(required_snippet),
            "compact fuzz target has unexpected content: {rel_path}"
        );
    }

    assert!(
        manifest.contains("era-compact"),
        "fuzz Cargo.toml must include era-compact dependency"
    );
}
