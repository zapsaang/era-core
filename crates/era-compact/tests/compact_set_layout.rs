use era_compact::set::plan_compact_volume_paths;

#[test]
fn erasure_layout_uses_one_volume_per_failure_domain() {
    let root = std::path::Path::new("archive.erac");

    let paths = plan_compact_volume_paths(root, 4, 2).expect("valid 4:2 layout");
    assert_eq!(paths.len(), 6, "N must equal data+parity shards");
    assert!(paths[0].ends_with("volume.000"));
    assert!(paths[5].ends_with("volume.005"));

    let single = plan_compact_volume_paths(root, 1, 0).expect("valid non-erasure layout");
    assert_eq!(single.len(), 1, "non-erasure compact must emit one volume");
    assert!(single[0].ends_with("volume.000"));
}
