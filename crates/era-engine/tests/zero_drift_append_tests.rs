use era_common::{ArchiveConfig, NormalizationLevel};
use era_engine::{ArchiveWriter, ExtractOptions};
use era_ingest::ChunkerConfig;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use tempfile::TempDir;

fn write_repeating_file(path: &std::path::Path, total_size: u64) {
    let mut writer = BufWriter::new(File::create(path).unwrap());
    let chunk = vec![0xABu8; 4 * 1024 * 1024];
    let mut remaining = total_size;

    while remaining > 0 {
        let to_write = std::cmp::min(remaining, chunk.len() as u64) as usize;
        writer.write_all(&chunk[..to_write]).unwrap();
        remaining -= to_write as u64;
    }
    writer.flush().unwrap();
}

#[test]
fn test_zero_drift_append_dedup() {
    let temp_dir = TempDir::new().unwrap();
    let data_path = temp_dir.path().join("data.bin");
    let copy_path = temp_dir.path().join("data_copy.bin");
    let archive_path = temp_dir.path().join("zero_drift.era");

    // 1GB dataset
    let total_size = 1024u64 * 1024 * 1024;
    write_repeating_file(&data_path, total_size);
    fs::hard_link(&data_path, &copy_path).unwrap();

    let mut config = ArchiveConfig::default();
    config.volume.max_size = 8 * 1024 * 1024 * 1024; // 8GB to avoid rotation
    let max_volume_size = config.volume.max_size;

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("zero_drift")
        .config(config.clone())
        .max_volume_size(max_volume_size)
        .enable_small_file_packing(false)
        .build()
        .unwrap();

    writer.add_file(&data_path).unwrap();
    let stats_first = writer.finalize().unwrap();
    let size_first = fs::metadata(&archive_path).unwrap().len();

    let mut sanity_reader = era_engine::ArchiveReader::open(&archive_path, "zero_drift").unwrap();
    sanity_reader.verify().unwrap();
    drop(sanity_reader);

    let drift_chunker = ChunkerConfig::new_with_params(
        2 * 1024,
        16 * 1024,
        64 * 1024,
        NormalizationLevel::Level3,
        123,
    );

    let mut writer = ArchiveWriter::builder(&archive_path)
        .password("zero_drift")
        .append_existing(true)
        .chunker_config(drift_chunker)
        .config(config)
        .max_volume_size(max_volume_size)
        .enable_small_file_packing(false)
        .build()
        .unwrap();

    writer.add_file(&copy_path).unwrap();
    let stats_second = writer.finalize().unwrap();
    let size_second = fs::metadata(&archive_path).unwrap().len();

    assert!(
        size_second <= size_first + (8 * 1024 * 1024),
        "Archive grew too much: {} -> {} bytes",
        size_first,
        size_second
    );

    assert!(
        stats_second.blocks_written.saturating_sub(stats_first.blocks_written) <= 2,
        "Unexpected data blocks written: {} -> {}",
        stats_first.blocks_written,
        stats_second.blocks_written
    );

    // Sanity check: extraction still works
    let output_dir = temp_dir.path().join("output");
    let mut reader = era_engine::ArchiveReader::open(&archive_path, "zero_drift").unwrap();
    let extract_stats = reader
        .extract_all(&ExtractOptions::new(&output_dir))
        .unwrap();

    assert_eq!(extract_stats.extracted, 2);
}
