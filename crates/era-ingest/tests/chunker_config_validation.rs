//! Regression tests for LL-05: invalid `ChunkerConfig` must not panic the public API.
//!
//! The configuration fields are public, so library users can hand the chunker
//! "sizes" that FastCDC rejects (and that may also be logically inverted).
//! Before the fix these paths reached `assert!` in `ChunkerConfig::new` and in
//! upstream `fastcdc`, panicking inside library code. These tests pin the
//! contract: `Chunker::new` is fallible and rejects an invalid configuration
//! instead of silently substituting the default FastCDC layout (R2-ING-01), the
//! infallible config constructors and the streaming chunkers never panic, and
//! fallible entry points surface `EraError` instead.

use era_ingest::{Chunker, ChunkerConfig, FileReader, StreamingChunker, StreamingChunkerZeroCopy};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Ordering-invalid configuration built through the public fields (no panic yet).
fn inverted_config() -> ChunkerConfig {
    ChunkerConfig {
        min_size: 1024,
        avg_size: 512,
        max_size: 256,
        ..Default::default()
    }
}

#[test]
fn chunker_config_new_does_not_panic_on_inverted_sizes() {
    let result = catch_unwind(|| ChunkerConfig::new(1024, 512, 256));
    assert!(
        result.is_ok(),
        "ChunkerConfig::new must not panic on inverted sizes"
    );
}

#[test]
fn chunker_config_new_with_params_does_not_panic_on_inverted_sizes() {
    let result = catch_unwind(|| {
        ChunkerConfig::new_with_params(
            1024,
            512,
            256,
            era_ingest::ChunkerConfig::default().normalization_level,
            0,
        )
    });
    assert!(
        result.is_ok(),
        "ChunkerConfig::new_with_params must not panic on inverted sizes"
    );
}

#[test]
fn chunker_new_rejects_invalid_config() {
    // R2-ING-01: Chunker::new used to warn and silently fall back to
    // ChunkerConfig::default(), which changes chunk boundaries and dedup layout
    // without telling the caller. It must now return Err instead.
    let result = catch_unwind(AssertUnwindSafe(|| Chunker::new(inverted_config())));
    let constructed = result.expect("Chunker::new must not panic on an inverted config");
    let error = constructed
        .err()
        .expect("Chunker::new must return Err for an invalid configuration");
    assert!(
        matches!(error, era_common::EraError::InvalidConfig(_)),
        "expected EraError::InvalidConfig, got {error:?}"
    );
    assert!(
        Chunker::new(ChunkerConfig::default()).is_ok(),
        "Chunker::new must still accept a valid configuration"
    );
}

#[tokio::test]
async fn streaming_chunker_invalid_config_returns_err() {
    let data = vec![0x5Au8; 8192];
    let handle = tokio::spawn(async move {
        let mut chunker = StreamingChunker::new(std::io::Cursor::new(data), inverted_config());
        chunker.next_chunk().await.map(|chunk| chunk.is_some())
    });

    let joined = handle
        .await
        .expect("StreamingChunker must not panic on an invalid config");
    let result = joined;
    assert!(
        result.is_err(),
        "StreamingChunker::next_chunk must return Err for an invalid config, got {result:?}"
    );
}

#[tokio::test]
async fn streaming_chunker_zero_copy_invalid_config_returns_err() {
    let data = vec![0x5Au8; 8192];
    let handle = tokio::spawn(async move {
        let mut chunker =
            StreamingChunkerZeroCopy::new(std::io::Cursor::new(data), inverted_config());
        chunker.next_chunk().await.map(|chunk| chunk.is_some())
    });

    let joined = handle
        .await
        .expect("StreamingChunkerZeroCopy must not panic on an invalid config");
    let result = joined;
    assert!(
        result.is_err(),
        "StreamingChunkerZeroCopy::next_chunk must return Err for an invalid config, got {result:?}"
    );
}

#[tokio::test]
async fn file_reader_invalid_config_returns_err() {
    let temp_dir = tempfile::TempDir::new().expect("temp dir");
    let path = temp_dir.path().join("payload.bin");
    std::fs::write(&path, vec![0x33u8; 4096]).expect("write fixture");

    let handle = tokio::spawn(async move {
        let reader = FileReader::with_cdc().with_chunker_config(inverted_config());
        reader
            .read_file_chunked(&path)
            .await
            .map(|chunks| chunks.len())
    });

    let joined = handle
        .await
        .expect("FileReader must not panic on an invalid chunker config");
    let result = joined;
    assert!(
        result.is_err(),
        "FileReader::read_file_chunked must return Err for an invalid config, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Fallible-API contract (added with the fix): callers that need an error
// instead of a non-panicking fallback use the try_* constructors.
// ---------------------------------------------------------------------------

#[test]
fn try_new_rejects_inverted_sizes() {
    assert!(ChunkerConfig::try_new(1024, 512, 256).is_err());
}

#[test]
fn try_new_rejects_fastcdc_out_of_bounds_sizes() {
    // Ordering holds, but FastCDC requires min in 64..=1MiB, avg in 256..=4MiB,
    // max in 1KiB..=16MiB.
    assert!(ChunkerConfig::try_new(1, 1, 1).is_err());
    assert!(ChunkerConfig::try_new(64, 256, 16 * 1024 * 1024 + 1).is_err());
}

#[test]
fn try_new_accepts_default_config() {
    let config = ChunkerConfig::try_new(4 * 1024, 64 * 1024, 256 * 1024)
        .expect("default chunk sizes must validate");
    assert_eq!(config.max_size, 256 * 1024);
}

#[test]
fn new_with_params_preserves_sizes_without_validating() {
    let normalization = ChunkerConfig::default().normalization_level;
    let config = ChunkerConfig::new_with_params(1024, 512, 256, normalization, 0);
    assert_eq!(config.min_size, 1024);
    assert_eq!(config.max_size, 256);
    assert!(
        config.validate().is_err(),
        "infallible construction must not disguise an invalid config as valid"
    );
}

#[test]
fn chunker_try_new_rejects_invalid_config() {
    assert!(Chunker::try_new(inverted_config()).is_err());
    assert!(Chunker::try_new(ChunkerConfig::default()).is_ok());
}

#[test]
fn invalid_config_is_never_silently_replaced_by_the_default_layout() {
    let data: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
    match Chunker::new(inverted_config()) {
        Ok(chunker) => {
            // If construction ever succeeds again it must at least chunk with the
            // caller's requested sizes; silently chunking with 4K/64K/256K would
            // change the archive layout behind the caller's back.
            let chunks = chunker.chunk_all(&data);
            assert_eq!(
                chunks.iter().map(|chunk| chunk.data.len()).sum::<usize>(),
                data.len()
            );
            panic!("Chunker::new silently accepted an invalid configuration");
        }
        Err(error) => assert!(
            matches!(error, era_common::EraError::InvalidConfig(_)),
            "a rejected config must surface EraError::InvalidConfig, got {error:?}"
        ),
    }
}
