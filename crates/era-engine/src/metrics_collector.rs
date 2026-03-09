//! Performance metrics collection for ERA archive operations
//!
//! This module provides instrumentation points for monitoring archive
//! creation, extraction, and other critical operations.

use std::time::Instant;
use tracing::debug;

/// Helper struct to measure and record operation timing
pub struct OperationTimer {
    name: &'static str,
    start: Instant,
}

impl OperationTimer {
    /// Create a new timer for an operation
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            start: Instant::now(),
        }
    }

    /// Record the elapsed time as a histogram metric
    /// Note: The metric name is combined with "_ms" suffix
    fn record_with_elapsed(self, elapsed_ms: f64) {
        // Since metrics macros require static strings, we can only record
        // the value without dynamic operation names. In production,
        // you would use a metrics exporter that supports labels.
        match self.name {
            "archive_create" => metrics::histogram!("archive_create_ms", elapsed_ms),
            "archive_extract" => metrics::histogram!("archive_extract_ms", elapsed_ms),
            "compression" => metrics::histogram!("compression_ms", elapsed_ms),
            "encryption" => metrics::histogram!("encryption_ms", elapsed_ms),
            "decryption" => metrics::histogram!("decryption_ms", elapsed_ms),
            "file_read" => metrics::histogram!("file_read_ms", elapsed_ms),
            "file_write" => metrics::histogram!("file_write_ms", elapsed_ms),
            _ => {
                debug!(
                    "Unknown operation '{}', skipping metrics recording",
                    self.name
                );
            }
        }
    }

    /// Record the elapsed time without returning it
    pub fn record(self) {
        let elapsed_ms = self.start.elapsed().as_secs_f64() * 1000.0;
        self.record_with_elapsed(elapsed_ms);
    }

    /// Record the elapsed time and return the duration in milliseconds
    pub fn finish(self) -> f64 {
        let elapsed_ms = self.start.elapsed().as_secs_f64() * 1000.0;
        self.record_with_elapsed(elapsed_ms);
        elapsed_ms
    }
}

/// Record bytes processed for an operation
pub fn record_bytes_processed(operation: &'static str, bytes: u64) {
    match operation {
        "compression" => metrics::counter!("compression_bytes_total", bytes),
        "encryption" => metrics::counter!("encryption_bytes_total", bytes),
        "archive_write" => metrics::counter!("archive_write_bytes_total", bytes),
        "archive_read" => metrics::counter!("archive_read_bytes_total", bytes),
        _ => {} // Unknown operation type, skip recording
    }
}

/// Record a single operation count
pub fn record_operation(operation: &'static str) {
    match operation {
        "file_encrypt" => metrics::counter!("file_encrypt_operations_total", 1u64),
        "file_decrypt" => metrics::counter!("file_decrypt_operations_total", 1u64),
        "chunk_process" => metrics::counter!("chunk_process_operations_total", 1u64),
        "archive_create" => metrics::counter!("archive_create_operations_total", 1u64),
        "archive_extract" => metrics::counter!("archive_extract_operations_total", 1u64),
        _ => {} // Unknown operation type, skip recording
    }
}

/// Record a gauge value (e.g., active connections, cache size)
pub fn record_gauge(metric_name: &'static str, value: f64) {
    match metric_name {
        "active_extractions" => metrics::gauge!("active_extractions", value),
        "cache_size_mb" => metrics::gauge!("cache_size_mb", value),
        "queue_depth" => metrics::gauge!("queue_depth", value),
        _ => {} // Unknown metric type, skip recording
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_creation_and_recording() {
        let timer = OperationTimer::new("archive_create");
        let elapsed = timer.finish();
        assert!(elapsed >= 0.0);
    }

    #[test]
    fn timer_with_different_operations() {
        for op in &[
            "archive_create",
            "archive_extract",
            "compression",
            "encryption",
        ] {
            let timer = OperationTimer::new(op);
            let elapsed = timer.finish();
            assert!(elapsed >= 0.0);
        }
    }
}
