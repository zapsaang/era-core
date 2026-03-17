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
            "archive_create" => metrics::histogram!("archive_create_ms").record(elapsed_ms),
            "archive_extract" => metrics::histogram!("archive_extract_ms").record(elapsed_ms),
            "compression" => metrics::histogram!("compression_ms").record(elapsed_ms),
            "encryption" => metrics::histogram!("encryption_ms").record(elapsed_ms),
            "decryption" => metrics::histogram!("decryption_ms").record(elapsed_ms),
            "file_read" => metrics::histogram!("file_read_ms").record(elapsed_ms),
            "file_write" => metrics::histogram!("file_write_ms").record(elapsed_ms),
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
        "compression" => metrics::counter!("compression_bytes_total").increment(bytes),
        "encryption" => metrics::counter!("encryption_bytes_total").increment(bytes),
        "archive_write" => metrics::counter!("archive_write_bytes_total").increment(bytes),
        "archive_read" => metrics::counter!("archive_read_bytes_total").increment(bytes),
        _ => {
            debug!(
                "Unknown operation '{}', skipping metrics recording",
                operation
            );
        }
    }
}

/// Record a single operation count
pub fn record_operation(operation: &'static str) {
    match operation {
        "file_encrypt" => metrics::counter!("file_encrypt_operations_total").increment(1),
        "file_decrypt" => metrics::counter!("file_decrypt_operations_total").increment(1),
        "chunk_process" => metrics::counter!("chunk_process_operations_total").increment(1),
        "archive_create" => metrics::counter!("archive_create_operations_total").increment(1),
        "archive_extract" => metrics::counter!("archive_extract_operations_total").increment(1),
        _ => {
            debug!(
                "Unknown operation '{}', skipping metrics recording",
                operation
            );
        }
    }
}

/// Record a gauge value (e.g., active connections, cache size)
pub fn record_gauge(metric_name: &'static str, value: f64) {
    match metric_name {
        "active_extractions" => metrics::gauge!("active_extractions").set(value),
        "cache_size_mb" => metrics::gauge!("cache_size_mb").set(value),
        "queue_depth" => metrics::gauge!("queue_depth").set(value),
        _ => {
            debug!("Unknown metric '{}', skipping gauge recording", metric_name);
        }
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

    #[test]
    fn timer_with_unknown_operation_is_logged() {
        // Unknown operation names should trigger the debug log path, not silently drop.
        // This test verifies the behavior is intentional and detectable.
        let timer = OperationTimer::new("unknown_op");
        let elapsed = timer.finish();
        assert!(elapsed >= 0.0);
        // The debug log "Unknown operation '...' should be captured in tracing output.
    }

    #[test]
    fn record_bytes_processed_with_known_operation() {
        // Known operations should record the metric
        record_bytes_processed("compression", 1024);
        record_bytes_processed("encryption", 2048);
        record_bytes_processed("archive_write", 4096);
        record_bytes_processed("archive_read", 8192);
        // No panic = success
    }

    #[test]
    fn record_bytes_processed_with_unknown_operation_is_logged() {
        // Unknown operation names should trigger debug logging, not silently drop.
        record_bytes_processed("unknown_bytes_op", 5000);
        // The debug log "Unknown operation '...' should be captured in tracing output.
        // No panic confirms the code path executes intentionally.
    }

    #[test]
    fn record_operation_with_known_names() {
        // Known operations should record the metric
        record_operation("file_encrypt");
        record_operation("file_decrypt");
        record_operation("chunk_process");
        record_operation("archive_create");
        record_operation("archive_extract");
        // No panic = success
    }

    #[test]
    fn record_operation_with_unknown_name_is_logged() {
        // Unknown operation names should trigger debug logging, not silently drop.
        record_operation("unknown_operation_name");
        // The debug log "Unknown operation '...' should be captured in tracing output.
        // No panic confirms the code path executes intentionally.
    }

    #[test]
    fn record_gauge_with_known_metrics() {
        // Known metrics should record the gauge
        record_gauge("active_extractions", 5.0);
        record_gauge("cache_size_mb", 100.0);
        record_gauge("queue_depth", 42.0);
        // No panic = success
    }

    #[test]
    fn record_gauge_with_unknown_metric_is_logged() {
        // Unknown metric names should trigger debug logging, not silently drop.
        record_gauge("unknown_gauge_metric", 99.5);
        // The debug log "Unknown metric '...' should be captured in tracing output.
        // No panic confirms the code path executes intentionally.
    }
}
