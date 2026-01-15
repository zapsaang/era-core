//! Index metrics for monitoring and debugging.

use std::sync::atomic::{AtomicU64, Ordering};

/// Metrics for tracking index performance
#[derive(Debug, Default)]
pub struct IndexMetrics {
    /// Number of get operations
    pub gets: AtomicU64,
    /// Number of get operations that found a value (cache hits)
    pub get_hits: AtomicU64,
    /// Number of get operations that didn't find a value (cache misses)
    pub get_misses: AtomicU64,
    /// Number of put operations
    pub puts: AtomicU64,
    /// Number of delete operations
    pub deletes: AtomicU64,
    /// Number of bloom filter positive results
    pub bloom_positives: AtomicU64,
    /// Number of bloom filter true positives (found after bloom said maybe)
    pub bloom_true_positives: AtomicU64,
    /// Total bytes written
    pub bytes_written: AtomicU64,
    /// Total bytes read
    pub bytes_read: AtomicU64,
    /// Number of compactions completed
    pub compactions: AtomicU64,
    /// Number of flushes completed
    pub flushes: AtomicU64,
}

impl IndexMetrics {
    /// Create new metrics
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Record a get operation
    pub fn record_get(&self, found: bool) {
        self.gets.fetch_add(1, Ordering::Relaxed);
        if found {
            self.get_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.get_misses.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    /// Record a put operation
    pub fn record_put(&self, bytes: usize) {
        self.puts.fetch_add(1, Ordering::Relaxed);
        self.bytes_written.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    
    /// Record a delete operation
    pub fn record_delete(&self) {
        self.deletes.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Record bloom filter result
    pub fn record_bloom(&self, positive: bool, actually_exists: bool) {
        if positive {
            self.bloom_positives.fetch_add(1, Ordering::Relaxed);
            if actually_exists {
                self.bloom_true_positives.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    
    /// Get bloom filter false positive rate
    pub fn bloom_false_positive_rate(&self) -> f64 {
        let positives = self.bloom_positives.load(Ordering::Relaxed);
        let true_positives = self.bloom_true_positives.load(Ordering::Relaxed);
        if positives == 0 {
            return 0.0;
        }
        let false_positives = positives.saturating_sub(true_positives);
        false_positives as f64 / positives as f64
    }
    
    /// Get cache hit rate
    pub fn hit_rate(&self) -> f64 {
        let hits = self.get_hits.load(Ordering::Relaxed);
        let total = self.gets.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        hits as f64 / total as f64
    }
    
    /// Get a snapshot of current metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            gets: self.gets.load(Ordering::Relaxed),
            get_hits: self.get_hits.load(Ordering::Relaxed),
            get_misses: self.get_misses.load(Ordering::Relaxed),
            puts: self.puts.load(Ordering::Relaxed),
            deletes: self.deletes.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            compactions: self.compactions.load(Ordering::Relaxed),
            flushes: self.flushes.load(Ordering::Relaxed),
            hit_rate: self.hit_rate(),
            bloom_false_positive_rate: self.bloom_false_positive_rate(),
        }
    }
    
    /// Reset all metrics to zero
    pub fn reset(&self) {
        self.gets.store(0, Ordering::Relaxed);
        self.get_hits.store(0, Ordering::Relaxed);
        self.get_misses.store(0, Ordering::Relaxed);
        self.puts.store(0, Ordering::Relaxed);
        self.deletes.store(0, Ordering::Relaxed);
        self.bloom_positives.store(0, Ordering::Relaxed);
        self.bloom_true_positives.store(0, Ordering::Relaxed);
        self.bytes_written.store(0, Ordering::Relaxed);
        self.bytes_read.store(0, Ordering::Relaxed);
        self.compactions.store(0, Ordering::Relaxed);
        self.flushes.store(0, Ordering::Relaxed);
    }
}

/// A point-in-time snapshot of metrics
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub gets: u64,
    pub get_hits: u64,
    pub get_misses: u64,
    pub puts: u64,
    pub deletes: u64,
    pub bytes_written: u64,
    pub bytes_read: u64,
    pub compactions: u64,
    pub flushes: u64,
    pub hit_rate: f64,
    pub bloom_false_positive_rate: f64,
}

impl std::fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IndexMetrics {{ gets: {}, hits: {} ({:.1}%), puts: {}, written: {} MB }}",
            self.gets,
            self.get_hits,
            self.hit_rate * 100.0,
            self.puts,
            self.bytes_written / (1024 * 1024)
        )
    }
}
