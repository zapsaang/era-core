use era_common::{EraError, NormalizationLevel, Result};
use fastcdc::v2020::{
    AVERAGE_MAX, AVERAGE_MIN, MAXIMUM_MAX, MAXIMUM_MIN, MINIMUM_MAX, MINIMUM_MIN,
};

/// Default minimum chunk size (4 KB)
pub const DEFAULT_MIN_SIZE: usize = 4 * 1024;

/// Default average chunk size (64 KB)
pub const DEFAULT_AVG_SIZE: usize = 64 * 1024;

/// Default maximum chunk size (256 KB)
pub const DEFAULT_MAX_SIZE: usize = 256 * 1024;

/// Configuration for FastCDC chunking
#[derive(Debug, Clone)]
pub struct ChunkerConfig {
    /// Minimum chunk size in bytes
    pub min_size: usize,
    /// Average (target) chunk size in bytes
    pub avg_size: usize,
    /// Maximum chunk size in bytes
    pub max_size: usize,
    /// FastCDC normalization level (v2020)
    pub normalization_level: NormalizationLevel,
    /// Rolling hash seed for FastCDC (v2020)
    pub rolling_hash_seed: u64,
}

impl Default for ChunkerConfig {
    fn default() -> Self {
        Self {
            min_size: DEFAULT_MIN_SIZE,
            avg_size: DEFAULT_AVG_SIZE,
            max_size: DEFAULT_MAX_SIZE,
            normalization_level: NormalizationLevel::default(),
            rolling_hash_seed: 0,
        }
    }
}

impl ChunkerConfig {
    /// Create a new configuration with custom sizes.
    ///
    /// This constructor is infallible for backwards compatibility and stores the
    /// sizes verbatim; it never panics. Sizes coming from untrusted input should
    /// go through [`ChunkerConfig::try_new`] (or be checked with
    /// [`ChunkerConfig::validate`]) before use.
    pub fn new(min_size: usize, avg_size: usize, max_size: usize) -> Self {
        Self::new_with_params(
            min_size,
            avg_size,
            max_size,
            NormalizationLevel::default(),
            0,
        )
    }

    /// Create a new configuration with custom sizes, normalization, and seed.
    ///
    /// Infallible for backwards compatibility: the values are stored verbatim and
    /// never asserted, so an invalid configuration cannot panic here. Prefer
    /// [`ChunkerConfig::try_new_with_params`] when the sizes are not already
    /// known to satisfy [`ChunkerConfig::validate`].
    pub fn new_with_params(
        min_size: usize,
        avg_size: usize,
        max_size: usize,
        normalization_level: NormalizationLevel,
        rolling_hash_seed: u64,
    ) -> Self {
        Self {
            min_size,
            avg_size,
            max_size,
            normalization_level,
            rolling_hash_seed,
        }
    }

    /// Create a validated configuration with custom sizes.
    ///
    /// # Errors
    /// Returns [`EraError::InvalidConfig`] if the sizes are out of order or
    /// outside FastCDC's bounds.
    pub fn try_new(min_size: usize, avg_size: usize, max_size: usize) -> Result<Self> {
        Self::try_new_with_params(
            min_size,
            avg_size,
            max_size,
            NormalizationLevel::default(),
            0,
        )
    }

    /// Create a validated configuration with custom sizes, normalization, and seed.
    ///
    /// # Errors
    /// Returns [`EraError::InvalidConfig`] if the sizes are out of order or
    /// outside FastCDC's bounds.
    pub fn try_new_with_params(
        min_size: usize,
        avg_size: usize,
        max_size: usize,
        normalization_level: NormalizationLevel,
        rolling_hash_seed: u64,
    ) -> Result<Self> {
        let config = Self::new_with_params(
            min_size,
            avg_size,
            max_size,
            normalization_level,
            rolling_hash_seed,
        );
        config.validate()?;
        Ok(config)
    }

    /// Check that these sizes can be used with FastCDC.
    ///
    /// # Errors
    /// Returns [`EraError::InvalidConfig`] if the sizes are out of order or outside FastCDC's bounds.
    pub fn validate(&self) -> Result<()> {
        for (name, size, lower, upper) in [
            ("maximum", self.max_size, MAXIMUM_MIN, MAXIMUM_MAX),
            ("average", self.avg_size, AVERAGE_MIN, AVERAGE_MAX),
            ("minimum", self.min_size, MINIMUM_MIN, MINIMUM_MAX),
        ] {
            if !u32::try_from(size).is_ok_and(|size| (lower..=upper).contains(&size)) {
                return Err(EraError::InvalidConfig(format!(
                    "FastCDC {name} chunk size {size} must be in {lower}..={upper} bytes"
                )));
            }
        }
        if self.min_size > self.avg_size || self.avg_size > self.max_size {
            return Err(EraError::InvalidConfig(
                "FastCDC chunk sizes must satisfy min <= avg <= max".into(),
            ));
        }
        Ok(())
    }

    /// Create configuration optimized for small files (16KB average)
    pub fn small_files() -> Self {
        Self::new(2 * 1024, 16 * 1024, 64 * 1024)
    }

    /// Create configuration optimized for large files (256KB average)
    pub fn large_files() -> Self {
        Self::new(16 * 1024, 256 * 1024, 1024 * 1024)
    }
}
