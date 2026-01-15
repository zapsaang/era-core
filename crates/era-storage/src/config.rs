//! Configuration file loading and validation
//!
//! This module provides:
//! - TOML configuration file loading
//! - Automatic validation on load
//! - Type-safe configuration structures
//! - Comprehensive error reporting

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use era_common::{EraError, Result};

/// Archive configuration
/// 
/// Describes parameters for archive creation and extraction
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArchiveConfig {
    /// Compression algorithm ("zstd" or "lz4")
    pub compression: Option<String>,
    
    /// Compression level (0-22 for zstd, 0-10 for lz4)
    pub compression_level: Option<u32>,
    
    /// Erasure coding data shards (1-255)
    pub erasure_data_shards: Option<usize>,
    
    /// Erasure coding parity shards (1-255)
    pub erasure_parity_shards: Option<usize>,
}

impl ArchiveConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate compression
        if let Some(ref comp) = self.compression {
            if comp != "zstd" && comp != "lz4" {
                return Err(EraError::InvalidConfig(
                    format!("compression must be 'zstd' or 'lz4', got '{}'", comp)
                ));
            }
        }
        
        // Validate compression level
        if let Some(level) = self.compression_level {
            let max_level = match self.compression.as_deref() {
                Some("zstd") => 22,
                Some("lz4") => 10,
                _ => 22, // Default to zstd
            };
            if level > max_level {
                return Err(EraError::InvalidConfig(
                    format!("compression_level must be 0-{}, got {}", max_level, level)
                ));
            }
        }
        
        // Validate erasure coding
        if let Some(data) = self.erasure_data_shards {
            if data < 1 || data > 255 {
                return Err(EraError::InvalidConfig(
                    format!("erasure_data_shards must be 1-255, got {}", data)
                ));
            }
        }
        
        if let Some(parity) = self.erasure_parity_shards {
            if parity < 1 || parity > 255 {
                return Err(EraError::InvalidConfig(
                    format!("erasure_parity_shards must be 1-255, got {}", parity)
                ));
            }
        }
        
        // Check total shards
        if let (Some(data), Some(parity)) = (self.erasure_data_shards, self.erasure_parity_shards) {
            if data + parity > 255 {
                return Err(EraError::InvalidConfig(
                    format!(
                        "total erasure shards must be <= 255, got {} (data) + {} (parity) = {}",
                        data, parity, data + parity
                    )
                ));
            }
        }
        
        Ok(())
    }
}

/// Key derivation configuration
///
/// Parameters for password-based key derivation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KdfConfig {
    /// Profile: "fast", "standard", or "production"
    pub profile: Option<String>,
    
    /// Memory cost in KB (explicit override)
    pub memory_cost: Option<u32>,
    
    /// Time cost/iterations (explicit override)
    pub time_cost: Option<u32>,
    
    /// Parallelism level (explicit override)
    pub parallelism: Option<u32>,
}

impl KdfConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if let Some(ref profile) = self.profile {
            if profile != "fast" && profile != "standard" && profile != "production" {
                return Err(EraError::InvalidConfig(
                    format!("profile must be 'fast', 'standard', or 'production', got '{}'", profile)
                ));
            }
        }
        
        if let Some(mem) = self.memory_cost {
            if mem < 1 {
                return Err(EraError::InvalidConfig(
                    format!("memory_cost must be >= 1, got {}", mem)
                ));
            }
        }
        
        if let Some(time) = self.time_cost {
            if time < 1 {
                return Err(EraError::InvalidConfig(
                    format!("time_cost must be >= 1, got {}", time)
                ));
            }
        }
        
        if let Some(parallelism) = self.parallelism {
            if parallelism < 1 {
                return Err(EraError::InvalidConfig(
                    format!("parallelism must be >= 1, got {}", parallelism)
                ));
            }
        }
        
        Ok(())
    }
}

/// Complete ERA configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EraConfig {
    #[serde(default)]
    pub archive: ArchiveConfig,
    
    #[serde(default)]
    pub kdf: KdfConfig,
}

impl EraConfig {
    /// Load configuration from a TOML file
    ///
    /// # Arguments
    /// * `path` - Path to the TOML configuration file
    ///
    /// # Errors
    /// * If file cannot be read
    /// * If file content is invalid TOML
    /// * If configuration is invalid
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(&path)?;
        
        let config: EraConfig = toml::from_str(&content)
            .map_err(|e| EraError::InvalidConfig(format!("Invalid TOML: {}", e)))?;
        
        config.validate()?;
        Ok(config)
    }
    
    /// Save configuration to a TOML file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        let content = toml::to_string_pretty(&self)
            .map_err(|e| EraError::InvalidConfig(format!("Failed to serialize config: {}", e)))?;
        
        fs::write(path, content)?;
        
        Ok(())
    }
    
    /// Validate the complete configuration
    pub fn validate(&self) -> Result<()> {
        self.archive.validate()?;
        self.kdf.validate()?;
        Ok(())
    }
    
    /// Get default configuration
    pub fn default_config() -> Self {
        Self {
            archive: ArchiveConfig {
                compression: Some("zstd".to_string()),
                compression_level: Some(3),
                erasure_data_shards: Some(16),
                erasure_parity_shards: Some(8),
            },
            kdf: KdfConfig {
                profile: Some("standard".to_string()),
                memory_cost: None,
                time_cost: None,
                parallelism: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_archive_config_validation_valid() {
        let config = ArchiveConfig {
            compression: Some("zstd".to_string()),
            compression_level: Some(3),
            erasure_data_shards: Some(16),
            erasure_parity_shards: Some(8),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_archive_config_invalid_compression() {
        let config = ArchiveConfig {
            compression: Some("invalid".to_string()),
            compression_level: None,
            erasure_data_shards: None,
            erasure_parity_shards: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_archive_config_invalid_data_shards() {
        let config = ArchiveConfig {
            compression: None,
            compression_level: None,
            erasure_data_shards: Some(0),
            erasure_parity_shards: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_archive_config_total_shards_exceed() {
        let config = ArchiveConfig {
            compression: None,
            compression_level: None,
            erasure_data_shards: Some(200),
            erasure_parity_shards: Some(200),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_kdf_config_validation_valid() {
        let config = KdfConfig {
            profile: Some("standard".to_string()),
            memory_cost: None,
            time_cost: None,
            parallelism: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_kdf_config_invalid_profile() {
        let config = KdfConfig {
            profile: Some("invalid".to_string()),
            memory_cost: None,
            time_cost: None,
            parallelism: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_era_config_load_save() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("era.toml");

        let config = EraConfig::default_config();
        config.save_to_file(&config_path).unwrap();

        let loaded = EraConfig::load_from_file(&config_path).unwrap();
        assert_eq!(loaded.archive.compression, Some("zstd".to_string()));
        assert_eq!(loaded.archive.erasure_data_shards, Some(16));
    }

    #[test]
    fn test_era_config_invalid_file() {
        let result = EraConfig::load_from_file("/nonexistent/path.toml");
        assert!(result.is_err());
    }
}
