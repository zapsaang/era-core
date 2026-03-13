use era_common::{EraError, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub fn discover_bundle_volumes(bundle_root: &Path) -> Result<Vec<PathBuf>> {
    if !bundle_root.is_dir() {
        return Err(EraError::InvalidFormat(format!(
            "compact bundle root is not a directory: {}",
            bundle_root.display()
        )));
    }

    let mut volumes = Vec::new();
    for entry in fs::read_dir(bundle_root)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("volume."))
            && path.is_file()
        {
            volumes.push(path);
        }
    }
    volumes.sort();
    if volumes.is_empty() {
        return Err(EraError::InvalidFormat(
            "compact bundle has no volume.* members".into(),
        ));
    }
    Ok(volumes)
}

pub fn plan_compact_volume_paths(
    bundle_root: &Path,
    data_shards: u16,
    parity_shards: u16,
) -> Result<Vec<PathBuf>> {
    let total = u32::from(data_shards) + u32::from(parity_shards);
    if total == 0 {
        return Err(EraError::InvalidConfig(
            "compact volume count must be > 0".into(),
        ));
    }
    let mut out = Vec::with_capacity(total as usize);
    for i in 0..total {
        out.push(bundle_root.join(format!("volume.{i:03}")));
    }
    Ok(out)
}
