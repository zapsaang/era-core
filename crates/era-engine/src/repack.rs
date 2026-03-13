use crate::reader::{ArchiveReader, ExtractOptions};
use crate::writer::ArchiveWriter;
use era_common::{ArchiveConfig, EraError, Result};
use std::path::Path;
use tracing::info;

#[derive(Debug)]
pub struct RepackStats {
    pub files_repacked: u64,
    pub extracted_bytes: u64,
    pub repacked_total_size: u64,
    pub blocks_written: u64,
}

pub async fn repack_archive(
    source: &Path,
    output: &Path,
    password: &str,
    new_config: ArchiveConfig,
) -> Result<RepackStats> {
    let source_canonical = std::fs::canonicalize(source).map_err(EraError::Io)?;
    let output_parent = output.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(output_parent).map_err(EraError::Io)?;
    if output.exists() {
        let output_canonical = std::fs::canonicalize(output).map_err(EraError::Io)?;
        if source_canonical == output_canonical {
            return Err(EraError::InvalidConfig(
                "source and output paths must differ".into(),
            ));
        }
    }

    let temp_dir = tempfile::tempdir().map_err(EraError::Io)?;
    let extract_dir = temp_dir.path();

    info!("extracting source archive to temp dir");
    let mut reader = ArchiveReader::open(source, password).await?;
    let extract_opts = ExtractOptions::new(extract_dir).overwrite(true);
    let extract_stats = reader.extract_all(&extract_opts).await?;

    info!(
        "extracted {} files ({} bytes), re-archiving with new config",
        extract_stats.extracted, extract_stats.bytes_written
    );

    let mut writer = ArchiveWriter::builder(output)
        .password(password)
        .config(new_config)
        .build()
        .await?;

    writer.add_path(extract_dir, true).await?;
    let archive_stats = writer.finalize().await?;

    Ok(RepackStats {
        files_repacked: extract_stats.extracted as u64,
        extracted_bytes: extract_stats.bytes_written,
        repacked_total_size: archive_stats.total_size,
        blocks_written: archive_stats.blocks_written,
    })
}

pub async fn repack_archive_with_keypair(
    source: &Path,
    output: &Path,
    keypair: &era_crypto::certificate::EraKeyPair,
    new_config: ArchiveConfig,
) -> Result<RepackStats> {
    let source_canonical = std::fs::canonicalize(source).map_err(EraError::Io)?;
    let output_parent = output.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(output_parent).map_err(EraError::Io)?;
    if output.exists() {
        let output_canonical = std::fs::canonicalize(output).map_err(EraError::Io)?;
        if source_canonical == output_canonical {
            return Err(EraError::InvalidConfig(
                "source and output paths must differ".into(),
            ));
        }
    }

    let temp_dir = tempfile::tempdir().map_err(EraError::Io)?;
    let extract_dir = temp_dir.path();

    let mut reader = ArchiveReader::open_with_keypair(source, keypair).await?;
    let extract_opts = ExtractOptions::new(extract_dir).overwrite(true);
    let extract_stats = reader.extract_all(&extract_opts).await?;

    let mut writer = ArchiveWriter::builder(output)
        .certificate(keypair.certificate())
        .config(new_config)
        .build()
        .await?;

    writer.add_path(extract_dir, true).await?;
    let archive_stats = writer.finalize().await?;

    Ok(RepackStats {
        files_repacked: extract_stats.extracted as u64,
        extracted_bytes: extract_stats.bytes_written,
        repacked_total_size: archive_stats.total_size,
        blocks_written: archive_stats.blocks_written,
    })
}
