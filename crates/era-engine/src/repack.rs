use crate::reader::{ArchiveReader, ExtractOptions};
use crate::writer::{ArchiveWriter, ArchiveWriterBuilder};
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

/// Generic repack with externally-provided source auth and writer builder.
///
/// This allows the caller to specify different authentication for source
/// (via providers) and destination (via the pre-configured writer builder).
pub async fn repack_archive_with_builder(
    source: &Path,
    output: &Path,
    source_providers: Vec<Box<dyn crate::auth::AuthProvider>>,
    writer_builder: ArchiveWriterBuilder,
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
    let mut reader = ArchiveReader::open_with_providers(source, source_providers).await?;
    let extract_opts = ExtractOptions::new(extract_dir).overwrite(true);
    let extract_stats = reader.extract_all(&extract_opts).await?;

    info!(
        "extracted {} files ({} bytes), re-archiving with new config",
        extract_stats.extracted, extract_stats.bytes_written
    );

    let mut writer = writer_builder.build().await?;

    writer.add_path(extract_dir, true).await?;
    let archive_stats = writer.finalize().await?;

    Ok(RepackStats {
        files_repacked: extract_stats.extracted as u64,
        extracted_bytes: extract_stats.bytes_written,
        repacked_total_size: archive_stats.total_size,
        blocks_written: archive_stats.blocks_written,
    })
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

pub async fn repack_archive_with_passwords(
    source: &Path,
    output: &Path,
    passwords: &[&str],
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

    let providers: Vec<Box<dyn crate::auth::AuthProvider>> = passwords
        .iter()
        .map(|p| Box::new(crate::auth::PasswordProvider::new(p.to_string())) as _)
        .collect();
    let mut reader = ArchiveReader::open_with_providers(source, providers).await?;
    let access_policy = reader.header().access_policy();
    let recipients = reader.header().recipients().to_vec();
    let extract_opts = ExtractOptions::new(extract_dir).overwrite(true);
    let extract_stats = reader.extract_all(&extract_opts).await?;

    let mut builder = ArchiveWriter::builder(output).config(new_config);

    match access_policy {
        era_volume::AccessPolicy::AnyOfN => {
            if recipients.len() == 1
                && matches!(
                    recipients[0].r_type(),
                    era_volume::RecipientType::Argon2idPassword
                )
            {
                if passwords.len() != 1 {
                    return Err(EraError::InvalidConfig(
                        "Source archive requires exactly one password for repack_archive_with_passwords. Use explicit auth configuration.".into(),
                    ));
                }
                builder = builder.password(passwords[0]);
            } else {
                return Err(EraError::InvalidConfig(
                    "Source archive auth mode is not supported by repack_archive_with_passwords. Use explicit auth configuration.".into(),
                ));
            }
        }
        era_volume::AccessPolicy::Threshold(t) => {
            let n = recipients.len();
            if (t as usize) < n {
                return Err(EraError::InvalidConfig(
                    "Source archive uses a threshold password policy where fewer than all passwords are required to unlock. Auto-preservation is disabled for security; use explicit auth configuration.".into(),
                ));
            }
            if n != passwords.len()
                || !recipients
                    .iter()
                    .all(|r| matches!(r.r_type(), era_volume::RecipientType::Argon2idPassword))
            {
                return Err(EraError::InvalidConfig(
                    "Source archive threshold password auth does not match provided passwords. Use explicit auth configuration.".into(),
                ));
            }
            builder = builder.password(passwords[0]);
            for pw in &passwords[1..] {
                builder = builder.add_password(*pw);
            }
            builder = builder.access_policy(era_volume::AccessPolicy::Threshold(t));
        }
        _ => {
            return Err(EraError::InvalidConfig(
                "Unsupported source access policy for repack".into(),
            ));
        }
    }

    let mut writer = builder.build().await?;

    writer.add_path(extract_dir, true).await?;
    let archive_stats = writer.finalize().await?;

    Ok(RepackStats {
        files_repacked: extract_stats.extracted as u64,
        extracted_bytes: extract_stats.bytes_written,
        repacked_total_size: archive_stats.total_size,
        blocks_written: archive_stats.blocks_written,
    })
}

pub async fn repack_archive_with_private_keys(
    source: &Path,
    output: &Path,
    keypairs: &[era_crypto::EitherKeyPair],
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

    let mut providers: Vec<Box<dyn crate::auth::AuthProvider>> = Vec::new();
    for kp in keypairs {
        match kp {
            era_crypto::EitherKeyPair::Legacy(k) => {
                providers.push(Box::new(crate::auth::CertificateProvider::new(k.clone())) as _);
            }
            era_crypto::EitherKeyPair::Hybrid(k) => {
                providers
                    .push(Box::new(crate::auth::HybridCertificateProvider::new(*k.clone())) as _);
            }
        }
    }

    let mut reader = ArchiveReader::open_with_providers(source, providers).await?;
    let access_policy = reader.header().access_policy();
    let recipients = reader.header().recipients().to_vec();
    let extract_opts = ExtractOptions::new(extract_dir).overwrite(true);
    let extract_stats = reader.extract_all(&extract_opts).await?;

    let mut builder = ArchiveWriter::builder(output).config(new_config);

    match access_policy {
        era_volume::AccessPolicy::AnyOfN => {
            if recipients.len() == 1 {
                let slot = &recipients[0];
                match slot.r_type() {
                    era_volume::RecipientType::X25519PubKey => {
                        let key_id = slot.key_id().ok_or_else(|| {
                            EraError::InvalidConfig("Source certificate slot missing key_id".into())
                        })?;
                        let matched = keypairs.iter().find(|kp| {
                            if let era_crypto::EitherKeyPair::Legacy(k) = kp {
                                k.certificate().key_id().get(..8) == Some(key_id.as_slice())
                            } else {
                                false
                            }
                        });
                        if let Some(era_crypto::EitherKeyPair::Legacy(k)) = matched {
                            builder = builder.certificate(k.certificate());
                        } else {
                            return Err(EraError::InvalidConfig(
                                "No matching legacy keypair found for source certificate slot. Use explicit auth configuration.".into(),
                            ));
                        }
                    }
                    era_volume::RecipientType::HybridKem => {
                        let hybrid_keypairs: Vec<_> = keypairs
                            .iter()
                            .filter_map(|kp| match kp {
                                era_crypto::EitherKeyPair::Hybrid(k) => Some(k),
                                _ => None,
                            })
                            .collect();
                        if hybrid_keypairs.len() != 1 {
                            return Err(EraError::InvalidConfig(
                                "Source archive requires exactly one hybrid keypair for repack_archive_with_private_keys. Use explicit auth configuration.".into(),
                            ));
                        }
                        builder = builder.hybrid_certificate(hybrid_keypairs[0].certificate());
                    }
                    _ => {
                        return Err(EraError::InvalidConfig(
                            "Source archive auth mode is not supported by repack_archive_with_private_keys. Use explicit auth configuration.".into(),
                        ));
                    }
                }
            } else {
                return Err(EraError::InvalidConfig(
                    "Source archive auth mode is not supported by repack_archive_with_private_keys. Use explicit auth configuration.".into(),
                ));
            }
        }
        era_volume::AccessPolicy::Threshold(t) => {
            let n = recipients.len();
            if (t as usize) < n {
                return Err(EraError::InvalidConfig(
                    "Source archive uses a threshold hybrid certificate policy where fewer than all certificates are required to unlock. Auto-preservation is disabled for security; use explicit auth configuration.".into(),
                ));
            }
            if !recipients
                .iter()
                .all(|r| matches!(r.r_type(), era_volume::RecipientType::HybridKem))
            {
                return Err(EraError::InvalidConfig(
                    "Source archive threshold auth is not supported by repack_archive_with_private_keys. Only threshold hybrid certificates are supported. Use explicit auth configuration.".into(),
                ));
            }
            let hybrid_keypairs: Vec<_> = keypairs
                .iter()
                .filter_map(|kp| match kp {
                    era_crypto::EitherKeyPair::Hybrid(k) => Some(k),
                    _ => None,
                })
                .collect();
            if hybrid_keypairs.len() != n {
                return Err(EraError::InvalidConfig(format!(
                    "Source archive has {} hybrid certificate slots but {} hybrid keypairs were provided. Use explicit auth configuration.",
                    n, hybrid_keypairs.len()
                )));
            }
            builder = builder.hybrid_certificate(hybrid_keypairs[0].certificate());
            for k in &hybrid_keypairs[1..] {
                builder = builder.add_hybrid_certificate(k.certificate());
            }
            builder = builder.access_policy(era_volume::AccessPolicy::Threshold(t));
        }
        _ => {
            return Err(EraError::InvalidConfig(
                "Unsupported source access policy for repack".into(),
            ));
        }
    }

    let mut writer = builder.build().await?;

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
