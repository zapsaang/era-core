//! # ERA CLI
//!
//! Command-line interface for the ERA (Encrypted Redundant Archive) system.
//!
//! ## Usage
//!
//! ```bash
//! # Create an archive
//! era create --output archive.era --password secret input.txt
//!
//! # Extract an archive
//! era extract --input archive.era --output ./restored/
//!
//! # List contents
//! era list archive.era
//! ```

mod commands;
mod progress;
use clap::{Parser, Subcommand};
use era_crypto::disable_core_dumps;
use std::path::PathBuf;
use tracing::Level;

#[derive(Parser)]
#[command(name = "era")]
#[command(author, version)]
#[command(about = "ERA — Encrypted Redundant Archiver")]
#[command(long_about = "ERA — Encrypted Redundant Archiver\n\n\
    Create, extract, and manage encrypted archives with built-in redundancy.\n\
    Features XChaCha20-Poly1305 encryption, Zstd compression, Reed-Solomon\n\
    erasure coding, and certificate-based access control.")]
#[command(after_help = "\x1b[1mQuick Start:\x1b[0m\n  \
    era create -o backup.era ./my-files          Create an archive (prompts for password)\n  \
    era extract -i backup.era -o ./restored      Extract an archive\n  \
    era list backup.era                           List archive contents\n  \
    era verify backup.era                         Verify archive integrity\n\n  \
    Use 'era <command> --help' for detailed usage of each command.")]
#[command(propagate_version = true)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new ERA archive
    #[command(
        long_about = "Create a new ERA archive from one or more files or directories.\n\n\
        Directories are walked recursively. By default, archives use Zstd level 3\n\
        compression and 4:2 Reed-Solomon erasure coding for redundancy.\n\n\
        Provide --password on the command line or omit it to be prompted interactively.\n\
        Use --certificate for key-based access without sharing a password."
    )]
    #[command(after_help = "\x1b[1mExamples:\x1b[0m\n  \
        era create -o backup.era ./my-files\n  \
        era create -o backup.era -p secret ./docs ./photos\n  \
        era create -o backup.era --compact ./data\n  \
        era create -o backup.era --certificate public.pem ./data\n  \
        era create -o backup.era --erasure 6:3 --volumes 9 ./data\n  \
        era create -o backup.era -C config.toml ./data\n  \
        era create -o backup.era --no-compression ./videos")]
    Create {
        /// Input file(s) to archive
        #[arg(required = true)]
        input: Vec<PathBuf>,

        /// Output archive path
        #[arg(short, long)]
        output: PathBuf,

        /// Configuration file path (TOML)
        /// Overrides defaults, but is overridden by CLI flags
        #[arg(short = 'C', long)]
        config: Option<PathBuf>,

        /// Public key certificate (PEM format, optional for password mode)
        /// Use era-keygen to generate a keypair and certificate
        #[arg(short, long)]
        certificate: Option<PathBuf>,

        /// Encryption password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Compression level (1-22, default: 3). Set to 0 to disable compression.
        #[arg(short = 'l', long)]
        level: Option<i32>,

        /// Disable compression entirely (Store mode).
        /// Equivalent to --level 0
        #[arg(long, conflicts_with = "level")]
        no_compression: bool,

        /// Enable erasure coding for data redundancy (format: data:parity, e.g., "4:2")
        /// If not specified, defaults to "4:2" for maximum safety.
        /// Use "none" to disable (NOT RECOMMENDED).
        #[arg(short = 'e', long)]
        erasure: Option<String>,

        /// Number of volumes to distribute shards across (default: total shards)
        #[arg(long)]
        volumes: Option<usize>,

        /// Maximum size per volume in bytes (e.g., 4294967296 for 4GB)
        /// When exceeded, new volumes are created automatically
        #[arg(long)]
        max_volume_size: Option<u64>,

        // --- GEEK PARAMETERS ---
        /// [Geek] CDC minimum chunk size (bytes)
        #[arg(long, help_heading = "Geek Parameters")]
        cdc_min: Option<usize>,

        /// [Geek] CDC average chunk size (bytes)
        #[arg(long, help_heading = "Geek Parameters")]
        cdc_avg: Option<usize>,

        /// [Geek] CDC maximum chunk size (bytes)
        #[arg(long, help_heading = "Geek Parameters")]
        cdc_max: Option<usize>,

        /// [Geek] Packing k-factor (buffer slots)
        #[arg(long, help_heading = "Geek Parameters")]
        packing_k: Option<usize>,

        /// [Geek] Packing flush threshold percentage (0-100)
        #[arg(long, help_heading = "Geek Parameters")]
        flush_threshold: Option<usize>,

        /// [Geek] Target block size in bytes
        #[arg(long, help_heading = "Geek Parameters")]
        block_target_size: Option<usize>,

        /// Use compact preset: Zstd-19, 16 MB blocks, k=32 (high compression, slower writes)
        #[arg(long)]
        compact: bool,
    },

    /// Extract files from an ERA archive
    #[command(
        long_about = "Extract all files from an ERA archive to a directory.\n\n\
        By default, files are extracted to the current directory. Use --output to\n\
        specify a different location. Existing files are skipped unless --force is set."
    )]
    #[command(after_help = "\x1b[1mExamples:\x1b[0m\n  \
        era extract -i backup.era -o ./restored\n  \
        era extract -i backup.era -o ./restored -p secret\n  \
        era extract -i backup.era -o ./restored --key private.pem\n  \
        era extract -i backup.era -o ./restored --force")]
    Extract {
        /// Input archive path
        #[arg(short, long)]
        input: PathBuf,

        /// Output directory (default: current directory)
        #[arg(short, long, default_value = ".")]
        output: PathBuf,

        /// Encryption password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Private key file for certificate mode (PEM format)
        #[arg(short = 'k', long)]
        key: Option<PathBuf>,

        /// Overwrite existing files
        #[arg(short = 'f', long)]
        force: bool,
    },

    /// List contents of an ERA archive
    #[command(long_about = "List files stored in an ERA archive.\n\n\
        Shows file paths by default. Use --long for sizes and chunk IDs.")]
    #[command(after_help = "\x1b[1mExamples:\x1b[0m\n  \
        era list backup.era\n  \
        era list backup.era -p secret --long\n  \
        era list backup.era --key private.pem")]
    List {
        /// Archive path
        archive: PathBuf,

        /// Encryption password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Private key file for certificate mode (PEM format)
        #[arg(short = 'k', long)]
        key: Option<PathBuf>,

        /// Show sizes and chunk IDs for each file
        #[arg(short, long)]
        long: bool,
    },

    /// Show information about an ERA archive
    #[command(
        long_about = "Display archive metadata including archive ID, volume info,\n\
        configuration parameters, and content summary."
    )]
    #[command(after_help = "\x1b[1mExamples:\x1b[0m\n  \
        era info backup.era\n  \
        era info backup.era -p secret\n  \
        era info backup.era --key private.pem")]
    Info {
        /// Archive path
        archive: PathBuf,

        /// Encryption password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Private key file for certificate mode (PEM format)
        #[arg(short = 'k', long)]
        key: Option<PathBuf>,
    },

    /// Verify integrity of an ERA archive
    #[command(
        long_about = "Verify archive integrity by checking all blocks and files.\n\n\
        Exits with code 0 if the archive is intact, non-zero otherwise.\n\
        Use --verbose for detailed per-block error information."
    )]
    #[command(after_help = "\x1b[1mExamples:\x1b[0m\n  \
        era verify backup.era\n  \
        era verify backup.era -p secret\n  \
        era verify backup.era --key private.pem\n  \
        era verify backup.era --verbose")]
    Verify {
        /// Archive path
        archive: PathBuf,

        /// Encryption password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Private key file for certificate mode (PEM format)
        #[arg(short = 'k', long)]
        key: Option<PathBuf>,

        /// Show detailed error information
        #[arg(long)]
        verbose: bool,
    },

    /// Repair or recover a damaged/incomplete ERA archive
    #[command(
        long_about = "Analyze an archive and attempt recovery where possible.\n\n\
        Without --force, runs in dry-run mode (analysis only).\n\
        With --force, applies Reed-Solomon repairs or discards an interrupted-create checkpoint.\n\n\
        Archives created with erasure coding can recover from corrupted shards.\n\
        Archives without erasure coding have limited repair options."
    )]
    #[command(after_help = "\x1b[1mExamples:\x1b[0m\n  \
        era repair backup.era                        Analyze only (dry run)\n  \
        era repair backup.era --force                Apply repairs\n  \
        era repair backup.era --password s3cr3t      Apply repairs (password mode)\n  \
        Note: Certificate-based repair is not supported. Use --password.")]
    Repair {
        /// Archive path
        archive: PathBuf,

        /// Encryption password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Apply repairs or discard an interrupted-create checkpoint
        #[arg(short = 'f', long)]
        force: bool,

        /// Show detailed repair/recovery information
        #[arg(long)]
        verbose: bool,
    },

    /// Repack an archive with new parameters
    #[command(
        long_about = "Extract an archive and re-create it with new parameters.\n\n\
        Useful for changing compression level, erasure coding settings, or applying\n\
        the --compact preset to an existing archive. The original archive is not modified."
    )]
    #[command(after_help = "\x1b[1mExamples:\x1b[0m\n  \
        era repack -i old.era -o new.era -p secret --compact\n  \
        era repack -i old.era -o new.era -p secret --level 19 --erasure 6:3\n  \
        era repack -i old.era -o new.era --key private.pem --no-compression")]
    Repack {
        /// Input archive path
        #[arg(short, long)]
        input: PathBuf,

        /// Output archive path
        #[arg(short, long)]
        output: PathBuf,

        /// Encryption password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Private key file for certificate mode (PEM format)
        #[arg(short = 'k', long)]
        key: Option<PathBuf>,

        /// Use compact preset: Zstd-19, 16 MB blocks, k=32 (high compression, slower writes)
        #[arg(long)]
        compact: bool,

        /// Compression level (1-22, default: 3)
        #[arg(short = 'l', long)]
        level: Option<i32>,

        /// Disable compression entirely (Store mode)
        #[arg(long, conflicts_with = "level")]
        no_compression: bool,

        /// Erasure coding (format: data:parity, e.g., "4:2")
        #[arg(short = 'e', long)]
        erasure: Option<String>,

        /// [Geek] CDC minimum chunk size (bytes)
        #[arg(long, help_heading = "Geek Parameters")]
        cdc_min: Option<usize>,

        /// [Geek] CDC average chunk size (bytes)
        #[arg(long, help_heading = "Geek Parameters")]
        cdc_avg: Option<usize>,

        /// [Geek] CDC maximum chunk size (bytes)
        #[arg(long, help_heading = "Geek Parameters")]
        cdc_max: Option<usize>,

        /// [Geek] Packing k-factor (buffer slots)
        #[arg(long, help_heading = "Geek Parameters")]
        packing_k: Option<usize>,

        /// [Geek] Packing flush threshold percentage (0-100)
        #[arg(long, help_heading = "Geek Parameters")]
        flush_threshold: Option<usize>,

        /// [Geek] Target block size in bytes
        #[arg(long, help_heading = "Geek Parameters")]
        block_target_size: Option<usize>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing subscriber first
    let cli = Cli::parse();

    // Configure structured logging with tracing
    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    use tracing_subscriber::fmt::format::FmtSpan;
    progress::init();
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(progress::ProgressMakeWriter)
        .with_target(false)
        .without_time()
        .with_span_events(FmtSpan::NONE)
        .init();

    // Disable core dumps for security
    if let Err(e) = disable_core_dumps() {
        tracing::warn!("Cannot disable core dumps: {}", e);
    } else {
        tracing::debug!("Core dumps disabled");
    }

    match cli.command {
        Commands::Create {
            input,
            output,
            config,
            certificate,
            password,
            level,
            no_compression,
            erasure,
            volumes,
            max_volume_size,
            cdc_min,
            cdc_avg,
            cdc_max,
            packing_k,
            flush_threshold,
            block_target_size,
            compact,
        } => {
            commands::create(commands::CreateArgs {
                inputs: &input,
                output: &output,
                config_path: config.as_deref(),
                certificate_path: certificate.as_deref(),
                password: password.as_deref(),
                compression_level: level,
                no_compression,
                erasure: erasure.as_deref(),
                volume_count: volumes,
                max_volume_size,
                cdc_min,
                cdc_avg,
                cdc_max,
                packing_k,
                flush_threshold,
                block_target_size,
                compact,
            })
            .await
        }

        Commands::Extract {
            input,
            output,
            password,
            key,
            force,
        } => commands::extract(&input, &output, password.as_deref(), key.as_deref(), force).await,

        Commands::List {
            archive,
            password,
            key,
            long,
        } => commands::list(&archive, password.as_deref(), key.as_deref(), long).await,

        Commands::Info {
            archive,
            password,
            key,
        } => commands::info(&archive, password.as_deref(), key.as_deref()).await,

        Commands::Verify {
            archive,
            password,
            key,
            verbose,
        } => commands::verify(&archive, password.as_deref(), key.as_deref(), verbose).await,

        Commands::Repair {
            archive,
            password,
            force,
            verbose,
        } => commands::repair(&archive, password.as_deref(), force, verbose).await,

        Commands::Repack {
            input,
            output,
            password,
            key,
            compact,
            level,
            no_compression,
            erasure,
            cdc_min,
            cdc_avg,
            cdc_max,
            packing_k,
            flush_threshold,
            block_target_size,
        } => {
            commands::repack(commands::RepackArgs {
                input: &input,
                output: &output,
                password: password.as_deref(),
                key_path: key.as_deref(),
                compact,
                compression_level: level,
                no_compression,
                erasure: erasure.as_deref(),
                cdc_min,
                cdc_avg,
                cdc_max,
                packing_k,
                flush_threshold,
                block_target_size,
            })
            .await
        }
    }
}
