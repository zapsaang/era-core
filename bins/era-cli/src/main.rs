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
use clap::{Parser, Subcommand};
use era_crypto::disable_core_dumps;
use std::path::PathBuf;
use tracing::Level;

#[derive(Parser)]
#[command(name = "era")]
#[command(author, version, about, long_about = None)]
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
        /// Use with --matrix-distribution for optimal fault tolerance
        #[arg(long)]
        volumes: Option<usize>,

        /// Maximum size per volume in bytes (e.g., 4294967296 for 4GB)
        /// When exceeded, new volumes are created automatically
        #[arg(long)]
        max_volume_size: Option<u64>,

        /// Enable true matrix distribution of erasure shards across volumes
        /// This ensures each volume contains different shards for better fault tolerance
        /// Defaults to TRUE if erasure is enabled.
        #[arg(long)]
        matrix_distribution: Option<bool>,

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
    },

    /// Extract files from an ERA archive
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
    List {
        /// Archive path
        archive: PathBuf,

        /// Encryption password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Private key file for certificate mode (PEM format)
        #[arg(short = 'k', long)]
        key: Option<PathBuf>,

        /// Show detailed information
        #[arg(short, long)]
        long: bool,
    },

    /// Show information about an ERA archive
    Info {
        /// Archive path
        archive: PathBuf,

        /// Encryption password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Verify integrity of an ERA archive
    Verify {
        /// Archive path
        archive: PathBuf,

        /// Encryption password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Show detailed error information
        #[arg(short, long)]
        verbose: bool,
    },

    /// Repair or recover a damaged/incomplete ERA archive
    Repair {
        /// Archive path
        archive: PathBuf,

        /// Encryption password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Force action (discard checkpoint for interrupted creation)
        #[arg(short = 'f', long)]
        force: bool,

        /// Show detailed information
        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() -> anyhow::Result<()> {
    // Initialize tracing subscriber first
    let cli = Cli::parse();

    // Configure structured logging with tracing
    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    use tracing_subscriber::fmt::format::FmtSpan;
    tracing_subscriber::fmt()
        .with_max_level(level)
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
            matrix_distribution,
            cdc_min,
            cdc_avg,
            cdc_max,
            packing_k,
        } => commands::create(commands::CreateArgs {
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
            matrix_distribution,
            cdc_min,
            cdc_avg,
            cdc_max,
            packing_k,
        }),

        Commands::Extract {
            input,
            output,
            password,
            key,
            force,
        } => commands::extract(&input, &output, password.as_deref(), key.as_deref(), force),

        Commands::List {
            archive,
            password,
            key,
            long,
        } => commands::list(&archive, password.as_deref(), key.as_deref(), long),

        Commands::Info { archive, password } => commands::info(&archive, password.as_deref()),

        Commands::Verify {
            archive,
            password,
            verbose,
        } => commands::verify(&archive, password.as_deref(), verbose),

        Commands::Repair {
            archive,
            password,
            force,
            verbose,
        } => commands::repair(&archive, password.as_deref(), force, verbose),
    }
}
