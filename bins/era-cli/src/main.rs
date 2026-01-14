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
use tracing_subscriber::FmtSubscriber;

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

        /// Encryption password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Compression level (1-22, default: 3)
        #[arg(short = 'l', long, default_value = "3")]
        level: i32,

        /// Enable erasure coding for data redundancy (format: data:parity, e.g., "4:2")
        /// With 4:2, data is split into 4 shards + 2 parity shards (50% overhead),
        /// allowing recovery from any 2 lost shards per block.
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
        #[arg(long)]
        matrix_distribution: bool,
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
    if let Err(e) = disable_core_dumps() {
        eprintln!("Warning：Cannot disable core dumps: {}", e);
    } else {
        println!("Core Dumps disabeld.");
    }
    let cli = Cli::parse();

    // Set up logging
    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .without_time()
        .init();

    match cli.command {
        Commands::Create {
            input,
            output,
            password,
            level,
            erasure,
            volumes,
            max_volume_size,
            matrix_distribution,
        } => commands::create(
            &input,
            &output,
            password.as_deref(),
            level,
            erasure.as_deref(),
            volumes,
            max_volume_size,
            matrix_distribution,
        ),

        Commands::Extract {
            input,
            output,
            password,
            force,
        } => commands::extract(&input, &output, password.as_deref(), force),

        Commands::List {
            archive,
            password,
            long,
        } => commands::list(&archive, password.as_deref(), long),

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
