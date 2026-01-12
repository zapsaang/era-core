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
}

fn main() -> anyhow::Result<()> {
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
        } => commands::create(&input, &output, password.as_deref(), level),

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
    }
}
