use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};

use crate::{
    VERSION,
    config::{ConfigFile, from_cli_targets},
    probe,
    report::{self, ReportFormat},
};

#[derive(Debug, Parser)]
#[command(
    name = "pathlens",
    version = VERSION,
    about = "Concurrent, safety-focused network reliability diagnostics",
    long_about = "PathLens performs bounded DNS, TCP and HTTP/TLS diagnostics against explicit HTTP or HTTPS targets. It never captures packets, follows redirects or accepts credentials in URLs."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check one or more explicit URLs.
    Check(CheckArgs),
    /// Run diagnostics from a YAML configuration file.
    Run(RunArgs),
    /// Validate a YAML configuration without making network requests.
    Validate {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Print the `PathLens` build version.
    Version,
}

#[derive(Debug, Args)]
struct CheckArgs {
    /// Explicit HTTP or HTTPS URL. Repeat for multiple targets.
    #[arg(short = 't', long = "target", required = true)]
    targets: Vec<String>,
    /// Per-stage timeout in milliseconds.
    #[arg(long, default_value_t = 5_000)]
    timeout_ms: u64,
    /// Maximum number of target probes running concurrently.
    #[arg(short, long, default_value_t = 8)]
    concurrency: usize,
    /// Safe HTTP method used for the final request.
    #[arg(long, default_value = "HEAD")]
    method: String,
    /// Accepted status code. Repeat or use comma-separated values.
    #[arg(long, value_delimiter = ',')]
    expect_status: Vec<u16>,
    /// Report format.
    #[arg(short, long, value_enum, default_value_t = ReportFormat::Table)]
    format: ReportFormat,
    /// Optional report file. Prints to stdout when omitted.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Path to a version 1 `PathLens` YAML configuration.
    #[arg(short, long)]
    config: PathBuf,
    /// Report format.
    #[arg(short, long, value_enum, default_value_t = ReportFormat::Table)]
    format: ReportFormat,
    /// Optional report file. Prints to stdout when omitted.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

/// Runs the parsed command and returns its documented process exit code.
///
/// # Errors
///
/// Returns an error when configuration, probing, serialization or report output fails.
pub async fn run() -> Result<u8> {
    let cli = Cli::parse();
    match cli.command {
        Command::Check(args) => {
            let config = from_cli_targets(
                args.targets,
                args.timeout_ms,
                args.concurrency,
                args.method,
                args.expect_status,
            )?;
            run_and_report(config, args.format, args.output).await
        }
        Command::Run(args) => {
            let config = ConfigFile::load(&args.config)?.resolve()?;
            run_and_report(config, args.format, args.output).await
        }
        Command::Validate { config } => {
            let resolved = ConfigFile::load(&config)?.resolve()?;
            println!(
                "valid: {} target(s), concurrency {}",
                resolved.targets.len(),
                resolved.concurrency
            );
            Ok(0)
        }
        Command::Version => {
            println!("pathlens {VERSION}");
            Ok(0)
        }
    }
}

async fn run_and_report(
    config: crate::config::ResolvedConfig,
    format: ReportFormat,
    output: Option<PathBuf>,
) -> Result<u8> {
    let report = probe::run(config).await?;
    let exit_code = if report.is_healthy() { 0 } else { 2 };
    let rendered = report::render(&report, format)?;
    report::write(&rendered, output.as_deref())?;
    Ok(exit_code)
}
