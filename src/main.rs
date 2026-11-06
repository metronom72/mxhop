use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use mxhop::config;

/// Where the file lives when nobody says otherwise.
const DEFAULT_CONFIG: &str = "/etc/mxhop/mxhop.toml";

#[derive(Debug, Parser)]
#[command(name = "mxhop", version, about = "A headless SMTP forwarder", long_about = None)]
struct Cli {
    /// Path to the configuration file.
    #[arg(long, short, global = true, env = "MXHOP_CONFIG", default_value = DEFAULT_CONFIG)]
    config: PathBuf,

    /// Log filter, in the `tracing` form: `info`, `mxhop::queue=debug`, …
    #[arg(long, global = true, env = "MXHOP_LOG")]
    log: Option<String>,

    /// Log as JSON lines instead of for a human reader.
    #[arg(long, global = true, env = "MXHOP_LOG_JSON")]
    log_json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check the configuration and say what is wrong with it, without
    /// starting anything. Exits non-zero if anything is wrong, so CI can run
    /// it.
    Check,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Check => check(&cli),
    }
}

fn check(cli: &Cli) -> ExitCode {
    let shown = cli.config.display();
    match config::load_file(&cli.config) {
        Ok(c) => {
            let domains: Vec<&str> = c.router.domains().collect();
            println!(
                "{shown}: ok — {} on {}, {} {} for {}",
                c.hostname,
                c.listen,
                c.router.alias_count(),
                plural(c.router.alias_count(), "alias", "aliases"),
                domains.join(", "),
            );
            ExitCode::SUCCESS
        }
        Err(problems) => {
            for p in &problems {
                match p.line {
                    Some(line) => eprintln!("{shown}:{line}: {}", p.message),
                    None => eprintln!("{shown}: {}", p.message),
                }
            }
            eprintln!(
                "{shown}: {} {} found",
                problems.len(),
                plural(problems.len(), "problem", "problems")
            );
            ExitCode::FAILURE
        }
    }
}

fn plural(n: usize, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 { one } else { many }
}
