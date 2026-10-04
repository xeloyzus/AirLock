//! Entry point for the Layer 4 Ephemeral Wasm Host.
//!
//! Usage:
//!   airlock-host <path-to-payload.wasm> [fuel]
//!
//! Loads a `wasm32-unknown-unknown` cdylib, runs its exported `run()` under a
//! strict fuel budget with no WASI, prints captured output, and traps on any
//! bounds violation or fuel exhaustion.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use log::info;

use airlock_host::{run_wasm_file, DEFAULT_FUEL};

fn parse_args() -> Result<(PathBuf, u64)> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .context("usage: airlock-host <payload.wasm> [fuel]")?;
    let fuel = match args.next() {
        Some(f) => f
            .parse::<u64>()
            .with_context(|| format!("invalid fuel value: {f}"))?,
        None => DEFAULT_FUEL,
    };
    if args.next().is_some() {
        bail!("too many arguments; usage: airlock-host <payload.wasm> [fuel]");
    }
    Ok((PathBuf::from(path), fuel))
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    match try_main() {
        Ok(code) => code,
        Err(err) => {
            // Every containment failure surfaces here as a SECURITY TRAP.
            log::error!("{err:#}");
            ExitCode::FAILURE
        }
    }
}

fn try_main() -> Result<ExitCode> {
    let (path, fuel) = parse_args()?;
    info!("starting ephemeral host with fuel budget {fuel}");

    let outcome = run_wasm_file(&path, fuel)?;

    println!("--- agent output begin ---");
    print!("{}", outcome.output);
    if !outcome.output.ends_with('\n') {
        println!();
    }
    println!("--- agent output end ---");
    println!(
        "execution complete: {} bytes captured, {} / {fuel} fuel remaining",
        outcome.output.len(),
        outcome.fuel_remaining
    );

    Ok(ExitCode::SUCCESS)
}
