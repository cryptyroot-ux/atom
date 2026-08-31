//! The `atom` binary: the sovereign process entry point (Blueprint §17).
//!
//! All logic lives in the `atom_cli` library so it can be tested directly; this
//! entry point only parses arguments and delegates to [`atom_cli::run`].

#![forbid(unsafe_code)]

use clap::Parser;

fn main() -> anyhow::Result<()> {
    atom_cli::run(atom_cli::Cli::parse())
}
