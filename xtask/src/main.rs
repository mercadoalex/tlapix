//! Xtask - Build automation for Tlapix Certificate Guardian.
//!
//! Handles eBPF program compilation targeting `bpfel-unknown-none`.
//! Usage: `cargo xtask build-ebpf [--release]`

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
#[command(name = "xtask", about = "Tlapix build automation")]
enum Cli {
    /// Build eBPF programs for bpfel-unknown-none target
    BuildEbpf {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::BuildEbpf { release } => build_ebpf(release),
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let workspace_root = workspace_root()?;
    let ebpf_dir = workspace_root.join("crates/tlapix-ebpf");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args([
            "+nightly",
            "build",
            "--target=bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .context("Failed to execute cargo build for eBPF programs")?;

    if !status.success() {
        bail!("eBPF build failed with status: {}", status);
    }

    println!("eBPF programs built successfully");
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    let output = Command::new("cargo")
        .args(["locate-project", "--workspace", "--message-format=plain"])
        .output()
        .context("Failed to locate workspace root")?;

    let path = String::from_utf8(output.stdout)
        .context("Invalid UTF-8 in cargo locate-project output")?;

    Ok(PathBuf::from(path.trim())
        .parent()
        .context("Failed to get parent directory of Cargo.toml")?
        .to_path_buf())
}
