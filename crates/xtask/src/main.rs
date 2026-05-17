#![forbid(unsafe_code)]
//! `BiBeam` workspace ops runner. Hosts cross-cutting maintenance subcommands.
//! Current subcommands:
//!   - `gen-readmes`         — write per-crate `README.md` from each member's `[package].description`.
//!   - `gen-readmes --check` — drift gate; exit non-zero if any README does not match what would be generated.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "xtask", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Generate per-crate `README.md` files from each crate's `[package].description`.
    GenReadmes {
        /// Verify every per-crate `README.md` matches what would be generated; exit non-zero on drift.
        #[arg(long)]
        check: bool,
    },
}

fn main() -> Result<()> {
    // Simple default subscriber — xtask is a one-shot CLI; no env-filter parsing needed.
    // Relies only on the `fmt` feature, which is enabled on the workspace tracing-subscriber dep (§4.2).
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::GenReadmes { check } => gen_readmes(check),
    }
}

fn gen_readmes(check_only: bool) -> Result<()> {
    let workspace_root = workspace_root()?;
    let members = workspace_members(&workspace_root)?;

    let mut drift = Vec::new();
    for member in members {
        let path = member.as_str().context("non-string entry in [workspace].members")?;
        let crate_dir = workspace_root.join(path);
        process_member(&crate_dir, check_only, &mut drift)?;
    }

    if check_only && !drift.is_empty() {
        for path in &drift {
            tracing::error!(readme = %path.display(), "drift detected");
        }
        bail!(
            "{} per-crate README(s) out of date; run `cargo run -p xtask --release -- gen-readmes`",
            drift.len()
        );
    }
    Ok(())
}

fn workspace_members(workspace_root: &Path) -> Result<Vec<toml::Value>> {
    let ws_manifest = fs::read_to_string(workspace_root.join("Cargo.toml"))
        .context("read workspace Cargo.toml")?;
    let ws: toml::Value = toml::from_str(&ws_manifest).context("parse workspace Cargo.toml")?;
    ws.get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .cloned()
        .context("missing [workspace].members in workspace Cargo.toml")
}

fn process_member(crate_dir: &Path, check_only: bool, drift: &mut Vec<PathBuf>) -> Result<()> {
    let manifest_path = crate_dir.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let parsed: toml::Value =
        toml::from_str(&manifest).with_context(|| format!("parse {}", manifest_path.display()))?;
    let pkg = parsed.get("package").context("missing [package] in crate Cargo.toml")?;
    let name = pkg.get("name").and_then(|n| n.as_str()).context("missing [package].name")?;
    let description = pkg
        .get("description")
        .and_then(|d| d.as_str())
        .context("missing [package].description (required by xtask gen-readmes)")?;

    let readme = format!("# {name}\n\n{description}\n");
    let readme_path = crate_dir.join("README.md");
    if check_only {
        let existing = fs::read_to_string(&readme_path).unwrap_or_default();
        if existing != readme {
            drift.push(readme_path);
        }
    } else {
        fs::write(&readme_path, &readme)
            .with_context(|| format!("write {}", readme_path.display()))?;
        tracing::info!(crate_name = name, "wrote README.md");
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("get current dir")?;
    let mut cur: &Path = cwd.as_path();
    loop {
        let manifest = cur.join("Cargo.toml");
        if manifest.exists() {
            let body = fs::read_to_string(&manifest)
                .with_context(|| format!("read {}", manifest.display()))?;
            if body.contains("[workspace]") {
                return Ok(cur.to_path_buf());
            }
        }
        match cur.parent() {
            Some(parent) => cur = parent,
            None => bail!("workspace root not found (no [workspace] Cargo.toml in ancestor chain)"),
        }
    }
}
