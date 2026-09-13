use clap::{Parser, Subcommand};
use quicsync_core::{
    auth::Identity,
    config::load_destination,
    sync::destination,
    transport::{CancellationToken, quic::listen},
};
use std::{error::Error, path::PathBuf};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a private identity and print its fingerprint.
    Init {
        #[arg(default_value = ".")]
        root: PathBuf,
    },
    /// Serve configured destination roots.
    Serve {
        #[arg(default_value = ".")]
        root: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let command = Cli::parse().command;
    let root = match &command {
        Command::Init { root } | Command::Serve { root } => root,
    };
    if matches!(command, Command::Init { .. }) {
        let identity = Identity::load_or_create(&root.join(".quicsync"))?;
        println!(
            "{}",
            identity
                .fingerprint()
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        return Ok(());
    }
    let config = load_destination(root)?;
    let identity = Identity::load_or_create(
        config
            .private_key()
            .parent()
            .ok_or("missing identity directory")?,
    )?;
    let listener = listen(&config, &identity, CancellationToken::new())?;
    eprintln!("listening on {}", listener.local_address()?);
    // One active attempt avoids concurrent commits to the same configured root.
    loop {
        match listener.accept_early().await {
            Ok(connection) => {
                if let Err(error) = destination::serve(&connection, &config).await {
                    eprintln!("{error}");
                }
            }
            Err(error) => eprintln!("{error}"),
        }
    }
}
