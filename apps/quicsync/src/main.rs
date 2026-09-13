use clap::{Parser, Subcommand};
use quicsync_core::{
    auth::Identity,
    config::load_source,
    sync::source,
    transport::{CancellationToken, quic::SourceClient},
};
use std::{error::Error, io, path::PathBuf};

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
    /// Run one sync from this source.
    Sync {
        #[arg(default_value = ".")]
        root: PathBuf,
    },
    /// Run a fresh sync on each Enter.
    Interactive {
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
        Command::Init { root } | Command::Sync { root } | Command::Interactive { root } => root,
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
    let config = load_source(root)?;
    let identity = Identity::load_or_create(
        config
            .private_key()
            .parent()
            .ok_or("missing identity directory")?,
    )?;
    let client = SourceClient::new(&config, &identity)?;
    loop {
        if matches!(command, Command::Interactive { .. }) {
            eprintln!("Enter to sync; EOF to exit.");
            let read =
                tokio::task::spawn_blocking(|| io::stdin().read_line(&mut String::new())).await??;
            if read == 0 {
                return Ok(());
            }
        }
        let start = std::time::Instant::now();
        let connection = client.connect(CancellationToken::new()).await?;
        source::run(&connection, &config).await?;
        eprintln!("sync complete ({:?})", start.elapsed());
        if matches!(command, Command::Sync { .. }) {
            return Ok(());
        }
    }
}
