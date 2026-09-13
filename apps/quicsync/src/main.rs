use quicsync_core::{
    auth::Identity,
    config::load_source,
    sync::source,
    transport::{CancellationToken, quic::SourceClient},
};
use std::{env, error::Error, io, path::PathBuf};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

// TODO: @gpt use clap crate
async fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let command = args
        .next()
        .ok_or("usage: quicsync <init|sync|interactive> ROOT")?;
    let root = PathBuf::from(args.next().ok_or("missing ROOT")?);
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    if command == "init" {
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
    if command != "sync" && command != "interactive" {
        return Err("unknown command".into());
    }
    let config = load_source(&root)?;
    let identity = Identity::load_or_create(
        config
            .private_key()
            .parent()
            .ok_or("missing identity directory")?,
    )?;
    let client = SourceClient::new(&config, &identity)?;
    loop {
        if command == "interactive" {
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
        if command == "sync" {
            return Ok(());
        }
    }
}
