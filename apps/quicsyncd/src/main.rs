use quicsync_core::{
    auth::Identity,
    config::load_destination,
    sync::destination,
    transport::{CancellationToken, quic::listen},
};
use std::{env, error::Error, path::PathBuf};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let command = args
        .next()
        .ok_or("usage: quicsyncd <init|serve> SETUP_ROOT")?;
    let root = PathBuf::from(args.next().ok_or("missing SETUP_ROOT")?);
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
    if command != "serve" {
        return Err("unknown command".into());
    }
    let config = load_destination(&root)?;
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
