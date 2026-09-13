//! Read-only scanner measurement with a draining consumer and no network.
//! Usage: scan_profile ROOT [RUNS] [QUEUE] [EXCLUSION ...]
use quicsync_core::{
    config::DEFAULT_LIMITS, filesystem::scan::scan_root, protocol::messages::IndexMessage,
    types::EntryKind,
};
use std::{error::Error, path::PathBuf, time::Instant};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(
        args.next()
            .ok_or("expected ROOT [RUNS] [QUEUE] [EXCLUSION ...]")?,
    );
    let runs: usize = args
        .next()
        .map(|v| v.to_string_lossy().parse())
        .transpose()?
        .unwrap_or(3);
    let queue: usize = args
        .next()
        .map(|v| v.to_string_lossy().parse())
        .transpose()?
        .unwrap_or(4);
    let exclusions = args
        .map(|value| value.into_string().map_err(|_| "exclusion must be UTF-8"))
        .collect::<Result<Vec<_>, _>>()?;
    if runs == 0 || queue == 0 {
        return Err("expected ROOT [positive RUNS] [positive QUEUE] [EXCLUSION ...]".into());
    }
    for run in 1..=runs {
        let (tx, mut rx) = mpsc::channel(queue);
        let started = Instant::now();
        let consuming = async {
            let mut records = 0u64;
            let mut files = 0u64;
            let mut bytes = 0u64;
            let mut first = None;
            let mut ended = false;
            while let Some(message) = rx.recv().await {
                match message? {
                    IndexMessage::Record(record) => {
                        first.get_or_insert_with(|| started.elapsed().as_secs_f64());
                        records += 1;
                        if record.metadata.kind() == EntryKind::RegularFile {
                            files += 1;
                            bytes += record.metadata.size();
                        }
                    }
                    IndexMessage::End => ended = true,
                }
            }
            if !ended {
                return Err("index closed without End".into());
            }
            Ok::<_, Box<dyn Error>>((records, files, bytes, first))
        };
        let (scan, counts) = tokio::join!(
            scan_root(&root, &exclusions, &DEFAULT_LIMITS, tx),
            consuming
        );
        scan?;
        let (records, files, bytes, first) = counts?;
        let elapsed = started.elapsed().as_secs_f64();
        let first = first.map_or_else(|| "null".to_owned(), |v| v.to_string());
        println!(
            "{{\"run\":{run},\"queue\":{queue},\"records\":{records},\"files\":{files},\"logical_bytes\":{bytes},\"first_record_seconds\":{first},\"elapsed_seconds\":{elapsed}}}"
        );
    }
    Ok(())
}
