//! Transport-independent synchronization orchestration.

pub mod commit;
pub mod destination;
pub mod planner;
pub mod source;
pub mod transfer;
mod wire;

struct Stage<'a> {
    name: &'a str,
    started: std::time::Instant,
}
impl<'a> Stage<'a> {
    fn start(name: &'a str) -> Self {
        eprintln!("{name}: start");
        Self {
            name,
            started: std::time::Instant::now(),
        }
    }
}
impl Drop for Stage<'_> {
    fn drop(&mut self) {
        eprintln!("{}: stop ({:?})", self.name, self.started.elapsed());
    }
}

async fn stage<T>(
    name: &str,
    work: impl std::future::Future<Output = Result<T, crate::error::QuicSyncError>>,
) -> Result<T, crate::error::QuicSyncError> {
    let _stage = Stage::start(name);
    work.await
}
