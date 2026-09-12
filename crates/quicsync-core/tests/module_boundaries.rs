#[allow(unused_imports)]
use quicsync_core::{
    auth as _, config as _, error as _,
    filesystem::{ignore as _, metadata as _, paths as _, scan as _, staging as _},
    protocol::{codec as _, messages as _, session as _},
    sync::{commit as _, destination as _, planner as _, source as _, transfer as _},
    transport::quic as _,
};

#[test]
fn core_module_boundaries_are_public() {
    // Importing each module above is the assertion while the modules are
    // intentionally empty.
}
