#[allow(unused_imports)]
use quicsync_core::{
    config as _, error as _, filesystem as _, protocol as _, state as _, sync as _, transport as _,
};

#[test]
fn core_module_boundaries_are_public() {
    // Importing each module above is the assertion while the modules are
    // intentionally empty.
}
