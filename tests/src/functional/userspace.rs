// SPDX-License-Identifier: Apache-2.0

/// Module to test the functionality of a userspace outside of pins and maps
///
/// ## Missing tests
///
/// - All BPF programs exist
use std::path::Path;

use libtest_mimic::{Failed, Trial};

use super::FunctionalTestSuite;
use crate::{create_test, suite::TestSuite};

/// Tests that the userspace process exists on the filesystem
fn functional_userspace_process_exists() -> Result<(), Failed> {
    let args = FunctionalTestSuite::get_system_state()?;

    let pid = args.rust_state.pid;
    let proc_path_str = format!("/proc/{pid}");

    // Check that our process exists
    if !Path::new(&proc_path_str).exists() {
        return Err(format!("Process {pid} has not entry on procfs").into());
    }

    Ok(())
}

pub fn tests() -> Vec<Trial> {
    vec![create_test!(functional_userspace_process_exists)]
}
