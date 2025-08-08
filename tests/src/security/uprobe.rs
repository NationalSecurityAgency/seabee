// SPDX-License-Identifier: Apache-2.0

/// Module to check the security of uprobe protections
///
/// This requires that the `tests` crate has been built
/// which contains the two BPF userspace binaries used for testing
use anyhow::Context;
use libtest_mimic::{Failed, Trial};

use crate::{command::TestCommandBuilder, create_test};

/// Tests that an arbitrary program using `bpf_write_user` is denied from loading
fn security_uprobe_deny_write_user() -> Result<(), Failed> {
    let exe_path = std::env::current_exe()?;
    let target_folder = exe_path
        .parent()
        .context("Expected to be running inside of the target folder")?;
    let binary_path = target_folder.join("bpf_write_user");
    let binary_path_str = binary_path
        .to_str()
        .context(format!("{binary_path:#?} could not be converted to string"))?;
    TestCommandBuilder::default()
        .program(binary_path_str)
        .expected_rc(101)
        .build()?
        .test()
}

pub fn tests() -> Vec<Trial> {
    vec![create_test!(security_uprobe_deny_write_user)]
}
