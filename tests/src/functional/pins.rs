// SPDX-License-Identifier: Apache-2.0

/// Module to test the functionality of a userspace's BPF pins
use libtest_mimic::{Failed, Trial};

use super::FunctionalTestSuite;
use crate::{create_test, suite::TestSuite};

/// Tests that the pin directory is correct
fn functional_pin_dir_correct() -> Result<(), Failed> {
    let args = FunctionalTestSuite::get_system_state()?;

    let pin_dir = &args.rust_state.pins.dir;
    let gt_pin_dir = &args.ground_truth.pins.dir;

    // Test that the pin directory reported by the Rust userspace
    // matches the ground truth directory
    if gt_pin_dir != pin_dir {
        return Err(
            format!("Pin dir `{pin_dir}` does not equal ground truth `{gt_pin_dir}`").into(),
        );
    }
    Ok(())
}

/// Tests that the total number of BPF pins is correct
fn functional_pin_num_total() -> Result<(), Failed> {
    let args = FunctionalTestSuite::get_system_state()?;

    let gt_pin_total = args.ground_truth.pins.pins.len();
    let rust_pin_total = args.rust_state.pins.pins.len();
    let linux_pin_total = args.linux_state.pins.pins.len();

    // Test that the total number of ground truth pins equals
    // the number of pins found on the file system
    if linux_pin_total != gt_pin_total {
        return Err(format!(
            "The number of pins in linux ({linux_pin_total}) does not equal ground truth ({gt_pin_total})"
        )
        .into());
    }
    // Test that the total number of ground truth pins equals
    // the number of pins reported by the Rust userspace
    if rust_pin_total != gt_pin_total {
        return Err(format!(
            "The number of pins in the Rust state ({rust_pin_total}) does not equal ground truth ({gt_pin_total})"
        )
        .into());
    }
    Ok(())
}

/// Tests the existence of each individual pin
fn functional_pin_check_pins() -> Result<(), Failed> {
    let args = FunctionalTestSuite::get_system_state()?;
    let gt_pins = &args.ground_truth.pins.pins;
    let rust_pins = &args.rust_state.pins.pins;
    let linux_pins = &args.linux_state.pins.pins;

    for pin_name in gt_pins.keys() {
        // Test that the pin name exists on the filesystem
        if !linux_pins.contains_key(pin_name) {
            return Err(format!("Ground truth pin '{pin_name}' missing on filesystem").into());
        }
        // Test that the pin name exists in the rust program
        if !rust_pins.contains_key(pin_name) {
            return Err(format!("Ground truth pin '{pin_name}' missing in rust pins").into());
        }
    }

    // Test that the linux pins are the same as the rust pins
    if linux_pins != rust_pins {
        return Err(format!(
            "Linux and rust pins don't match.\nGround truth: {gt_pins:?}\nRust: {rust_pins:?}"
        )
        .into());
    }
    Ok(())
}

pub fn tests() -> Vec<Trial> {
    vec![
        create_test!(functional_pin_dir_correct),
        create_test!(functional_pin_num_total),
        create_test!(functional_pin_check_pins),
    ]
}
