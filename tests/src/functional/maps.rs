// SPDX-License-Identifier: Apache-2.0

/// Module to test the functionality of a userspace's BPF maps
///
/// ## Intentionally Unincluded tests
///
/// We do not check that `max_entries`` is initialized correctly since we
/// examine each element individually
use libtest_mimic::{Failed, Trial};

use super::FunctionalTestSuite;
use crate::{create_test, suite::TestSuite};

fn map_err(map_name: &str) -> Result<(), Failed> {
    Err(format!("The `{map_name}` map does not exist in Linux").into())
}

/// Tests that the total number of maps we expect are present
fn functional_map_total_num() -> Result<(), Failed> {
    let args = FunctionalTestSuite::get_system_state()?;
    let gt_len = args.ground_truth.maps.len();
    let bt_len = args.linux_state.maps.len();
    let rust_len = args.rust_state.maps.len();
    // Test that the expected map counts from Linux is correct
    if gt_len != bt_len {
        return Err(format!(
            "Number of maps in ground truth ({gt_len}) and linux ({bt_len}) don't match"
        )
        .into());
    }
    // Test that the expected map counts from the Rust userspace is correct
    if gt_len != rust_len {
        return Err(format!(
            "Number of maps in ground truth ({gt_len}) and rust ({rust_len}) don't match"
        )
        .into());
    }
    Ok(())
}

/// Tests the validity of info we know about the map at compile time
fn functional_map_exists() -> Result<(), Failed> {
    let args = FunctionalTestSuite::get_system_state()?;
    // Given that each of these maps are the same size, and each element in one is contained
    // in the others, we can conclude they are the same.
    for map_name in args.ground_truth.maps.keys() {
        // Test that each expected map exists under Linux
        if !args.linux_state.maps.contains_key(map_name) {
            return map_err(map_name);
        }
        // Test that each expected map exists under the Rust userspace
        if !args.rust_state.maps.contains_key(map_name) {
            return map_err(map_name);
        }
    }
    Ok(())
}

/// Tests the validity of info we know about the map at runtime
fn functional_map_contents_match() -> Result<(), Failed> {
    let args = FunctionalTestSuite::get_system_state()?;
    for (rust_name, rust_map) in args.rust_state.maps.iter() {
        let linux_map = match args.linux_state.maps.get(rust_name) {
            Some(map) => map,
            None => return map_err(rust_name),
        };
        // Tests that the map contents from Linux and Rust match
        if rust_map != linux_map {
            return Err(format!(
                "Map '{}' contents don't match.\nrust({} elems): {:?}\nlinux({} elems): {:?}",
                rust_name,
                rust_map.data.keys().len(),
                rust_map,
                linux_map.data.keys().len(),
                linux_map
            )
            .into());
        }
    }
    Ok(())
}

pub fn tests() -> Vec<Trial> {
    vec![
        create_test!(functional_map_total_num),
        create_test!(functional_map_exists),
        create_test!(functional_map_contents_match),
    ]
}
