// SPDX-License-Identifier: Apache-2.0

use libtest_mimic::{Failed, Trial};

use crate::{create_test, policy::daemon_status};

use super::shared::{self, Expected, ECDSA_PUB, V1, V2};

// Add update remove unsigned
fn add_unsigned_policy() -> Result<(), Failed> {
    shared::update_policy_unsigned(V1, Expected::Success)?;
    shared::list_policies(1)?;
    shared::policies_on_disk(1)
}

fn update_unsigned_policy() -> Result<(), Failed> {
    shared::update_policy_unsigned(V2, Expected::Success)?;
    shared::list_policies(1)?;
    shared::policies_on_disk(1)
}

fn remove_unsigned_policy() -> Result<(), Failed> {
    shared::remove_policy_unsigned(V2, Expected::Success)?;
    shared::list_policies(0)?;
    shared::policies_on_disk(0)
}

// add update remove signed should still work
fn add_ecdsa_key() -> Result<(), Failed> {
    shared::add_key_unsigned(ECDSA_PUB, Expected::Success)?;
    shared::list_keys(2)
}

fn add_signed_policy() -> Result<(), Failed> {
    shared::update_policy_signed(V1, shared::V1_ECDSA, Expected::Success)?;
    shared::list_policies(1)?;
    shared::policies_on_disk(1)
}

fn update_signed_policy() -> Result<(), Failed> {
    shared::update_policy_signed(shared::V2, shared::V2_ECDSA, Expected::Success)?;
    shared::list_policies(1)?;
    shared::policies_on_disk(1)
}

fn remove_signed_policy() -> Result<(), Failed> {
    shared::remove_policy_signed(
        shared::REMOVE_V2,
        shared::REMOVE_V2_ECDSA,
        Expected::Success,
    )?;
    shared::list_policies(0)?;
    shared::policies_on_disk(0)
}

fn remove_key() -> Result<(), Failed> {
    shared::remove_key_unsigned(ECDSA_PUB, Expected::Success)?;
    shared::list_keys(1)
}

pub fn tests() -> Vec<Trial> {
    vec![
        create_test!(daemon_status::daemon_status),
        create_test!(shared::no_starting_keys_policies),
        create_test!(add_unsigned_policy),
        create_test!(update_unsigned_policy),
        create_test!(remove_unsigned_policy),
        create_test!(add_ecdsa_key),
        create_test!(add_signed_policy),
        create_test!(update_signed_policy),
        create_test!(remove_signed_policy),
        create_test!(remove_key),
    ]
}
