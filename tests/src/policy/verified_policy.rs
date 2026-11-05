// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use libtest_mimic::{Failed, Trial};

use crate::{
    create_test,
    policy::{daemon_status, shared},
    test_utils::try_open,
};

use super::shared::{Expected, ECDSA_PUB, ECDSA_PUB_ECDSA_SIG, V1};

fn add_ecdsa_key() -> Result<(), Failed> {
    shared::add_key_unsigned(ECDSA_PUB, Expected::Success)?;
    shared::list_keys(2)
}

fn add_signed_policy() -> Result<(), Failed> {
    shared::update_policy_signed(V1, shared::V1_ECDSA, Expected::Success)?;
    shared::list_policies(1)?;
    shared::policies_on_disk(1)
}

fn no_remove_policy_unsigned() -> Result<(), Failed> {
    shared::remove_policy_unsigned(V1, Expected::Error)?;
    shared::list_policies(1)?;
    shared::policies_on_disk(1)
}

fn update_policy() -> Result<(), Failed> {
    shared::update_policy_signed(shared::V2, shared::V2_ECDSA, Expected::Success)?;
    shared::list_policies(1)?;
    shared::policies_on_disk(1)
}

fn remove_policy() -> Result<(), Failed> {
    shared::remove_policy_signed(
        shared::REMOVE_V2,
        shared::REMOVE_V2_ECDSA,
        Expected::Success,
    )?;
    shared::list_policies(0)?;
    shared::policies_on_disk(0)
}

fn no_add_policy_unsigned() -> Result<(), Failed> {
    shared::update_policy_unsigned(V1, Expected::Error)?;
    shared::list_policies(0)?;
    shared::policies_on_disk(0)
}

/// Two policies protect the same file: both are enforced
fn overlap_both_enforced() -> Result<(), Failed> {
    std::fs::write(shared::OVERLAP_FILE, b"overlap")?;
    shared::update_policy_signed(
        shared::OVERLAP_AUDIT,
        shared::OVERLAP_AUDIT_ECDSA,
        Expected::Success,
    )?;
    try_open(Path::new(shared::OVERLAP_FILE), false, true)?;
    shared::update_policy_signed(
        shared::OVERLAP_BLOCK,
        shared::OVERLAP_BLOCK_ECDSA,
        Expected::Success,
    )?;
    try_open(Path::new(shared::OVERLAP_FILE), false, false)?;
    shared::list_policies(2)
}

/// Removing one policy leaves the other in force
fn overlap_remove_one() -> Result<(), Failed> {
    shared::remove_policy_signed(
        shared::REMOVE_OVERLAP_AUDIT,
        shared::REMOVE_OVERLAP_AUDIT_ECDSA,
        Expected::Success,
    )?;
    try_open(Path::new(shared::OVERLAP_FILE), false, false)?;
    shared::list_policies(1)
}

/// A file removed from a policy by an update is no longer protected by it
fn overlap_update_removes_file() -> Result<(), Failed> {
    shared::update_policy_signed(
        shared::OVERLAP_BLOCK_V2,
        shared::OVERLAP_BLOCK_V2_ECDSA,
        Expected::Success,
    )?;
    try_open(Path::new(shared::OVERLAP_FILE), false, true)?;
    shared::remove_policy_signed(
        shared::REMOVE_OVERLAP_BLOCK_V2,
        shared::REMOVE_OVERLAP_BLOCK_V2_ECDSA,
        Expected::Success,
    )?;
    std::fs::remove_file(shared::OVERLAP_FILE)?;
    shared::list_policies(0)?;
    shared::policies_on_disk(0)
}

fn no_remove_key_unsigned() -> Result<(), Failed> {
    shared::remove_key_unsigned(ECDSA_PUB, Expected::Error)?;
    shared::list_keys(2)
}

fn remove_key() -> Result<(), Failed> {
    shared::remove_key_signed(ECDSA_PUB, ECDSA_PUB_ECDSA_SIG, Expected::Success)?;
    shared::list_keys(1)
}

pub fn tests() -> Vec<Trial> {
    vec![
        create_test!(daemon_status::daemon_status),
        create_test!(daemon_status::daemon_deny_tid_sigkill),
        create_test!(shared::no_starting_keys_policies),
        create_test!(add_ecdsa_key),
        create_test!(add_signed_policy),
        create_test!(no_remove_policy_unsigned),
        create_test!(update_policy),
        create_test!(remove_policy),
        create_test!(no_add_policy_unsigned),
        create_test!(overlap_both_enforced),
        create_test!(overlap_remove_one),
        create_test!(overlap_update_removes_file),
        create_test!(no_remove_key_unsigned),
        create_test!(remove_key),
    ]
}
