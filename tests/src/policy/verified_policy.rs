// SPDX-License-Identifier: Apache-2.0

use libtest_mimic::{Failed, Trial};

use crate::{
    create_test,
    policy::{daemon_status, shared},
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
        create_test!(daemon_status::daemon_show_config),
        create_test!(shared::no_starting_keys_policies),
        create_test!(add_ecdsa_key),
        create_test!(add_signed_policy),
        create_test!(no_remove_policy_unsigned),
        create_test!(update_policy),
        create_test!(remove_policy),
        create_test!(no_add_policy_unsigned),
        create_test!(no_remove_key_unsigned),
        create_test!(remove_key),
    ]
}
