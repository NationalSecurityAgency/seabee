// SPDX-License-Identifier: Apache-2.0

use std::fs;

use anyhow::{anyhow, Result};
use libtest_mimic::Failed;
use seabee::{
    constants::{self, SEABEECTL_EXE},
    utils::str_to_abs_path_str,
};

use crate::command::TestCommandBuilder;

// policies
pub const V1: &str = "policies/test_policy.yaml";
pub const V2: &str = "policies/test_policy_v2.yaml";
pub const REMOVE_V2: &str = "policies/remove_test_policy_v2.yaml";
pub const OVERLAP_AUDIT: &str = "policies/overlap_audit.yaml";
pub const OVERLAP_BLOCK: &str = "policies/overlap_block.yaml";
pub const OVERLAP_BLOCK_V2: &str = "policies/overlap_block_v2.yaml";
pub const REMOVE_OVERLAP_AUDIT: &str = "policies/remove_overlap_audit.yaml";
pub const REMOVE_OVERLAP_BLOCK_V2: &str = "policies/remove_overlap_block_v2.yaml";

// signatures
pub const V1_ECDSA: &str = "crypto/sigs/test-policy-ecdsa.sign";
pub const V2_ECDSA: &str = "crypto/sigs/test-policy-v2-ecdsa.sign";
pub const REMOVE_V2_ECDSA: &str = "crypto/sigs/remove-test-policy-v2-ecdsa.sign";
pub const OVERLAP_AUDIT_ECDSA: &str = "crypto/sigs/overlap-audit-ecdsa.sign";
pub const OVERLAP_BLOCK_ECDSA: &str = "crypto/sigs/overlap-block-ecdsa.sign";
pub const OVERLAP_BLOCK_V2_ECDSA: &str = "crypto/sigs/overlap-block-v2-ecdsa.sign";
pub const REMOVE_OVERLAP_AUDIT_ECDSA: &str = "crypto/sigs/remove-overlap-audit-ecdsa.sign";
pub const REMOVE_OVERLAP_BLOCK_V2_ECDSA: &str = "crypto/sigs/remove-overlap-block-v2-ecdsa.sign";
pub const ECDSA_PUB_ECDSA_SIG: &str = "crypto/sigs/ecdsa-public-ecdsa-sig.sign";
pub const ECDSA_PUB_ROOT_SIG: &str = "crypto/sigs/ecdsa-public-root-sig.sign";
pub const RSA_PUB_ROOT_SIG: &str = "crypto/sigs/rsa-public-root-sig.sign";

// files
pub const OVERLAP_FILE: &str = "/etc/seabee_test_overlap";

// keys
pub const ECDSA_PUB: &str = "crypto/keys/ecdsa-public.pem";
pub const RSA_PUB: &str = "crypto/keys/rsa-public.pem";

pub enum Expected {
    Success,
    Error,
}

impl Expected {
    fn err_text(&self) -> &str {
        match &self {
            Expected::Error => "Error",
            Expected::Success => "",
        }
    }

    fn out_text(&self) -> &str {
        match &self {
            Expected::Error => "",
            Expected::Success => "Success",
        }
    }

    fn rc(&self) -> i32 {
        match &self {
            Expected::Error => 1,
            Expected::Success => 0,
        }
    }
}

// Shared Tests

pub fn no_starting_keys_policies() -> Result<(), Failed> {
    // There will always be a root key
    list_keys(1)?;
    list_policies(0)
}

// Shared Helpers

pub fn policies_on_disk(expected: usize) -> Result<(), Failed> {
    let actual = fs::read_dir(constants::POLICY_DIR)?.count();
    if actual != expected {
        return Err(anyhow!(
            "unexpected policy count on disk\nexpected: {expected}, actual: {actual}"
        )
        .into());
    }

    Ok(())
}

pub fn list_policies(count: u32) -> Result<(), Failed> {
    let stdout = if count == 1 {
        "1 SeaBee Policy"
    } else {
        &format!("{count} SeaBee Policies")
    };

    TestCommandBuilder::default()
        .program(SEABEECTL_EXE)
        .args(&["list"])
        .expected_rc(0)
        .expected_stdout(stdout)
        .build()?
        .test()
}

pub fn list_keys(count: u32) -> Result<(), Failed> {
    TestCommandBuilder::default()
        .program(SEABEECTL_EXE)
        .args(&["list-keys"])
        .expected_rc(0)
        .expected_stdout(&format!("Listed {count} Keys"))
        .build()?
        .test()
}

pub fn add_key_unsigned(key: &str, expected: Expected) -> Result<(), Failed> {
    TestCommandBuilder::default()
        .program(SEABEECTL_EXE)
        .args(&["add-key", "-t", &str_to_abs_path_str(key)?])
        .expected_rc(expected.rc())
        .expected_stdout(expected.out_text())
        .expected_stdout(expected.err_text())
        .build()?
        .test()
}

pub fn add_key_signed(key: &str, sig: &str, expected: Expected) -> Result<(), Failed> {
    TestCommandBuilder::default()
        .program(SEABEECTL_EXE)
        .args(&[
            "add-key",
            "-t",
            &str_to_abs_path_str(key)?,
            "-s",
            &str_to_abs_path_str(sig)?,
        ])
        .expected_rc(expected.rc())
        .expected_stdout(expected.out_text())
        .expected_stderr(expected.err_text())
        .build()?
        .test()
}

pub fn update_policy_unsigned(policy: &str, expected: Expected) -> Result<(), Failed> {
    TestCommandBuilder::default()
        .program(SEABEECTL_EXE)
        .args(&["update", "-t", &str_to_abs_path_str(policy)?])
        .expected_rc(expected.rc())
        .expected_stdout(expected.out_text())
        .expected_stderr(expected.err_text())
        .build()?
        .test()
}

pub fn update_policy_signed(policy: &str, sig: &str, expected: Expected) -> Result<(), Failed> {
    TestCommandBuilder::default()
        .program(SEABEECTL_EXE)
        .args(&[
            "update",
            "-t",
            &str_to_abs_path_str(policy)?,
            "-s",
            &str_to_abs_path_str(sig)?,
        ])
        .expected_rc(expected.rc())
        .expected_stdout(expected.out_text())
        .expected_stderr(expected.err_text())
        .build()?
        .test()
}

pub fn remove_policy_unsigned(policy: &str, expected: Expected) -> Result<(), Failed> {
    TestCommandBuilder::default()
        .program(SEABEECTL_EXE)
        .args(&["remove", "-t", &str_to_abs_path_str(policy)?])
        .expected_rc(expected.rc())
        .expected_stdout(expected.out_text())
        .expected_stderr(expected.err_text())
        .build()?
        .test()
}

pub fn remove_policy_signed(policy: &str, sig: &str, expected: Expected) -> Result<(), Failed> {
    TestCommandBuilder::default()
        .program(SEABEECTL_EXE)
        .args(&[
            "remove",
            "-t",
            &str_to_abs_path_str(policy)?,
            "-s",
            &str_to_abs_path_str(sig)?,
        ])
        .expected_rc(expected.rc())
        .expected_stdout(expected.out_text())
        .expected_stderr(expected.err_text())
        .build()?
        .test()
}

pub fn remove_key_unsigned(key: &str, expected: Expected) -> Result<(), Failed> {
    TestCommandBuilder::default()
        .program(SEABEECTL_EXE)
        .args(&["remove-key", "-t", &str_to_abs_path_str(key)?])
        .expected_rc(expected.rc())
        .expected_stdout(expected.out_text())
        .expected_stderr(expected.err_text())
        .build()?
        .test()
}

pub fn remove_key_signed(key: &str, sig: &str, expected: Expected) -> Result<(), Failed> {
    TestCommandBuilder::default()
        .program(SEABEECTL_EXE)
        .args(&[
            "remove-key",
            "-t",
            &str_to_abs_path_str(key)?,
            "-s",
            &str_to_abs_path_str(sig)?,
        ])
        .expected_rc(expected.rc())
        .expected_stdout(expected.out_text())
        .expected_stderr(expected.err_text())
        .build()?
        .test()
}
