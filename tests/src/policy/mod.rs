// SPDX-License-Identifier: Apache-2.0

use std::{
    process::{Command, Stdio},
    thread, time,
};

use anyhow::{anyhow, Result};
use libtest_mimic::{Arguments, Failed, Trial};
use seabee::constants::{self, SEABEECTL_EXE};

mod daemon_status;
mod protect_tool;
mod shared;
mod unverified_policy;
mod verified_keys;
mod verified_policy;

const VERIFIED_POLICY_CONFIG: &str = "configs/verified_policy.yaml";
const VERIFIED_KEYS_CONFIG: &str = "configs/verified_keys.yaml";
const UNVERIFIED_POLICY_CONFIG: &str = "configs/unverified_policy.yaml";

fn start_daemon() -> Result<()> {
    let status = Command::new("systemctl")
        .args(["start", "test_seabee.service"])
        .status()?;
    if !status.success() {
        return Err(anyhow!(
            "Failed to start SeaBee daemon.\nstatus: {}",
            status
        ));
    }

    // wait for seabee daemon to be ready
    let max_wait_seconds = 10;
    let mut waited = 0;
    while waited < max_wait_seconds {
        if daemon_is_ready()? {
            break;
        } else {
            thread::sleep(time::Duration::from_secs(1));
            waited += 1;
        }
    }
    if waited == max_wait_seconds {
        return Err(anyhow!(
            "Daemon failed to start. Reached max wait time of {} seconds",
            max_wait_seconds
        ));
    }

    Ok(())
}

/// Uses "seabeectl list" to determine if seabee is ready
fn daemon_is_ready() -> Result<bool> {
    let status = Command::new(SEABEECTL_EXE)
        .arg("list")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    Ok(status.success())
}

fn stop_daemon() -> Result<()> {
    let status = Command::new("systemctl")
        .args(["stop", "test_seabee.service"])
        .status()?;
    if !status.success() {
        return Err(anyhow!("Failed to stop SeaBee daemon.\nstatus: {}", status));
    }
    Ok(())
}

fn update_config(path: &str) -> Result<()> {
    let status = Command::new(SEABEECTL_EXE)
        .args(["config", "update", path])
        .stdout(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(anyhow!(
            "Failed to update SeaBee config.\nstatus: {}",
            status
        ));
    }
    Ok(())
}

fn remove_config() -> Result<()> {
    let status = Command::new(SEABEECTL_EXE)
        .args(["config", "remove"])
        .stdout(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(anyhow!(
            "Failed to remove SeaBee config.\nstatus: {}",
            status
        ));
    }
    Ok(())
}

fn seabeectl_clean_keys_policies() -> Result<()> {
    let status = Command::new(SEABEECTL_EXE)
        .args(["clean", "policy"])
        .stdout(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(anyhow!(
            "Failed to run seabeectl clean policy\nstatus: {}",
            status
        ));
    }
    let status = Command::new(SEABEECTL_EXE)
        .args(["clean", "keys"])
        .stdout(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(anyhow!(
            "Failed to run seabeectl clean keys\nstatus: {}",
            status
        ));
    }
    Ok(())
}

fn check_root_key() -> Result<()> {
    if !std::path::Path::new(constants::SEABEE_ROOT_KEY_PATH).exists() {
        return Err(anyhow!(
            "No root key installed at {}",
            constants::SEABEE_ROOT_KEY_PATH
        ));
    }
    Ok(())
}

fn policy_test_setup() -> Result<()> {
    seabee::utils::verify_requirements()?;
    check_root_key()?;
    seabeectl_clean_keys_policies()?;
    Ok(())
}

fn policy_test_teardown() -> Result<()> {
    remove_config()?;
    Ok(())
}

fn run_tests_with_config(args: &Arguments, tests: Vec<Trial>, config: &str) -> Result<(), Failed> {
    update_config(config)?;
    start_daemon()?;
    let conclusion = libtest_mimic::run(args, tests);
    stop_daemon()?;

    if conclusion.has_failed() {
        return Err("At least one test failed".into());
    }

    Ok(())
}

fn run_protect_tool_tests(args: &Arguments) -> Result<(), Failed> {
    // start tests
    update_config(VERIFIED_POLICY_CONFIG)?;
    start_daemon()?;
    let child = match protect_tool::start_test_tool() {
        Ok(child) => child,
        Err(e) => {
            stop_daemon()?;
            return Err(anyhow!("failed to start test tool: {e}").into());
        }
    };
    // run tests
    let conclusion = libtest_mimic::run(args, protect_tool::tests());
    // conclude tests
    if let Err(e) = protect_tool::stop_test_tool(child) {
        stop_daemon()?;
        return Err(anyhow!("failed to stop test_tool: {e}").into());
    }
    stop_daemon()?;

    if conclusion.has_failed() {
        return Err("At least one test failed".into());
    }

    Ok(())
}

pub fn run_policy_tests(args: &Arguments) -> Result<(), Failed> {
    policy_test_setup()?;

    println!("Run Verified Policy Tests");
    run_tests_with_config(args, verified_policy::tests(), VERIFIED_POLICY_CONFIG)?;
    println!("Run Verified Key Tests");
    run_tests_with_config(args, verified_keys::tests(), VERIFIED_KEYS_CONFIG)?;
    println!("Run Unverified Policy Tests");
    run_tests_with_config(args, unverified_policy::tests(), UNVERIFIED_POLICY_CONFIG)?;
    println!("Test Protecting a Tool");
    run_protect_tool_tests(args)?;

    policy_test_teardown()?;
    Ok(())
}
