// SPDX-License-Identifier: Apache-2.0

use std::process::{Child, Command};

use anyhow::{anyhow, Result};
use libtest_mimic::{Failed, Trial};
use seabee::{constants::SEABEECTL_EXE, utils};
use serde::Deserialize;

use crate::{command::TestCommandBuilder, create_test};

use super::shared::RSA_PUB;

// use debug policy for debug build
#[cfg(debug_assertions)]
mod test_tool_config {
    pub const TEST_TOOL_BIN: &str = "../target/debug/test_tool";
    pub const TEST_TOOL_POLICY: &str = "policies/test_tool_debug_policy.yaml";
    pub const TEST_TOOL_POLICY_SIG: &str = "crypto/sigs/test-tool-debug-policy.sign";
}

// use release policy for release build
#[cfg(not(debug_assertions))]
mod test_tool_config {
    pub const TEST_TOOL_BIN: &str = "../target/release/test_tool";
    pub const TEST_TOOL_POLICY: &str = "policies/test_tool_release_policy.yaml";
    pub const TEST_TOOL_POLICY_SIG: &str = "crypto/sigs/test-tool-release-policy.sign";
}

const TEST_TOOL_PIN: &str = "/sys/fs/bpf/test_tool_pin";
const TEST_PROG_NAME: &str = "test_seabee";

pub fn start_test_tool() -> Result<Child> {
    // add key
    Command::new(SEABEECTL_EXE)
        .args(["add-key", "-t", &utils::str_to_abs_path(RSA_PUB)?])
        .stdout(std::process::Stdio::null())
        .status()?;

    // add policy
    Command::new(SEABEECTL_EXE)
        .args([
            "update",
            "-t",
            &utils::str_to_abs_path(test_tool_config::TEST_TOOL_POLICY)?,
            "-s",
            &utils::str_to_abs_path(test_tool_config::TEST_TOOL_POLICY_SIG)?,
        ])
        .stdout(std::process::Stdio::null())
        .status()?;

    // start process
    let child = Command::new(test_tool_config::TEST_TOOL_BIN)
        .stdout(std::process::Stdio::null())
        .spawn()?;

    // wait up to 10 seconds for eBPF to load
    for _timeout in 1..10 {
        if std::path::Path::new(TEST_TOOL_PIN).exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1))
    }
    Ok(child)
}

pub fn stop_test_tool(child: Child) -> Result<()> {
    // send Ctrl+C to process
    let res = unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    if res != 0 {
        return Err(anyhow!("Failed to send SIGINT to test tool"));
    }

    // cleanup seabee
    Command::new(SEABEECTL_EXE)
        .args(["clean", "policy"])
        .stdout(std::process::Stdio::null())
        .status()?;
    Command::new(SEABEECTL_EXE)
        .args(["clean", "keys"])
        .stdout(std::process::Stdio::null())
        .status()?;

    Ok(())
}

fn deny_remove_pin() -> Result<(), Failed> {
    match std::fs::remove_file(TEST_TOOL_PIN) {
        Err(e) => match e.kind() {
            std::io::ErrorKind::PermissionDenied => Ok(()),
            k => Err(format!("Got: ErrorKind {k}, Expected: PermissionDenied").into()),
        },
        Ok(()) => Err("Got: Ok, Expected: PermissionDenied".into()),
    }
}

#[derive(Debug, Deserialize)]
struct ProgInfo {
    map_ids: Vec<u32>,
}

fn deny_map_access() -> Result<(), Failed> {
    let output = Command::new("bpftool")
        .args(["prog", "show", "name", TEST_PROG_NAME, "-p"])
        .output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    let json_out: ProgInfo = serde_json::from_str(&stdout)
        .map_err(|e| anyhow!("serde_json failed read output of 'bpftool prog show name {TEST_PROG_NAME} -p'\n{e}\nbpftool stdout: {stdout}\nbpftool stderr:{stderr}"))?;

    let mut found_map = false;
    for id in json_out.map_ids {
        found_map = true;
        TestCommandBuilder::default()
            .program("bpftool")
            .args(&["map", "dump", "id", &id.to_string()])
            .expected_rc(255)
            .expected_stderr("Operation not permitted")
            .build()?
            .test()?
    }

    if !found_map {
        return Err(anyhow!("Failed to find any maps for test bpf program").into());
    }
    Ok(())
}

pub fn tests() -> Vec<Trial> {
    vec![create_test!(deny_map_access), create_test!(deny_remove_pin)]
}
