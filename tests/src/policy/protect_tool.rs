// SPDX-License-Identifier: Apache-2.0

use std::{
    io::{ErrorKind, Write},
    path::Path,
    process::{Child, Command},
    sync::{
        atomic::{AtomicU32, Ordering},
        OnceLock,
    },
};

use anyhow::{anyhow, Result};
use libtest_mimic::{Failed, Trial};
use seabee::{config::SecurityLevel, constants::SEABEECTL_EXE, utils};
use serde::Deserialize;

use crate::{
    command::TestCommandBuilder,
    create_test,
    test_utils::{self, try_chmod, try_create_file, try_open, try_unlink_file, PtraceOp},
};

use super::{
    shared::{RSA_PUB, RSA_PUB_ROOT_SIG},
    test_constants,
};

// Globals
pub static TEST_TOOL_PID: OnceLock<AtomicU32> = OnceLock::new();
pub const REMOVE_TEST_TOOL_POLICY: &str = "policies/remove_test_tool_policy.yaml";
pub const REMOVE_TEST_TOOL_POLICY_SIG: &str = "crypto/sigs/remove-test-tool-policy.sign";
pub const TEST_TOOL_OVERWRITE: &str = "policies/test_tool_overwrite.yaml";
pub const TEST_TOOL_OVERWRITE_SIG: &str = "policies/test_tool_overwrite.sign";

// use debug policy for debug build
#[cfg(debug_assertions)]
mod test_tool_config {
    pub const TEST_TOOL_BIN: &str = "../target/debug/test_tool";
    pub const TEST_TOOL_AUDIT_POLICY: &str = "policies/test_tool_debug_audit.yaml";
    pub const TEST_TOOL_AUDIT_POLICY_SIG: &str = "crypto/sigs/test-tool-debug-audit.sign";
    pub const TEST_TOOL_BLOCK_POLICY: &str = "policies/test_tool_debug_block.yaml";
    pub const TEST_TOOL_BLOCK_POLICY_SIG: &str = "crypto/sigs/test-tool-debug-block.sign";
}

// use release policy for release build
#[cfg(not(debug_assertions))]
mod test_tool_config {
    pub const TEST_TOOL_BIN: &str = "../target/release/test_tool";
    pub const TEST_TOOL_AUDIT_POLICY: &str = "policies/test_tool_release_audit.yaml";
    pub const TEST_TOOL_AUDIT_POLICY_SIG: &str = "crypto/sigs/test-tool-release-audit.sign";
    pub const TEST_TOOL_BLOCK_POLICY: &str = "policies/test_tool_release_block.yaml";
    pub const TEST_TOOL_BLOCK_POLICY_SIG: &str = "crypto/sigs/test-tool-release-block.sign";
}

const TEST_PROG_NAME: &str = "test_seabee";

pub fn start_test_tool(level: SecurityLevel) -> Result<Child> {
    // create test dir
    if let Err(e) = std::fs::create_dir(test_constants::TEST_TOOL_DIR) {
        if e.kind() != ErrorKind::AlreadyExists {
            return Err(anyhow!(
                "failed create_dir on {}:{e}",
                test_constants::TEST_TOOL_DIR
            ));
        }
    }
    // create file
    let mut file = std::fs::File::create(test_constants::TEST_TOOL_FILE).map_err(|e| {
        anyhow!(
            "failed to create file {}: {e}",
            test_constants::TEST_TOOL_FILE
        )
    })?;
    file.write_all(b"Hello, World!")?;

    // add key
    Command::new(SEABEECTL_EXE)
        .args(["add-key", "-t", &utils::str_to_abs_path_str(RSA_PUB)?])
        .stdout(std::process::Stdio::null())
        .status()?;

    // choose which policy to use
    let (policy_file, policy_sig) = match level {
        SecurityLevel::allow | SecurityLevel::audit => (
            test_tool_config::TEST_TOOL_AUDIT_POLICY,
            test_tool_config::TEST_TOOL_AUDIT_POLICY_SIG,
        ),
        SecurityLevel::block => (
            test_tool_config::TEST_TOOL_BLOCK_POLICY,
            test_tool_config::TEST_TOOL_BLOCK_POLICY_SIG,
        ),
    };

    // add policy
    Command::new(SEABEECTL_EXE)
        .args([
            "update",
            "-t",
            &utils::str_to_abs_path_str(policy_file)?,
            "-s",
            &utils::str_to_abs_path_str(policy_sig)?,
        ])
        .stdout(std::process::Stdio::null())
        .status()?;

    // start process
    let child = Command::new(test_tool_config::TEST_TOOL_BIN)
        .stdout(std::process::Stdio::null())
        .spawn()?;

    // wait up to 10 seconds for eBPF to load
    for _timeout in 1..10 {
        if std::path::Path::new(test_constants::TEST_TOOL_PIN_PATH).exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1))
    }
    TEST_TOOL_PID
        .get_or_init(|| AtomicU32::new(0))
        .store(child.id(), Ordering::SeqCst);

    Ok(child)
}

pub fn stop_test_tool(child: Child) -> Result<()> {
    // send Ctrl+C to process
    let res = unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    if res != 0 {
        return Err(anyhow!("Failed to send SIGINT to test tool"));
    }

    // remove policy
    Command::new(SEABEECTL_EXE)
        .args([
            "remove",
            "-t",
            &utils::str_to_abs_path_str(REMOVE_TEST_TOOL_POLICY)?,
            "-s",
            &utils::str_to_abs_path_str(REMOVE_TEST_TOOL_POLICY_SIG)?,
        ])
        .stdout(std::process::Stdio::null())
        .status()?;

    // remove key
    Command::new(SEABEECTL_EXE)
        .args([
            "remove-key",
            "-t",
            &utils::str_to_abs_path_str(RSA_PUB)?,
            "-s",
            &utils::str_to_abs_path_str(RSA_PUB_ROOT_SIG)?,
        ])
        .stdout(std::process::Stdio::null())
        .status()?;

    Ok(())
}

fn deny_policy_overwrite() -> Result<(), Failed> {
    // Try to overwrite policy
    TestCommandBuilder::default()
        .program(SEABEECTL_EXE)
        .args(&[
            "update",
            "-t",
            &utils::str_to_abs_path_str(TEST_TOOL_OVERWRITE)?,
            "-s",
            &utils::str_to_abs_path_str(TEST_TOOL_OVERWRITE_SIG)?,
        ])
        .expected_rc(0)
        .expected_stdout("Success");

    // try to delete a protected file
    try_unlink_file(test_constants::TEST_TOOL_FILE, false)?;

    Ok(())
}

fn deny_remove_pin() -> Result<(), Failed> {
    match std::fs::remove_file(test_constants::TEST_TOOL_PIN_PATH) {
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

/// Check that a null/0 signal can be sent to the process
fn allow_signal_null() -> Result<(), Failed> {
    test_utils::try_kill(0, TEST_TOOL_PID.get().unwrap().load(Ordering::SeqCst), true)
}

// /Check that a an allowed signal is allowed
fn allow_signal_winch() -> Result<(), Failed> {
    test_utils::try_kill(
        libc::SIGWINCH,
        TEST_TOOL_PID.get().unwrap().load(Ordering::SeqCst),
        true,
    )
}

/// Check that a blocked signal is blocked
fn deny_sigkill() -> Result<(), Failed> {
    test_utils::try_kill(
        libc::SIGKILL,
        TEST_TOOL_PID.get().unwrap().load(Ordering::SeqCst),
        false,
    )
}

/// Check that ptrace is properly blocked
fn deny_ptrace_attach() -> Result<(), Failed> {
    test_utils::try_ptrace(
        PtraceOp::Attach,
        TEST_TOOL_PID.get().unwrap().load(Ordering::SeqCst),
        false,
    )
}

fn deny_ptrace_seize() -> Result<(), Failed> {
    test_utils::try_ptrace(
        PtraceOp::Seize,
        TEST_TOOL_PID.get().unwrap().load(Ordering::SeqCst),
        false,
    )
}

// check that directory is properly protected
fn deny_delete_dir() -> Result<(), Failed> {
    test_utils::try_remove_dir_all(test_constants::TEST_TOOL_DIR, false)
}

// check that file is properly protected
fn deny_delete_file() -> Result<(), Failed> {
    test_utils::try_unlink_file(test_constants::TEST_TOOL_FILE, false)
}

// check that new files cannot be created in protected directory
fn deny_create_file() -> Result<(), Failed> {
    test_utils::try_create_file(Path::new(test_constants::TEST_TOOL_FILE), false)
}

// check that protected files cannot be edited
fn deny_open_file() -> Result<(), Failed> {
    test_utils::try_open(Path::new(test_constants::TEST_TOOL_FILE), false, false)
}

// check that protected file attributes cannot be modified
fn deny_chmod_file() -> Result<(), Failed> {
    test_utils::try_chmod(test_constants::TEST_TOOL_FILE, false)
}

fn deny_rename_file() -> Result<(), Failed> {
    test_utils::try_rename(test_constants::TEST_TOOL_FILE, false)
}

// check that protected directory attributes cannot be modified
fn deny_chmod_dir() -> Result<(), Failed> {
    test_utils::try_chmod(test_constants::TEST_TOOL_DIR, false)
}

/// Check that ptrace can be allowed as well
fn allow_ptrace_attach() -> Result<(), Failed> {
    test_utils::try_ptrace(
        PtraceOp::Attach,
        TEST_TOOL_PID.get().unwrap().load(Ordering::SeqCst),
        true,
    )
}

fn allow_ptrace_seize() -> Result<(), Failed> {
    test_utils::try_ptrace(
        PtraceOp::Seize,
        TEST_TOOL_PID.get().unwrap().load(Ordering::SeqCst),
        true,
    )
}

fn allow_open_file() -> Result<(), Failed> {
    try_open(Path::new(test_constants::TEST_TOOL_FILE), false, true)
}

fn allow_create_file() -> Result<(), Failed> {
    let path = Path::new(test_constants::TEST_TOOL_DIR).join("testfile");
    try_create_file(&path, true)
}

fn allow_chmod_file() -> Result<(), Failed> {
    try_chmod(test_constants::TEST_TOOL_FILE, true)
}

fn allow_chmod_dir() -> Result<(), Failed> {
    try_chmod(test_constants::TEST_TOOL_DIR, true)
}

fn allow_delete_file() -> Result<(), Failed> {
    test_utils::try_unlink_file(test_constants::TEST_TOOL_FILE, true)
}

fn allow_delete_dir() -> Result<(), Failed> {
    test_utils::try_remove_dir_all(test_constants::TEST_TOOL_DIR, true)
}

fn allow_unlink_pin() -> Result<(), Failed> {
    test_utils::try_unlink_file(test_constants::TEST_TOOL_PIN_PATH, true)
}

// TODO: missing test case, prevent one policy from overwriting files/processes of another

fn block_tests() -> Vec<Trial> {
    vec![
        create_test!(deny_map_access),
        create_test!(deny_remove_pin),
        create_test!(allow_signal_null),
        create_test!(allow_signal_winch),
        create_test!(deny_sigkill),
        create_test!(deny_ptrace_attach),
        create_test!(deny_ptrace_seize),
        create_test!(deny_delete_dir),
        create_test!(deny_delete_file),
        create_test!(deny_create_file),
        create_test!(deny_open_file),
        create_test!(deny_chmod_file),
        create_test!(deny_chmod_dir),
        create_test!(deny_rename_file),
        create_test!(deny_policy_overwrite),
    ]
}

fn audit_tests() -> Vec<Trial> {
    // Since this tests are allowing actions, the order matters
    // consider where to place a test in the order when adding tests
    vec![
        create_test!(allow_ptrace_seize),
        create_test!(allow_ptrace_attach),
        create_test!(allow_open_file),
        create_test!(allow_create_file),
        create_test!(allow_chmod_file),
        create_test!(allow_chmod_dir),
        create_test!(allow_delete_file),
        create_test!(allow_delete_dir),
        create_test!(allow_unlink_pin),
    ]
}

pub fn get_tests(level: SecurityLevel) -> Vec<Trial> {
    match level {
        SecurityLevel::allow | SecurityLevel::audit => audit_tests(),
        SecurityLevel::block => block_tests(),
    }
}
