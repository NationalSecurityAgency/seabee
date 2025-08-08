// SPDX-License-Identifier: Apache-2.0

/// Integration test suite for the SeaBee systemd daemon
use libtest_mimic::Failed;

use crate::command::TestCommandBuilder;

/// Test that the daemon is active and running
pub fn daemon_status() -> Result<(), Failed> {
    TestCommandBuilder::default()
        .program("systemctl")
        .args(&["is-active", "test_seabee"])
        .expected_rc(0)
        .expected_stdout("active")
        .build()?
        .test()
}

/// Test that the individual threads of the daemon cannot be killed
pub fn daemon_deny_tid_sigkill() -> Result<(), Failed> {
    let main_pid = get_daemon_main_pid()?;
    for tid in get_daemon_tids(main_pid)? {
        TestCommandBuilder::default()
            .program("kill")
            .args(&["-s", "SIGKILL", &tid.to_string()])
            .expected_rc(1)
            .build()?
            .test()?;
        std::thread::sleep(std::time::Duration::from_secs(1));
        is_running(tid)?;
    }
    Ok(())
}

/// Helper to get the main process id of the daemon
fn get_daemon_main_pid() -> Result<u64, Failed> {
    let (stdout, _) = TestCommandBuilder::default()
        .program("systemctl")
        .args(&["show", "--property", "MainPID", "--value", "test_seabee"])
        .expected_rc(0)
        .build()?
        .test_result()?;
    match stdout.trim().parse::<u64>() {
        Ok(x) => Ok(x),
        Err(_) => Err(format!("Unable to convert \"{stdout}\" into integer").into()),
    }
}

/// Helper to get all of the thread pids of the daemon
fn get_daemon_tids(pid: u64) -> Result<Vec<u64>, Failed> {
    let path = format!("/proc/{pid}/task");
    let (stdout, _) = TestCommandBuilder::default()
        .program("ls")
        .args(&[&path])
        .expected_rc(0)
        .build()?
        .test_result()?;
    let mut tids = Vec::new();
    for line in stdout.split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        match line.trim().parse::<u64>() {
            Ok(x) => tids.push(x),
            Err(_) => return Err(format!("Unable to convert \"{line}\" into integer").into()),
        };
    }
    Ok(tids)
}

/// Helper to determine if a process / thread is still running
fn is_running(pid: u64) -> Result<(), Failed> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let stat_split: Vec<&str> = stat.split_whitespace().collect();
    if stat_split[2] != "R" && stat_split[2] != "S" {
        return Err(format!(
            "pid {} has status {} and is not running",
            pid, stat_split[2]
        )
        .into());
    }
    Ok(())
}
