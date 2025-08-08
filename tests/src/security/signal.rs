// SPDX-License-Identifier: Apache-2.0

/// Module to check the security of signal protections
use libtest_mimic::{Failed, Trial};

use seabee::utils::{generate_sigmask, is_sigint_allowed};

use crate::{create_test, suite::TestSuite};

use super::SeaBeeSecurityTestSuite;

/// Attempts to run `kill` with specified arguments and return code
fn try_kill(signal: i32, expect_success: bool) -> Result<(), Failed> {
    let res = unsafe { libc::kill(libc::getpid(), signal) };
    if res == 0 && !expect_success {
        Err(format!("Signal {signal:?} should not have succeeded: {res}").into())
    } else if res != 0 && expect_success {
        Err(format!("Signal {signal:?} should not have failed: {res}").into())
    } else {
        Ok(())
    }
}

/// Check that a null/0 signal can be sent to the userspace
/// This is commonly used to see if a pid still exists
fn security_signal_send_null() -> Result<(), Failed> {
    try_kill(0, true)
}

/// Check that the process survives a SIGKILL
fn security_signal_send_sigkill() -> Result<(), Failed> {
    try_kill(libc::SIGKILL, false)
}

/// Check that the sigmask works to block unwanted signals
fn security_signal_check_sigmask() -> Result<(), Failed> {
    let config = SeaBeeSecurityTestSuite::get_custom_state()?;
    let sigmask = generate_sigmask(config.sigint);

    for signal in 1..=libc::SIGRTMAX() {
        // SIGINT is reserved as a 'backdoor' for test purposes
        if signal == libc::SIGINT && is_sigint_allowed(config.sigint) {
            continue;
        }
        // if the signal is allowed skip it
        if (1 << (signal - 1)) & sigmask != 0 {
            continue;
        }
        try_kill(signal, false)?
    }
    Ok(())
}

pub fn tests() -> Vec<Trial> {
    vec![
        create_test!(security_signal_send_null),
        create_test!(security_signal_send_sigkill),
        create_test!(security_signal_check_sigmask),
    ]
}
