// SPDX-License-Identifier: Apache-2.0

/// Module to check the security of ptrace protections
///
/// TODO: Do we need to create a fork and ptrace our parent?
///       Otherwise, it's unclear if `EPERM` is from SeaBee
use libtest_mimic::{Failed, Trial};

use crate::create_test;

/// Tests whether a ptrace can be attached to the current process
fn security_ptrace_deny_attach() -> Result<(), Failed> {
    match nix::sys::ptrace::attach(nix::unistd::getpid()) {
        Ok(_) => Err("Was able to ptrace attach to process".into()),
        Err(err) => {
            if err != nix::Error::EPERM {
                Err(format!("Ptrace attach gave unexpected error: {err}").into())
            } else {
                Ok(())
            }
        }
    }
}

pub fn tests() -> Vec<Trial> {
    vec![create_test!(security_ptrace_deny_attach)]
}
