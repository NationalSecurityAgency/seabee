// SPDX-License-Identifier: Apache-2.0

/// Module to run a binary in a forked process, check its output,
/// and optionally return the output captured in stdout and stderr
use std::process::{Command, Output};

use derive_builder::Builder;
use libtest_mimic::Failed;

/// Create a [Failed] with a message and the stdout and stderr of the output
fn command_err(msg: String, output: Output) -> Result<(String, String), Failed> {
    let mut err = msg;
    err.push_str(&format!(
        "\nstdout: \"{}\"",
        &String::from_utf8(output.stdout)?
    ));
    err.push_str(&format!(
        "\nstderr: \"{}\"",
        &String::from_utf8(output.stderr)?
    ));
    Err(err.into())
}

/// Structure which holds all of the information necessary to run a specific
/// binary and (optionally) check its output for expected values
#[derive(Builder, Default)]
#[builder(setter(strip_option))]
pub struct TestCommand<'a> {
    /// The binary to run in a forked process
    program: &'a str,
    /// Optional: The arguments to pass to the binary
    #[builder(default)]
    args: Option<&'a [&'a str]>,
    /// Optional: The expected return code
    #[builder(default)]
    expected_rc: Option<i32>,
    /// Optional: Expected string to find in stdout
    #[builder(default)]
    expected_stdout: Option<&'a str>,
    /// Optional: Expected string to find in stderr
    #[builder(default)]
    expected_stderr: Option<&'a str>,
}

impl TestCommand<'_> {
    /// Runs the command as configured and returns the output captured in stdout and stderr
    ///
    /// It also checks for the expected values (if set in the builder)
    pub fn test_result(&self) -> Result<(String, String), Failed> {
        let output = if let Some(args) = self.args {
            Command::new(self.program).args(args).output()?
        } else {
            Command::new(self.program).output()?
        };
        // Check the return code from the binary
        if let Some(exp_rc) = self.expected_rc {
            match output.status.code() {
                Some(errno) => {
                    if errno != exp_rc {
                        return command_err(
                            format!(
                                "Unexpected errno from {} {:?}\n got: {}, expected: {}",
                                self.program, self.args, errno, exp_rc
                            ),
                            output,
                        );
                    }
                }
                None => {
                    return command_err(format!("{} terminated by signal", self.program), output)
                }
            }
        }
        // Check the output captured in stdout
        let stdout = String::from_utf8(output.stdout.clone())?;
        if let Some(exp_stdout) = self.expected_stdout {
            if !stdout.contains(exp_stdout) {
                return command_err(
                    format!("Unexpected stdout, wanted: \"{exp_stdout}\""),
                    output,
                );
            }
        }
        // Check the output captured in stderr
        let stderr = String::from_utf8(output.stderr.clone())?;
        if let Some(exp_stderr) = self.expected_stderr {
            if !stderr.contains(exp_stderr) {
                return command_err(
                    format!("Unexpected stderr, wanted: \"{exp_stderr}\""),
                    output,
                );
            }
        }
        Ok((stdout, stderr))
    }

    /// Convenience method to run [TestCommand::test_result] but discarding the pipe output
    pub fn test(&self) -> Result<(), Failed> {
        match self.test_result() {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}
