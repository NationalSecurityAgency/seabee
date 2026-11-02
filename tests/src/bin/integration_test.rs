// SPDX-License-Identifier: Apache-2.0
use std::{
    mem::MaybeUninit,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::Result;
use libbpf_rs::OpenObject;
use libtest_mimic::{Arguments, Failed};

use bpf::logging::LogLevel;
use seabee::{
    config::{self, configure_logging, Config, SecurityLevel},
    constants, utils, SeaBee,
};
use tests::suite::{TestSuite, TestSystemState};

use tests::functional::FunctionalTestSuite as SBFTS;
use tests::security::SeaBeeSecurityTestSuite as SBSTS;
use tracing::info;

const GROUND_TRUTH: &str = "ground_truth.toml";

#[derive(Debug)]
struct ThreadControl {
    thread_handle: std::thread::JoinHandle<Result<()>>,
    stop_trigger: Arc<AtomicBool>,
}

fn start_seabee_with_logging(
    config: Config,
    open_obj: &mut MaybeUninit<OpenObject>,
) -> Result<(SeaBee<'_>, ThreadControl)> {
    config::init_paths()?;
    let sb = seabee::seabee_init(config, open_obj)?;
    let stop_trigger = Arc::new(AtomicBool::new(true));
    let stop_trigger_clone = stop_trigger.clone();
    let log_rb = bpf::logging::setup_logger(&sb.maps.log_ringbuf)?;

    let thread_handle = std::thread::Builder::new().spawn(move || -> Result<()> {
        let timeout = std::time::Duration::from_millis(10);
        while stop_trigger_clone.load(std::sync::atomic::Ordering::SeqCst) {
            if let Err(e) = log_rb.poll(timeout) {
                // sometimes SIGINT will interrupt poll() which is okay
                if e.kind() != libbpf_rs::ErrorKind::Interrupted {
                    tracing::error!("error during poll:\n{e}")
                }
            }
        }
        Ok(())
    })?;
    let thread_control = ThreadControl {
        thread_handle,
        stop_trigger,
    };

    Ok((sb, thread_control))
}

fn cleanup_seabee_with_logging(thread_control: ThreadControl) -> Result<()> {
    thread_control.stop_trigger.store(false, Ordering::SeqCst);
    thread_control
        .thread_handle
        .join()
        .expect("Failed to join thread handle")?;
    Ok(())
}

/// Tests the functionality of the SeaBee userspace with minimal security
fn functional_tests(args: &Arguments, log_level: LogLevel) -> Result<(), Failed> {
    let mut config = Config {
        // to allow an errant test to be stopped
        sigint: true,
        // to allow other processes like bpftool to run
        test: true,
        log_level,
        ..Default::default()
    };
    // to allow the Linux state to be gathered
    config.policy_config.map_access = SecurityLevel::audit;

    let mut open_obj = MaybeUninit::uninit();
    let (sb, thread_control) = start_seabee_with_logging(config, &mut open_obj)?;
    let pin_dir = &PathBuf::from(constants::PIN_DIR);
    SBFTS::run_tests(
        args,
        TestSystemState::new(&*sb.skel, pin_dir, GROUND_TRUTH)?,
        0,
    )?;
    cleanup_seabee_with_logging(thread_control)?;

    SBFTS::check_args(TestSystemState::new(&*sb.skel, pin_dir, GROUND_TRUTH)?)?;

    Ok(())
}

/// Tests the security of the SeaBee userspace with maximum security
fn security_tests(args: &Arguments, log_level: LogLevel) -> Result<(), Failed> {
    let config = Config {
        // don't allow kernel modules to be loaded
        kmod: SecurityLevel::block,
        // to allow an errant test to be stopped
        sigint: true,
        // to allow other processes like kill and bpftool to run
        test: true,
        log_level,
        ..Default::default()
    };

    let mut open_obj = MaybeUninit::uninit();
    let (sb, thread_control) = start_seabee_with_logging(config.clone(), &mut open_obj)?;
    let pin_dir = &PathBuf::from(constants::PIN_DIR);
    SBSTS::run_tests(
        args,
        TestSystemState::new(&*sb.skel, pin_dir, GROUND_TRUTH)?,
        config,
    )?;
    cleanup_seabee_with_logging(thread_control)?;
    SBSTS::check_args(TestSystemState::new(&*sb.skel, pin_dir, GROUND_TRUTH)?)?;

    Ok(())
}

fn fork_integration_test(log_level: LogLevel) -> Result<(), Failed> {
    let config = Config {
        log_level,
        ..Default::default()
    };
    let mut open_obj = MaybeUninit::uninit();
    start_seabee_with_logging(config, &mut open_obj)
        .expect_err("starting a thread should not have been possible");
    info!("Fork integration test passed");
    Ok(())
}

fn main() -> Result<(), Failed> {
    let args = Arguments::from_args();
    // verify system requirements and dependencies
    utils::verify_requirements()?;

    // This will cause logs to only print if a test fails, in which case, the log level can be made more granular
    // Note that since the tests are run in parallel, any log output generated from eBPF may not correlate with
    // the test that failed.
    let test_log_level = LogLevel::LOG_LEVEL_ERROR;
    configure_logging(test_log_level)?;

    functional_tests(&args, test_log_level)?;
    security_tests(&args, test_log_level)?;
    fork_integration_test(test_log_level)?;

    println!("Successfully Completed Integration Tests!");
    Ok(())
}
