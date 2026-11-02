// SPDX-License-Identifier: Apache-2.0
#![allow(non_camel_case_types)]

use std::{mem::MaybeUninit, path::PathBuf, sync::Arc};

use anyhow::Result;
use libbpf_rs::{skel::Skel, MapHandle, OpenObject};
use tracing::{debug, info};

use bpf::logging::{LOG_FILTER, LOG_LEVEL};

use crate::{config::Config, policy::SeaBeePolicy};

mod cli;
pub mod config;
pub mod constants;
pub mod crypto;
mod enforce;
mod kernel_api;
pub mod lockdown;
pub mod policy;
pub mod seabeectl_lib;
mod socket_io;
mod unload_ebpf;
pub mod utils;

pub struct SeaBeeMapHandles {
    pub inode_storage: MapHandle,
    pub log_ringbuf: MapHandle,
    pub map_to_pol_id: MapHandle,
    pub policy_map: MapHandle,
    pub task_storage: MapHandle,
    pub path_to_pol_id: MapHandle,
}

pub struct SeaBee<'a> {
    /// The configuration for SeaBee
    pub config: Config,
    /// The loaded and running skeleton
    pub skel: Box<dyn Skel<'a> + 'a>,
    /// The map handles shared between skeletons
    pub maps: SeaBeeMapHandles,
    pub policy: SeaBeePolicy,
}

impl std::fmt::Debug for SeaBee<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeaBee")
            .field("config", &self.config)
            .field("policy", &self.policy)
            .finish()
    }
}

/// Load all of the eBPF programs in the desired configuration.
///
/// 1. The eBPF code was converted to multiple [libbpf_rs::skel] during compilation.
/// 1. First the 'enforce skeleton' containing eBPF LSM programs is loaded.
/// 1. Next, 'policy skeleton' is loaded containing programs for updating policy.
/// 1. Each program is attached to its hook point and pinned to the eBPF filesystem.
pub fn seabee_init(config: Config, open_obj: &mut MaybeUninit<OpenObject>) -> Result<SeaBee<'_>> {
    // set the static LOG_LEVEL so that it can be used by various skeletons
    LOG_LEVEL.get_or_init(|| config.log_level);
    LOG_FILTER.get_or_init(|| config.log_filter.clone());
    utils::init_machine_id()?;

    print_debug_info(&config);
    let policy = SeaBeePolicy::init(&config)?;
    let mut sb = match enforce::load_ebpf(config.clone(), policy, open_obj) {
        Ok(sb) => sb,
        // failsafe in case the SeaBee structure is not created
        // before an error occurred
        Err(e) => {
            crate::unload_ebpf::cleanup_return();
            return Err(e);
        }
    };
    sb.policy.boot_time_key_load()?;
    sb.policy.boot_time_policy_load(&sb.maps)?;
    sb.policy.init_listener()?;
    // Label seabeectl to enable runtime updates
    kernel_api::add_path_to_scope(
        &sb.maps,
        &PathBuf::from(constants::SEABEECTL_EXE),
        policy::policy_file::BASE_POLICY_ID,
    )?;
    debug!("exit SeaBee init");
    Ok(sb)
}

pub fn main_loop(
    mut seabee: SeaBee,
    ctrlc_handler: Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    debug!("Starting main loop...");

    let log_rb = bpf::logging::setup_logger(&seabee.maps.log_ringbuf)?;

    let timeout = std::time::Duration::from_millis(10);
    while ctrlc_handler.load(std::sync::atomic::Ordering::SeqCst) {
        // sync policy
        policy::runtime_update::runtime_policy_update(&mut seabee)?;
        // check for logs
        if let Err(e) = log_rb.poll(timeout) {
            // sometimes SIGINT will interrupt poll() which is okay
            if e.kind() != libbpf_rs::ErrorKind::Interrupted {
                return Err(e.into());
            }
        }
    }
    info!("Exiting main loop");
    Ok(())
}

/// Prints welcome message
fn print_debug_info(config: &Config) {
    info!("Welcome to the SeaBee userspace!");
    if config.sigint {
        info!("Kill the userspace with the Ctrl+C shortcut");
    }
    info!("See daemon output with `journalctl -u seabee -f`");
    info!("If cannot remove seabee another way, you will have to 'sudo reboot'");
    info!("{:#?}", config);
}
