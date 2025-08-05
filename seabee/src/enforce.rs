// SPDX-License-Identifier: Apache-2.0
use std::{collections::HashSet, mem::MaybeUninit, path::Path};

use anyhow::{Context, Result};
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    OpenObject,
};
use tracing::info;

use crate::{
    cli::SecurityLevel,
    config::Config,
    constants, kernel_api,
    policy::{policy_file::BASE_POLICY_ID, SeaBeePolicy},
    utils, SeaBee, SeaBeeMapHandles,
};
use bpf::{common::get_map, seabee};

type DeviceNumber = u64;

/// Return the device id of a given path
fn dev_id(path: &str) -> Result<DeviceNumber> {
    Ok(nix::sys::stat::stat(path)?.st_dev)
}

/// Load enforcing eBPF programs in the desired configuration.
/// This includes all programs that use LSM to make access control decisions.
pub fn load_ebpf(
    config: Config,
    policy: SeaBeePolicy,
    open_obj: &mut MaybeUninit<OpenObject>,
) -> Result<SeaBee> {
    // Build and load skeleton
    let mut skel = edit_seabee_skel(&config, open_obj)?;

    let maps = SeaBeeMapHandles {
        inode_storage: get_map("inode_storage", &*skel)?,
        log_ringbuf: get_map("log_ringbuf", &*skel)?,
        map_to_pol_id: get_map("map_to_pol_id", &*skel)?,
        policy: get_map("policy_map", &*skel)?,
        task_storage: get_map("task_storage", &*skel)?,
        path_to_pol_id: get_map("path_to_pol_id", &*skel)?,
    };

    // Attach enforce skeleton
    let pinned_links = bpf::common::attach_pin_programs(
        &mut *skel,
        Path::new(constants::PIN_DIR),
        generate_prog_filter(&config),
    )?;

    // #################################################
    // NOTE: do not add any code between these two calls
    // #################################################

    // Create SeaBee to enable Drop (RAII) protections on the pins
    let sb = SeaBee {
        config,
        skel,
        maps,
        policy,
    };

    // Apply base policy
    kernel_api::update_kernel_policy_map(
        &sb.maps,
        sb.policy.base_policy.id,
        &sb.policy.base_policy.config,
    )?;
    // protect objects
    kernel_api::label_seabee_process(&sb)?;
    kernel_api::label_maps_for_skel(&*sb.skel, BASE_POLICY_ID, &sb.maps)?;
    kernel_api::label_pins(&pinned_links, BASE_POLICY_ID, &sb.maps)?;
    kernel_api::label_files_from_policy(&sb.policy.base_policy, &sb.maps)?;

    info!("Sucessfully loaded eBPF LSM");
    Ok(sb)
}

/// Reduce editing boilerplate when adding new skeletons
fn edit_seabee_skel<'a>(
    config: &Config,
    open_obj: &'a mut MaybeUninit<OpenObject>,
) -> Result<Box<dyn Skel<'a> + 'a>> {
    let mut open_skel = seabee::SeabeeSkelBuilder::default().open(open_obj)?;
    open_skel.maps.bss_data.my_pid = std::process::id();
    open_skel.maps.bss_data.sigmask = utils::generate_sigmask(config.sigint);
    open_skel.maps.bss_data.bpf_dev_id = dev_id(constants::BPF_PATH)?;
    open_skel.maps.bss_data.sys_dev_id = dev_id(constants::SYS_PATH)?;
    // Set which level of logs will be printed
    open_skel.maps.bss_data.log_level = config.log_level as u32;
    open_skel.maps.bss_data.kmod_modification = config.kmod as u32;
    open_skel
        .maps
        .map_to_pol_id
        .set_max_entries(constants::SEABEE_MAX_MAPS)
        .context(format!(
            "Couldn't set max protected map entries to {}",
            constants::SEABEE_MAX_MAPS
        ))?;
    open_skel
        .maps
        .policy_map
        .set_max_entries(constants::SEABEE_MAX_POLICIES)
        .context(format!(
            "Couldn't set max pids entries to {}",
            constants::SEABEE_MAX_POLICIES
        ))?;
    open_skel
        .maps
        .path_to_pol_id
        .set_max_entries(constants::SEABEE_MAX_POLICY_SCOPES)
        .context(format!(
            "Couldn't set max pids entries to {}",
            constants::SEABEE_MAX_POLICY_SCOPES
        ))?;
    Ok(Box::new(open_skel.load()?))
}

/// Used to prevent some eBPF programs from loading if they are unecessary based on the config.
/// This is a performance optimization.
fn generate_prog_filter(config: &Config) -> HashSet<String> {
    let mut filtered_progs = HashSet::new();
    // if kernel module loading is allowed,
    // then don't load the program
    if config.kmod == SecurityLevel::allow {
        filtered_progs.insert(String::from("seabee_kernel_read_file"));
        filtered_progs.insert(String::from("seabee_kernel_module_request"));
        filtered_progs.insert(String::from("seabee_kernel_load_data"));
    }
    crate::lockdown::lockdown_seabee(config, &mut filtered_progs);
    crate::policy::generate_policy_prog_filter(config, &mut filtered_progs);
    filtered_progs
}
