// SPDX-License-Identifier: Apache-2.0

/// Functions to gather BPF information from a Linux userspace
///
/// See `BPFState` for more details.
use std::num::ParseIntError;
use std::os::unix::fs::DirEntryExt;
use std::path::PathBuf;
use std::process::Command;
use std::{collections::HashMap, path::Path};

use anyhow::{anyhow, Context, Result};
use libbpf_rs::{skel::Skel, MapCore};
use serde::Deserialize;

use super::{BPFState, MapState, PinState};

/// Helper structure to deserialize standard maps from `bpftool`
#[derive(Deserialize)]
struct BPFToolMapDump {
    key: Vec<String>,
    value: Vec<String>,
}

/// Helper structure to deserialize PerCPU map values from `bpftool`
#[derive(Deserialize)]
struct BPFToolPerCPUMapDumpValue {
    value: Vec<String>,
}

/// Helper structure to deserialize PerCPU maps from `bpftool`
#[derive(Deserialize)]
struct BPFToolPerCPUMapDump {
    key: Vec<String>,
    values: Vec<BPFToolPerCPUMapDumpValue>,
}

/// Runs `bpftool` with the given arguments and returns output from stdout
fn bpftool_command(args: &str) -> Result<String> {
    let output = Command::new("bpftool")
        .args(args.split_whitespace())
        .output()?;
    Ok(String::from_utf8(output.stdout)?)
}

/// Converts strings output by `bpftool` into a vector of bytes that
/// can be compared against other [BPFState] objects in a consistent manner
fn bpftool_str_to_bytes(strings: &[String]) -> Result<Vec<u8>, ParseIntError> {
    strings
        .iter()
        .map(|string| parse_int::parse::<u8>(string))
        .collect()
}

/// Creates a [HashMap] of [MapState] objects with information harvested
/// by running bpftool
fn bpftool_maps(skel: &dyn Skel, ground_truth: &BPFState) -> Result<HashMap<String, MapState>> {
    let mut hashmap = HashMap::new();
    for map in skel.object().maps() {
        let name = map
            .name()
            .to_str()
            .context(format!("Cannot convert {:#?}", map.name()))?;
        let map_id = map.info()?.info.id;
        let gt_map_state = match ground_truth.maps.get(name) {
            Some(map_state) => map_state,
            None => return Err(anyhow!("\"{}\" map not found in ground truth", name)),
        };
        let show_str = bpftool_command(&format!("-j map show id {map_id}"))?;
        let mut state: MapState = serde_json::from_slice(show_str.as_bytes())?;
        state.is_static = gt_map_state.is_static;

        // don't read the data if the map isn't static, it won't be tested
        if state.bytes_key != 0 && state.is_static {
            let dump_str = bpftool_command(&format!("-j map dump id {}", &state.id))?;
            if state._type.starts_with("percpu") {
                let data: Vec<BPFToolPerCPUMapDump> = serde_json::from_slice(dump_str.as_bytes())?;
                for entry in data.iter() {
                    let key = bpftool_str_to_bytes(&entry.key)?;
                    let mut values = Vec::new();
                    for value in entry.values.iter() {
                        values.push(bpftool_str_to_bytes(&value.value)?);
                    }
                    state.data.insert(key, values);
                }
            } else {
                let data: Vec<BPFToolMapDump> = serde_json::from_slice(dump_str.as_bytes())?;
                for entry in data {
                    let key = bpftool_str_to_bytes(&entry.key)?;
                    let value = bpftool_str_to_bytes(&entry.value)?;
                    state.data.insert(key, vec![value]);
                }
            }
        }
        hashmap.insert(name.to_string(), state);
    }
    Ok(hashmap)
}

/// Checks whether the pin directory exists on the BPF filesystem
/// and is a valid directory
fn check_pin_dir(pin_dir: &Path) -> Result<()> {
    if !pin_dir.exists() {
        return Err(anyhow!(
            "Pin dir `{}` doesn't exist",
            pin_dir.to_string_lossy()
        ));
    }
    // Test that the path points to a directory
    if !pin_dir.is_dir() {
        return Err(anyhow!(
            "Pin dir `{}` is not a directory",
            pin_dir.to_string_lossy()
        ));
    }
    Ok(())
}

/// Gathers [PinState] information by reading the Linux filesystem
fn linux_pins(pin_dir: &PathBuf) -> Result<PinState> {
    check_pin_dir(pin_dir)?;
    let mut pins = HashMap::new();
    for pin in std::fs::read_dir(pin_dir)? {
        let pin = pin?;
        pins.insert(pin.file_name().to_string_lossy().to_string(), pin.ino());
    }
    Ok(PinState {
        dir: pin_dir.to_string_lossy().to_string(),
        pins,
    })
}

/// Creates a [BPFState] object from the perspective of a
/// superuser in Linux
pub fn linux_state(
    skel: &dyn Skel,
    pin_dir: &PathBuf,
    ground_truth: &BPFState,
) -> Result<BPFState> {
    Ok(BPFState {
        maps: bpftool_maps(skel, ground_truth)?,
        pins: linux_pins(pin_dir)?,
        ..Default::default()
    })
}
