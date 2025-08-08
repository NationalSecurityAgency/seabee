// SPDX-License-Identifier: Apache-2.0
use std::{collections::HashMap, fmt::Debug};

use serde::{Deserialize, Serialize};
use serde_json_any_key::any_key_map;

pub mod linux;
pub mod rust;

/// Summarized information about a BPF map
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct MapState {
    /// BPF map id
    pub id: u32,
    /// BPF map type, see [libbpf_rs::MapType]
    #[serde(rename = "type")]
    pub _type: String,
    /// true if the map contents will not be written to by kernel eBPF
    is_static: bool,
    /// size in bytes of a key
    pub bytes_key: u32,
    /// byte-vector copy of key/value paired data in the BPF map
    pub bytes_value: u32,
    #[serde(with = "any_key_map")]
    pub data: HashMap<Vec<u8>, Vec<Vec<u8>>>,
}

impl PartialEq for MapState {
    fn eq(&self, other: &Self) -> bool {
        if self.id != other.id
            || self._type != other._type
            || self.bytes_key != other.bytes_key
            || self.bytes_value != other.bytes_value
            || (self.is_static && self.data != other.data)
        {
            return false;
        }
        true
    }
}

/// Summarized pin information
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct PinState {
    /// pin directory on the BPF filesystem
    pub dir: String,
    /// pin paths on the BPF filesystem
    pub pins: HashMap<String, u64>,
}

/// Summarized BPF userspace, map, and pin state
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct BPFState {
    /// process id of the SeaBee userspace
    pub pid: u32,
    /// static dump of eBPF map information
    pub maps: HashMap<String, MapState>,
    /// static dump of eBPF pin information
    pub pins: PinState,
}

impl BPFState {
    // Prints differences between self and other
    pub fn diff(&self, other: &BPFState) {
        // pid
        if self.pid != other.pid {
            println!("self pid: {} other pid: {}", self.pid, other.pid);
        }
        // maps, yes it's ugly, but it really helps for debugging
        for (name, data) in &self.maps {
            match other.maps.get(name) {
                None => println!("other did not contain map: {name}"),
                Some(other_data) => {
                    if data != other_data {
                        println!("map '{name}' is different.")
                    }
                    for (k, v) in &data.data {
                        match other_data.data.get(k) {
                            None => {
                                println!("other does not have\nkey: {k:?}\nvalue:{v:?}")
                            }
                            Some(other_v) => {
                                if v != other_v {
                                    println!(
                                        "different values for key:\n{k:?}\nself: {v:?}\nother: {other_v:?}"
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
        // pins
        if self.pins.dir != other.pins.dir {
            println!(
                "pin dir does not match: self {}, other: {}",
                self.pins.dir, other.pins.dir
            )
        }
        for (name, data) in &self.pins.pins {
            match other.pins.pins.get(name) {
                None => println!("other does not have pin: {name}"),
                Some(other_data) => {
                    if data != other_data {
                        println!(
                            "pin data does not match for pin {name}\nself: {data}\nother: {other_data}"
                        )
                    }
                }
            }
        }
    }
}
