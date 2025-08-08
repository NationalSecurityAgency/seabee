// SPDX-License-Identifier: Apache-2.0
use std::mem::MaybeUninit;
use std::str;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapHandle, UprobeOpts};
use zerocopy::FromBytes;

use bpf::tests::write_user::*;

fn main() -> Result<()> {
    // load ebpf skel
    let skel_builder = WriteUserSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let load_result = open_skel.load();
    if load_result.is_err() {
        // fail on error
        panic!();
    }
    let mut skel = load_result?;

    // check if load succees

    // Taken from libbpf_rs tests: https://github.com/libbpf/libbpf-rs/blob/master/libbpf-rs/tests/test.rs
    // Attach program with opts
    let prog = bpf::common::get_prog("bpf_write_user", &mut skel)?;

    let pid = -1;
    let exe_path = std::env::current_exe()?;
    let target_folder = exe_path
        .parent()
        .context("Expected to be running inside of the target folder")?;
    let binary_path = target_folder.join("bpf_write_user");
    println!("{binary_path:?}");
    let func_offset = 0;
    let opts = UprobeOpts {
        func_name: "uprobe_target_string".to_string(),
        ..Default::default()
    };
    let _link = prog
        .attach_uprobe_with_opts(pid, binary_path, func_offset, opts)
        .expect("Failed to attach prog");

    // trigger uprobe and check result
    //ascii: "Hello World!"
    let hello: [u8; 12] = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];
    let map = bpf::common::get_map("ringbuf", &skel)?;
    let action = || {
        uprobe_target_string(&hello);
    };
    let result = with_ringbuffer(map, action);
    assert_eq!(result, 1);

    Ok(())
}

#[inline(never)]
#[no_mangle]
fn uprobe_target_string(s: &[u8]) {
    let buf = str::from_utf8(s);
    println!("data= `{buf:?}`");
}

// Taken from https://github.com/libbpf/libbpf-rs/blob/master/libbpf-rs/tests/test.rs
fn with_ringbuffer<F>(map: MapHandle, action: F) -> i32
where
    F: FnOnce(),
{
    let mut value = 0i32;
    {
        let callback = |data: &[u8]| {
            value = i32::read_from_bytes(data).expect("Wrong size");
            0
        };

        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder.add(&map, callback).expect("Failed to add ringbuf");
        let ringbuffer = builder.build().expect("Failed to build");

        action();
        ringbuffer.consume().expect("Failed to consume ringbuf");
    }

    value
}
