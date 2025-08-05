// SPDX-License-Identifier: Apache-2.0
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{env, fs};

use anyhow::{anyhow, Context, Result};
use libbpf_cargo::SkeletonBuilder;

const VMLINUX_FEATURES: [&str; 2] = ["bpf_map_create", "bpf_map_alloc_security"];

/// Tells Cargo to rerun the build if the supplied file has changed
fn track_file(header: &str) {
    println!("cargo:rerun-if-changed={header}");
}

/// Converts a BPF source code path to a skeleton path for [libbpf_rs]
fn get_skel_path(src_file: &Path) -> PathBuf {
    if let Some(bpf) = src_file.file_stem() {
        if let Some(stem) = Path::new(bpf).file_stem() {
            let mut skel = PathBuf::new();
            skel.push(stem);
            skel.set_extension("skel.rs");
            return skel;
        }
    }
    panic!(
        "{} was not of the expected format .bpf.c",
        src_file.as_os_str().to_string_lossy()
    );
}

/// Uses [libbpf_cargo::SkeletonBuilder] to compile BPF source code to a skeleton
fn compile_bpf_obj(src_file: &PathBuf, out_path: &Path) -> Result<PathBuf> {
    let bpf_skel_path = out_path.join(get_skel_path(src_file));
    SkeletonBuilder::new()
        .source(src_file)
        .clang_args([&format!("-I{}", out_path.to_string_lossy()), "-Iinclude"])
        .build_and_generate(&bpf_skel_path)?;
    Ok(bpf_skel_path)
}

#[derive(Debug)]
struct BindgenCallbacks {}

impl bindgen::callbacks::ParseCallbacks for BindgenCallbacks {
    fn add_derives(&self, info: &bindgen::callbacks::DeriveInfo<'_>) -> Vec<String> {
        match info.kind {
            // provides `to_string()` and From/Into trait definitions for enums
            bindgen::callbacks::TypeKind::Enum => vec![
                "serde::Serialize".to_string(),
                "strum_macros::AsRefStr".to_string(),
                "strum_macros::FromRepr".to_string(),
                "strum_macros::Display".to_string(),
            ],
            // provides safe transmute methods for C structs to Rust structs
            bindgen::callbacks::TypeKind::Struct => {
                if info.name == "c_policy_config" {
                    vec![
                        "zerocopy_derive::Immutable".to_string(),
                        "zerocopy_derive::IntoBytes".to_string(),
                    ]
                } else {
                    vec![
                        "zerocopy_derive::FromBytes".to_string(),
                        "zerocopy_derive::Immutable".to_string(),
                        "zerocopy_derive::KnownLayout".to_string(),
                    ]
                }
            }
            _ => vec![],
        }
    }

    /// Converts Doxygen comments in header files to valid Rustdoc comments
    fn process_comment(&self, comment: &str) -> Option<String> {
        Some(doxygen_rs::transform(comment))
    }
}

/// Uses [bindgen] to generate Rust definitions for C headers used in BPF code
fn generate_header_bindings(hdr_file: &Path, out_path: &Path) -> Result<PathBuf> {
    let mut out_file = out_path.join(
        hdr_file
            .file_stem()
            .context(format!("Header path has no stem: {:?}", hdr_file))?,
    );
    out_file.set_extension("rs");
    let hdr_file_str = hdr_file.to_string_lossy();
    let bindings = bindgen::builder()
        .header(hdr_file_str.clone())
        .clang_arg("-Iinclude")
        .prepend_enum_name(false)
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .parse_callbacks(Box::new(BindgenCallbacks {}))
        .generate()?;
    bindings.write_to_file(&out_file)?;
    Ok(out_file)
}

/// Headers from the statically compiled libbpf to be used for BPF code compilation
///
/// Copied from https://github.com/libbpf/libbpf-rs/blob/aacaec1b7dfaa4bf9112d2f4168d77dfceee499f/libbpf-cargo/src/build.rs#L55
fn extract_libbpf_headers_to_disk(target_dir: &Path) -> Result<Option<PathBuf>> {
    let dir = target_dir.join("bpf");
    fs::create_dir_all(&dir)?;
    for (filename, contents) in libbpf_rs::libbpf_sys::API_HEADERS.iter() {
        let path = dir.as_path().join(filename);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(contents.as_bytes())?;
    }

    Ok(Some(dir))
}

/// Runs Clang and bindgen to search for and build all .bpf.c and .h files in the folder
///
/// You can pass a vector of filenames to explicitly ignore if they are known to cause
/// problems for either Clang or bindgen (e.g. "vmlinux.h")
fn build(out_path: &Path, base_path: &str, ignore_files: Vec<&str>) -> Result<()> {
    for path in fs::read_dir(base_path)?
        .filter_map(|r| r.ok())
        .map(|r| r.path())
    {
        let path_str = path.to_string_lossy();
        track_file(&path_str);
        if ignore_files
            .iter()
            .any(|e| Path::new(base_path).join(*e) == path)
        {
            continue;
        }
        if path_str.ends_with(".bpf.c") {
            compile_bpf_obj(&path, out_path)?;
        }
        if path_str.ends_with(".h") {
            generate_header_bindings(&path, out_path)?;
        }
    }
    Ok(())
}

// Creates vmlinux (truncates if exists)
fn generate_vmlinux(out_path: &Path) -> Result<PathBuf> {
    let vmlinux_path = out_path.join("bpf/vmlinux.h");
    let vmlinux_file = fs::File::create(&vmlinux_path)?;
    // bpftool is installed in the update_test_dependencies.sh which
    // is run as part of the update_root_dependencies.sh
    let status = Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .stdout(Stdio::from(vmlinux_file))
        .status()?;
    if !status.success() {
        return Err(anyhow!(
            "failed to generate vmlinux using bpftool: {}",
            status
        ));
    }

    Ok(vmlinux_path)
}

fn detect_vmlinux_features(vmlinux: &PathBuf) -> Result<HashSet<String>> {
    // detect features
    let file = fs::File::open(vmlinux)?;
    let reader = BufReader::new(file);
    let mut found = HashSet::new();
    for line in reader.lines() {
        let line = line?;
        for feat in VMLINUX_FEATURES {
            if line.contains(feat) {
                found.insert(feat.to_string());
            }
        }
    }

    // validate features
    if found.contains(VMLINUX_FEATURES[0]) && found.contains(VMLINUX_FEATURES[1]) {
        return Err(anyhow!(
            "Conflicting function definitions: '{}' and '{}'",
            VMLINUX_FEATURES[0],
            VMLINUX_FEATURES[1]
        ));
    } else if !found.contains(VMLINUX_FEATURES[0]) && !found.contains(VMLINUX_FEATURES[1]) {
        return Err(anyhow!(
            "Kernel no supported. No function definition found for '{}' or '{}'",
            VMLINUX_FEATURES[0],
            VMLINUX_FEATURES[1]
        ));
    }

    Ok(found)
}

fn export_features_to_header(features: HashSet<String>, out_path: &Path) -> Result<()> {
    let vmlinux_features_path = out_path.join("bpf/vmlinux_features.h");
    let mut f = fs::File::create(vmlinux_features_path)?;

    writeln!(f, "// Auto-generated header from build.rs")?;

    for flag in features {
        let macro_name = flag.to_uppercase();
        writeln!(f, "#define HAS_{}", macro_name)?;
    }

    Ok(())
}

fn main() -> Result<()> {
    let out_path = PathBuf::from(env::var_os("OUT_DIR").context("OUT_DIR must be set")?);
    extract_libbpf_headers_to_disk(&out_path)?;
    // Create vmlinux and do feature detection based on it
    let vmlinux =
        generate_vmlinux(&out_path).map_err(|e| anyhow!("failed to generate vmlinux.h: {e}"))?;
    let features = detect_vmlinux_features(&vmlinux)?;
    export_features_to_header(features, &out_path)?;

    // Build common
    build(
        &out_path,
        "include",
        vec!["logging.h", "seabee_maps.h", "seabee_utils.h"],
    )?;
    // Build bpf code
    build(&out_path, "src/seabee", vec!["seabee_log.h"])?;
    build(&out_path, "src/kernel_api", vec![])?;
    build(&out_path, "src/tests", vec![])?;
    Ok(())
}
