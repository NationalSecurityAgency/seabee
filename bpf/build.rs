// SPDX-License-Identifier: Apache-2.0
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use libbpf_cargo::SkeletonBuilder;
use procfs::KernelVersion;

/// Tells Cargo to rerun the build if the supplied file has changed
fn track_file(header: &str) {
    println!("cargo:rerun-if-changed={header}");
}

/// Converts a BPF source code path to a skeleton path for [libbpf_rs]
fn get_skel_path(src_file: &Path, version: Option<&KernelVersion>) -> String {
    if let Some(bpf) = src_file.file_stem() {
        if let Some(stem) = Path::new(bpf).file_stem() {
            let mut skel_path = String::new();
            skel_path.push_str(&stem.to_string_lossy());
            // if a kernel version is specified, add that at the end of the name
            if let Some(version) = version {
                skel_path.push_str(&format!(
                    "_{}_{}_{}",
                    version.major, version.minor, version.patch
                ));
            }
            skel_path.push_str(".skel.rs");
            return skel_path;
        }
    }
    panic!(
        "{} was not of the expected format .bpf.c",
        src_file.as_os_str().to_string_lossy()
    );
}

/// Converts [KernelVersion] to BPF_CODE_VERSION to be compared against the
/// `KERNEL_VERSION` macro for conditional compilation
pub fn kernel_version_to_bpf_code_version(version: &KernelVersion) -> u32 {
    ((version.major as u32) << 16)
        + ((version.minor as u32) << 8)
        + std::cmp::max(version.patch as u32, 255)
}

/// Uses [libbpf_cargo::SkeletonBuilder] to compile BPF source code to a skeleton
fn compile_bpf_obj(
    src_file: &PathBuf,
    out_path: &Path,
    versions: Option<&[KernelVersion]>,
) -> Result<()> {
    let mut clang_args: Vec<String> = vec![
        "-Iinclude".to_string(),
        format!("-I{}", out_path.to_string_lossy()),
    ];
    let mut skel_build = SkeletonBuilder::new();
    skel_build.source(src_file);
    // if multiple versions are specified
    if let Some(versions) = versions {
        // compile the default case (every version before the first specified)
        clang_args.push("-DBPF_CODE_VERSION=0".to_owned());
        skel_build
            .clang_args(&clang_args)
            .build_and_generate(out_path.join(get_skel_path(src_file, None)))?;
        clang_args.pop();
        // compile each version of the skeleton separately
        for version in versions {
            clang_args.push(format!(
                "-DBPF_CODE_VERSION={}",
                kernel_version_to_bpf_code_version(version)
            ));
            skel_build
                .clang_args(&clang_args)
                .build_and_generate(out_path.join(get_skel_path(src_file, Some(version))))?;
            clang_args.pop();
        }
    }
    // otherwise, assume all versions are supported with the same skeleton
    else {
        skel_build
            .clang_args(&clang_args)
            .build_and_generate(out_path.join(get_skel_path(src_file, None)))?;
    }
    Ok(())
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
            .context(format!("Header path has no stem: {hdr_file:?}"))?,
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
    use std::fs::OpenOptions;
    use std::io::Write;

    let dir = target_dir.join("bpf");
    fs::create_dir_all(&dir)?;
    for (filename, contents) in libbpf_rs::libbpf_sys::API_HEADERS.iter() {
        let path = dir.as_path().join(filename);
        let mut file = OpenOptions::new()
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
fn build(
    out_path: &Path,
    base_path: &str,
    ignore_files: Vec<&str>,
    versions: Option<&[KernelVersion]>,
) -> Result<()> {
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
            compile_bpf_obj(&path, out_path, versions)?;
        }
        if path_str.ends_with(".h") {
            generate_header_bindings(&path, out_path)?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let out_path = PathBuf::from(env::var_os("OUT_DIR").context("OUT_DIR must be set")?);
    extract_libbpf_headers_to_disk(&out_path)?;
    // Build common
    build(
        &out_path,
        "include",
        vec![
            "logging.h",
            "vmlinux.h",
            "vmlinux_6_0_18.h",
            "vmlinux_6_11_4.h",
            "seabee_maps.h",
            "seabee_utils.h",
        ],
        None,
    )?;
    // Build bpf code
    build(
        &out_path,
        "src/seabee",
        vec!["seabee_log.h"],
        Some(&[KernelVersion::new(6, 1, 0), KernelVersion::new(6, 9, 0)]),
    )?;
    build(&out_path, "src/kernel_api", vec![], None)?;
    build(&out_path, "src/tests", vec![], None)?;
    Ok(())
}
