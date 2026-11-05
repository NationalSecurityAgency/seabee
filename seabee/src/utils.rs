// SPDX-License-Identifier: Apache-2.0
use std::{
    fs::{self, File},
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anyhow::{anyhow, Result};
use nix::sys::signal::Signal;
use tracing::{error, trace};

use crate::constants;

/// Ensure the system has all requirements for running ebpf security
pub fn verify_requirements() -> Result<()> {
    ensure_root()?;
    verify_bpf_lsm_enabled()?;
    verify_seabee_unloaded()?;
    Ok(())
}

fn verify_bpf_lsm_enabled() -> Result<()> {
    let lsm_string = std::fs::read_to_string("/sys/kernel/security/lsm")?;
    if !lsm_string.contains("bpf") {
        Err(anyhow!("BPF LSM is not enabled!\nTry adding \"bpf\" to \"lsm=\" on the kernel command line.\nAlso confirm your kernel config uses CONFIG_BPF_LSM."))
    } else {
        Ok(())
    }
}

/// Check if the process is running with uid 0
pub fn ensure_root() -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        Err(anyhow!("You must run as root!"))
    } else {
        Ok(())
    }
}

/// Check that seabee programs have been unloaded
pub fn verify_seabee_unloaded() -> Result<()> {
    // after the SeaBee pins are removed, the kernel takes time to clean up the programs
    // we will check if the programs have been removed by creating a file in /etc/seabee
    // which should be blocked by an existing version of seabee

    let max_wait = 5;
    let mut waited = 0;
    for _ in 0..max_wait {
        if fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(constants::CONFIG_PATH)
            .is_ok()
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        waited += 1;
    }

    if waited >= max_wait {
        return Err(anyhow!(
            "failed 'verify_seabee_unloaded' check. Lacking permissions to edit files in {}",
            constants::SEABEE_DIR
        ));
    }

    Ok(())
}

/// Error if file does not have extensions in list of expected_ext
pub fn verify_file_has_ext(file: &Path, expected_ext: Vec<&str>) -> Result<()> {
    if let Some(file_ext) = file.extension() {
        for ext in &expected_ext {
            if file_ext == *ext {
                return Ok(());
            }
        }
    }
    Err(anyhow!(
        "file {} did not have an expected extension: {:?}",
        file.display(),
        expected_ext
    ))
}

pub fn file_to_bytes(file: &dyn AsRef<Path>) -> Result<Vec<u8>> {
    let mut file_bytes = Vec::new();
    let mut open_file = File::open(file)
        .map_err(|e| anyhow!("Failed to open file {:?}\n{e}", file.as_ref().display()))?;
    open_file
        .read_to_end(&mut file_bytes)
        .map_err(|e| anyhow!("failed to read file {}\n{e}", file.as_ref().display()))?;
    Ok(file_bytes)
}

pub fn str_to_abs_path_str(path: &str) -> Result<String> {
    match std::path::absolute(path)?.to_str() {
        Some(abs_path) => Ok(abs_path.to_owned()),
        None => Err(anyhow!("failed to convert '{path}' to String")),
    }
}

pub fn str_to_abs_pathbuf(path: &str) -> Result<PathBuf> {
    Ok(std::path::absolute(path)?)
}

/// Converts a path to a u8 vector with a requested max size
pub fn str_to_bytes(string: &str, max_size: usize) -> Result<Vec<u8>> {
    let mut bpf_c_path = vec![0; max_size];
    fill_buff_with_str(&mut bpf_c_path, max_size, string)?;

    Ok(bpf_c_path)
}

pub fn fill_buff_with_str(buf: &mut [u8], buf_size: usize, string: &str) -> Result<()> {
    // string.len() does not include a null terminator, hence >=
    if string.len() >= buf_size {
        return Err(anyhow!(
            "fill buf_with_str: string '{string}' is longer than {buf_size} bytes"
        ));
    }

    buf[..string.len()].clone_from_slice(string.as_bytes());

    Ok(())
}

/// Generates a [mask](https://en.wikipedia.org/wiki/Mask_(computing))
/// of allowed signals
pub const fn generate_sigmask(sigint: bool) -> u64 {
    let mut sigmask: u64 = 0;
    // These signals are those that do not terminate a process by default
    sigmask |= 1 << (Signal::SIGCHLD as u64 - 1);
    sigmask |= 1 << (Signal::SIGCONT as u64 - 1);
    sigmask |= 1 << (Signal::SIGURG as u64 - 1);
    sigmask |= 1 << (Signal::SIGWINCH as u64 - 1);

    if sigint {
        sigmask |= 1 << (Signal::SIGINT as u64 - 1);
    }
    sigmask
}

pub fn create_dir_if_not_exists(dir: &str) -> Result<()> {
    if let Err(e) = fs::create_dir_all(dir) {
        if e.kind() != ErrorKind::AlreadyExists {
            return Err(anyhow!("failed to create dir '{}'\n{}", dir, e));
        }
    }
    Ok(())
}

/// try to open a file for reading, but create the file if it does not exist
///
/// Why open or create for all files we protect?
/// 1. if file exists, protect it
/// 2. if file does not exist,create it to prevent an adversary from creating it
/// 3. if file exists, we should not delete it when the program exits
/// 4. if file does not exist, there is no harm in not deleting it
pub fn open_or_create(path: &str) -> Result<()> {
    trace!("try open {path}");
    // try open file
    match File::open(path) {
        Ok(_) => Ok(()),
        // try to create file if it doesn't exist
        Err(e) => match e.kind() {
            ErrorKind::NotFound => {
                if let Err(e) = File::create(path) {
                    error!("open_or_create: create failed for {path}");
                    return Err(e.into());
                };
                if let Err(e) = File::open(path) {
                    error!("open_or_create: create failed for {path}");
                    return Err(e.into());
                };
                Ok(())
            }
            _ => {
                error!("open_or_create: File::open failed for {path}");
                Err(e.into())
            }
        },
    }
}

pub fn remove_if_exists(path: &Path) -> Result<()> {
    let result = if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    if let Err(e) = result {
        match e.kind() {
            ErrorKind::NotFound => return Ok(()),
            _ => return Err(anyhow!("Failed to remove {}\n{e}", path.display())),
        }
    };

    Ok(())
}

/// Global OnceLock to hold the machine-id string.
pub static MACHINE_ID: OnceLock<String> = OnceLock::new();

/// Initialize MACHINE_ID from `/etc/machine-id` if it isn't already set.
pub fn init_machine_id() -> Result<()> {
    // Error on already assigned
    if MACHINE_ID.get().is_some() {
        return Ok(());
    }

    // Read file
    let contents = fs::read_to_string("/etc/machine-id")?;
    let trimmed = contents.trim().to_owned();

    // Try to set the OnceLock
    MACHINE_ID.set(trimmed).map_err(|e| anyhow!("{e}"))?;
    Ok(())
}

/// Traverse all files and directories under `root`, calling `f` on each entry.
pub fn walk_with<F>(root: &Path, mut f: F) -> Result<()>
where
    F: FnMut(&walkdir::DirEntry) -> Result<()>,
{
    for entry in walkdir::WalkDir::new(root) {
        let entry = entry.map_err(|e| anyhow!("walk_wirk DirEntry error: {e}"))?;
        f(&entry).map_err(|e| anyhow!("walk_with function error: {e}"))?;
    }
    Ok(())
}

// The following test cases are ai generated
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::os::unix::fs as unix_fs; // for symlink on Unix
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    // Test that walk_with visits all entries including root, dirs, files, and others.
    #[test]
    fn test_walk_visits_all_entries() -> Result<()> {
        let dir = tempdir()?;
        let root = dir.path();

        // Create a subdirectory
        let subdir = root.join("sub");
        fs::create_dir(&subdir)?;

        // Create files
        let file1 = root.join("file1.txt");
        let file2 = subdir.join("file2.txt");
        File::create(&file1)?;
        File::create(&file2)?;

        // Create a symlink (non-file/dir entry, but still should be visited)
        let symlink_path = root.join("symlink");
        unix_fs::symlink(&file1, &symlink_path)?;

        let mut visited = Vec::new();
        walk_with(root, |entry| {
            visited.push(entry.path().strip_prefix(root).unwrap().to_path_buf());
            Ok(())
        })?;

        // Expected: root itself, subdir, file1, file2, symlink
        assert!(visited.contains(&Path::new("").to_path_buf())); // root
        assert!(visited.contains(&Path::new("sub").to_path_buf()));
        assert!(visited.contains(&Path::new("file1.txt").to_path_buf()));
        assert!(visited.contains(&Path::new("sub/file2.txt").to_path_buf()));
        assert!(visited.contains(&Path::new("symlink").to_path_buf()));

        Ok(())
    }

    // Test that walk_with does not follow symlinks.
    #[test]
    fn test_walk_does_not_follow_symlinks() -> Result<()> {
        let dir = tempdir()?;
        let root = dir.path();

        // Create nested directory
        let subdir = root.join("sub");
        fs::create_dir(&subdir)?;

        // Symlink pointing back to root (would cause infinite recursion if followed)
        let symlink_path = subdir.join("loop");
        unix_fs::symlink(root, &symlink_path)?;

        let mut visited = Vec::new();
        walk_with(root, |entry| {
            visited.push(entry.path().to_path_buf());
            Ok(())
        })?;

        // Ensure symlink itself is seen, but traversal doesn’t loop infinitely
        assert!(visited.contains(&symlink_path));
        // Should only visit root, sub, and loop
        assert!(visited.len() == 3);

        Ok(())
    }

    // Test that walk_with works on deeply nested directories (5+ levels).
    #[test]
    fn test_walk_deeply_nested_directories() -> Result<()> {
        let dir = tempdir()?;
        let root = dir.path();

        // Create nested structure: root/a/b/c/d/e/file.txt
        let mut current = root.to_path_buf();
        for name in ["a", "b", "c", "d", "e"] {
            current.push(name);
            fs::create_dir(&current)?;
        }
        let file_path = current.join("file.txt");
        File::create(&file_path)?;

        let mut visited = Vec::new();
        walk_with(root, |entry| {
            visited.push(entry.path().strip_prefix(root).unwrap().to_path_buf());
            Ok(())
        })?;

        // Check that all layers are present
        for prefix in [
            Path::new(""),
            Path::new("a"),
            Path::new("a/b"),
            Path::new("a/b/c"),
            Path::new("a/b/c/d"),
            Path::new("a/b/c/d/e"),
            Path::new("a/b/c/d/e/file.txt"),
        ] {
            assert!(
                visited.contains(&prefix.to_path_buf()),
                "Missing {prefix:?}",
            );
        }

        Ok(())
    }

    // Negative test: broken symlink
    #[test]
    fn test_walk_with_broken_symlink() -> Result<()> {
        let dir = tempdir()?;
        let root = dir.path();

        // Create a symlink to a non-existent target
        let broken_symlink = root.join("broken");
        unix_fs::symlink("/does/not/exist", &broken_symlink)?;

        let mut visited = Vec::new();
        let result = walk_with(root, |entry| {
            visited.push(entry.path().to_path_buf());
            Ok(())
        });

        // The traversal itself should still succeed: walkdir skips broken symlinks.
        assert!(result.is_ok());
        assert!(visited.contains(&broken_symlink));

        Ok(())
    }

    // Negative test: unreadable directory
    #[test]
    fn test_walk_with_unreadable_directory() -> Result<()> {
        let dir = tempdir()?;
        let root = dir.path();

        // Create an unreadable subdirectory
        let secret = root.join("secret");
        fs::create_dir(&secret)?;
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o000))?;

        // Try walking
        let result = walk_with(root, |_entry| Ok(()));

        // Should fail with a permission denied error
        assert!(result.is_err());
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("Permission denied"),
            "Expected permission denied, got {err_str}",
        );

        // Restore perms so tempdir can clean up
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o755))?;

        Ok(())
    }

    // Test: root is a single file, not a directory
    #[test]
    fn test_walk_with_file_as_root() -> Result<()> {
        let dir = tempdir()?;
        let file_path = dir.path().join("lonely.txt");
        File::create(&file_path)?;

        let mut visited = Vec::new();
        walk_with(&file_path, |entry| {
            visited.push(entry.path().to_path_buf());
            Ok(())
        })?;

        // Expect exactly one entry: the file itself
        assert_eq!(visited.len(), 1);
        assert_eq!(visited[0], file_path);

        Ok(())
    }

    // Test: root path does not exist
    #[test]
    fn test_walk_with_nonexistent_root() {
        // Create a clearly non-existent path
        let fake_path = PathBuf::from("/this/does/not/exist/123456");

        let result = walk_with(&fake_path, |_entry| Ok(()));

        // Should error out
        assert!(result.is_err(), "Expected error for nonexistent root");
        let err_str = format!("{:?}", result.unwrap_err());
        assert!(
            err_str.contains("No such file or directory"),
            "Unexpected error: {err_str}"
        );
    }
}
