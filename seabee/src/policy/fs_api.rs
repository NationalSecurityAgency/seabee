// SPDX-License-Identifier: Apache-2.0
use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

use super::policy_file::{FromYamlPath, PolicyFile};
use crate::{
    constants::{self, KEYLIST_PATH},
    crypto::{SeaBeeDigest, SeaBeeKey},
    utils,
};

/// Used to distinguish between keys and policies
#[derive(Debug)]
pub enum FileType {
    Key,
    Policy,
}

/// Minimal information about a key saved to the filesystem
#[derive(Serialize, Deserialize, Debug)]
pub struct SavedKey {
    pub path: PathBuf,
    pub sig_digest: SeaBeeDigest,
}

impl From<&SeaBeeKey> for crate::policy::fs_api::SavedKey {
    fn from(value: &SeaBeeKey) -> Self {
        Self {
            path: value.seabee_path.clone(),
            sig_digest: value.sig_digest.clone(),
        }
    }
}

impl super::SeaBeePolicy {
    pub fn export_keys(&self) -> Result<()> {
        let mut keylist: Vec<SavedKey> = Vec::new();
        for key in self.verification_keys.values() {
            if key.id != super::ROOT_KEY_ID {
                keylist.push(key.into());
            }
        }

        let yaml = serde_yaml::to_string(&keylist)?;
        if let Err(e) = fs::write(KEYLIST_PATH, yaml) {
            return Err(anyhow!("Error writing keylist to '{KEYLIST_PATH}'\n{e}"));
        }

        Ok(())
    }
}

pub fn import_keys() -> Result<Vec<SavedKey>> {
    match fs::read_to_string(KEYLIST_PATH) {
        Ok(yaml) => Ok(serde_yaml::from_str(&yaml)?),
        Err(e) => {
            info!("Warning: No keys added. Error reading from keylist: '{KEYLIST_PATH}'\n{e}");
            Ok(Vec::new())
        }
    }
}

/// Generates a [PolicyFile] from a yaml file. Does not do signature validation
pub fn generate_policy_from_yaml(yaml_path: &Path) -> Result<PolicyFile> {
    // get policy
    let mut new_policy = PolicyFile::from_path(yaml_path)?;

    // validate files
    for file in &new_policy.files {
        if !Path::new(file).exists() {
            return Err(anyhow!("File {} does not exist.\nOptions are: create the file and try again, protect the directory in which this file resides, or use 'seabeectl update' to change the policy and add the file after it has been created.", file.display()));
        }
    }

    // set filesystem path
    new_policy.seabee_path = get_seabee_policy_path(&new_policy.name)?;

    Ok(new_policy)
}

// Remove a policy or key file from disk and the corresponding signature
pub fn delete_seabee_file_and_sig(file_path: &PathBuf, file_type: &FileType) -> Result<()> {
    // remove file
    if let Err(e) = fs::remove_file(file_path) {
        return Err(anyhow!(
            "failed to {file_type:?} file at '{}'\n{e}",
            file_path.display()
        ));
    }

    // remove signature
    let sig_path = get_sig_path(file_path, file_type)?;
    if let Err(e) = utils::remove_if_exists(&sig_path) {
        return Err(anyhow!(
            "failed to remove {file_type:?} file signature at '{}'\n{e}",
            sig_path.display()
        ));
    };
    Ok(())
}

/// Save a policy or key to disk and its signature
/// If signature is none, then no signature is saved to disk
pub fn save_seabee_file_and_sig(
    src_path: &PathBuf,
    dest_path: &PathBuf,
    sig_path: &Option<PathBuf>,
    file_type: &FileType,
) -> Result<()> {
    // get paths
    let new_sig_path = get_sig_path(dest_path, file_type)?;

    // save file if it doesn't already exist
    // make sure that source and dest for copy are different
    if dest_path != src_path {
        if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Err(e) = fs::copy(src_path, dest_path) {
            return Err(anyhow!(
                "add_new_policy_from_yaml: failed to copy from {} to {}. Got error: {e}",
                src_path.display(),
                dest_path.display(),
            ));
        }
    }
    // save the signature if there is one
    // make sure that source and dest for copy are different
    if let Some(sig_path) = sig_path {
        if *sig_path != new_sig_path {
            if let Some(parent) = new_sig_path.parent() {
                fs::create_dir_all(parent)?;
            }
            if let Err(e) = fs::copy(sig_path, &new_sig_path) {
                return Err(anyhow!(
                    "add_new_policy_from_yaml: failed to copy from {} to {}. Got error: {e}",
                    sig_path.display(),
                    new_sig_path.display()
                ));
            }
        }
    }
    Ok(())
}

/// Return a path where the policy will be stored on disk.
///
/// * `policy_name` - the name of a SeaBee policy
fn get_seabee_policy_path(policy_name: &String) -> Result<PathBuf> {
    let mut path = Path::new(constants::POLICY_DIR).join(policy_name);
    if !path.set_extension("yaml") {
        return Err(anyhow!(
            "failed to set yaml extension on policy: {}",
            policy_name
        ));
    }
    Ok(path)
}

/// Return an unused path where the key will be stored on disk.
pub fn get_seabee_key_path() -> Result<PathBuf> {
    loop {
        let path = Path::new(constants::KEY_DIR).join(format!("{}.pem", uuid::Uuid::new_v4()));
        match fs::metadata(&path) {
            Ok(_) => continue,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(path),
            Err(error) => return Err(error.into()),
        }
    }
}

/// Gets the path to the signature file for a policy on disk
pub fn get_sig_path(file_path: &Path, file_type: &FileType) -> Result<PathBuf> {
    // This function should not be refactored into get_seabee_path() function because
    // boot time load requires deriving the signature path from the file path

    let dir = match file_type {
        FileType::Policy => constants::POL_SIGNATURE_DIR,
        FileType::Key => constants::KEY_SIGNATURE_DIR,
    };

    let mut sig_path = match file_path.file_name() {
        Some(name) => Path::new(dir).join(name),
        None => {
            return Err(anyhow!(
                "get_sig_path: invalid file name for path '{}'",
                file_path.display()
            ))
        }
    };
    sig_path.set_extension("sign");
    Ok(sig_path)
}
