// SPDX-License-Identifier: Apache-2.0
use std::{fs, io::ErrorKind, os::unix::net::UnixListener, path::PathBuf};

use anyhow::{anyhow, Result};
use tracing::{debug, error, info};

use crate::{
    constants::{self, POLICY_DIR, SEABEE_ROOT_KEY_PATH},
    policy::fs_api::{self, FileType},
    SeaBeeMapHandles,
};

impl super::SeaBeePolicy {
    pub fn boot_time_key_load(&mut self) -> Result<()> {
        debug!("Start boot time key load");

        // add keys to SeaBee one at a time
        for key in fs_api::import_keys()? {
            // root key will have already been loaded
            if key.path == PathBuf::from(SEABEE_ROOT_KEY_PATH) {
                continue;
            }

            // load other keys
            debug!("try load key: {:?}, {}", key.path, key.sig_digest);
            let sig_path = fs_api::get_sig_path(&key.path, &FileType::Key)?;
            let result = if sig_path.exists() {
                self.add_key(&key.path, &Some(sig_path), &Some(key.sig_digest), false)
            } else {
                self.add_key(&key.path, &None, &None, false)
            };

            // report result
            match result {
                Ok(_) => info!("Added key from: {}", key.path.display()),
                Err(e) => error!("Failed to add key from {}\n{e}", key.path.display()),
            }
        }

        Ok(())
    }

    /// overwrites all existing policies with policy from policy directory
    /// does not modify kernel structures
    pub fn boot_time_policy_load(&mut self, maps: &SeaBeeMapHandles) -> Result<()> {
        debug!("Start boot time policy load");
        // Get policies from policy directory
        for entry in fs::read_dir(POLICY_DIR)? {
            // get paths
            let pol_path = entry?.path();
            let sig_path = fs_api::get_sig_path(&pol_path, &FileType::Policy)?;
            let sig_path_opt = if sig_path.exists() {
                Some(sig_path)
            } else {
                None
            };

            // get policy
            let mut new_policy = match fs_api::generate_policy_from_yaml(&pol_path) {
                Ok(policy) => policy,
                Err(e) => {
                    error!(
                        "failed to get policy from {}:\n{e}",
                        pol_path.to_string_lossy(),
                    );
                    continue;
                }
            };

            // add policy
            if let Err(e) = self.add_new_policy(&mut new_policy, &pol_path, &sig_path_opt, maps) {
                error!(
                    "failed to add policy from {}:\n{e}",
                    pol_path.to_string_lossy(),
                );
                continue;
            };
            info!("Boot-time policy added: {}", new_policy.display_short());
        }

        Ok(())
    }

    // Sets up socket listening for runtime policy updates
    pub fn init_listener(&mut self) -> Result<()> {
        let listener = match UnixListener::bind(constants::SOCKET_PATH) {
            Ok(l) => l,
            Err(e) => {
                return match e.kind() {
                    ErrorKind::PermissionDenied => Err(anyhow!(
                    "SeaBeePolicy listener::bind() deniend. Possibly failed to label socket.\n{e}",
                )),
                    _ => Err(anyhow!("SeaBeePolicy listener::bind() failed: {e}")),
                }
            }
        };
        listener.set_nonblocking(true)?;
        self.listener = Some(listener);

        Ok(())
    }
}
