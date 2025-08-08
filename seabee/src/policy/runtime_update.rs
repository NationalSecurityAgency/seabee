// SPDX-License-Identifier: Apache-2.0
use std::{
    fs,
    io::{BufRead, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
};

use anyhow::{anyhow, Context, Result};
use itertools::Itertools;
use tracing::{debug, error, info, trace};

use crate::{
    constants::{self, SEABEE_ROOT_KEY_PATH},
    crypto::{SeaBeeDigest, SeaBeeKey},
    kernel_api,
    seabeectl_lib::{KeyIdentifier, ObjIdentifier, SignedRequestInfo, SocketCommand},
    SeaBeeMapHandles,
};

use super::{
    fs_api::{self, FileType},
    policy_file::{PolicyFile, RemovePolicyYaml},
    ROOT_KEY_ID,
};

impl super::SeaBeePolicy {
    /// Execute a [PolicyCommand] from seabeectl
    ///
    /// Returns and error or text that will be written back to the seabeectl client.
    /// Many different possible errors based on the command.
    pub fn handle_cli_command(
        &mut self,
        cmd: SocketCommand,
        maps: &SeaBeeMapHandles,
    ) -> Result<String> {
        debug!("Got CLI Command: {cmd}");
        // prevents unecesaary cloning
        let info_string = format!("Completed CLI Command: {cmd}");
        // perform move of command here
        let output = match cmd {
            SocketCommand::List => self.list_policy(),
            SocketCommand::Show(policy) => self.show_policy(policy)?,
            SocketCommand::Update(request) => self.handle_update_command(request, maps)?,
            SocketCommand::Remove(request) => {
                self.remove_policy(request, maps)?;
                "Success".to_owned()
            }
            SocketCommand::ListKeys => self.list_keys(),
            SocketCommand::ShowKey(key) => self.show_key(key)?,
            SocketCommand::AddKey(request) => {
                self.add_key(&request.target_path, &request.sig_path, &request.digest)?
            }
            SocketCommand::RemoveKey(request) => self.remove_key(request)?,
        };
        info!("{}", info_string);
        Ok(output)
    }

    /// list all policies as a string
    fn list_policy(&self) -> String {
        let mut output = self.policies.values().join("\n");
        let policy_count = self.policies.values().len();
        if policy_count == 1 {
            output.push_str(&format!("Listed {policy_count} SeaBee Policy"));
        } else {
            output.push_str(&format!("Listed {policy_count} SeaBee Policies"));
        }
        output
    }

    /// Show a single policy as a string
    fn show_policy(&self, ident: ObjIdentifier) -> Result<String> {
        let policy = match ident {
            // Get Policy from a path (matches on name of policy at destination)
            ObjIdentifier::File { path } => match PolicyFile::from_path(&path) {
                Ok(policy_file) => self.policies.get(&policy_file.name).context(anyhow!(
                    "the policy at path '{}' did not match any existing policy",
                    path.display()
                ))?,
                Err(e) => {
                    return Err(anyhow!(
                        "failed to read policy file: '{}'. Error: {e}",
                        path.display()
                    ))
                }
            },
            // Get policy by id
            ObjIdentifier::Id { id } => self
                .policies
                .values()
                .find(|&policy| policy.id == id)
                .context(anyhow!("No policy found for id {id}"))?,

            // Get policy by name
            ObjIdentifier::Name { name } => self
                .policies
                .get(&name)
                .context(anyhow!("no policy found for name {name}"))?,
        };
        Ok(policy.to_string())
    }

    // Processes an update command from seabeectl
    fn handle_update_command(
        &mut self,
        request: SignedRequestInfo,
        maps: &SeaBeeMapHandles,
    ) -> Result<String> {
        // Get policy
        let mut new_policy = fs_api::generate_policy_from_yaml(&request.target_path)?;

        // Do policy update
        match self.policies.get(&new_policy.name) {
            // update
            Some(old_policy) => {
                self.update_policy(&mut new_policy, old_policy.key_id, &request, maps)?;
            }
            // add
            None => {
                self.add_new_policy(
                    &mut new_policy,
                    &request.target_path,
                    &request.sig_path,
                    maps,
                )?;
            }
        }

        // Save updated policy to disk
        if let Err(e) = fs_api::save_seabee_file_and_sig(
            &request.target_path,
            &new_policy.seabee_path,
            &request.sig_path,
            &FileType::Policy,
        ) {
            return Err(anyhow!("Policy update succeeded, but error occurred while updating files on disk.\nChanges will not persist after reboot. Issuing another successful policy update would resolve the issue.\n{e}"));
        }

        Ok(format!("Success!\n{new_policy}"))
    }

    /// add a new policy to SeaBee and to the kernel, but does not save to disk
    pub fn add_new_policy(
        &mut self,
        new_policy: &mut PolicyFile,
        pol_path: &PathBuf,
        sig_path: &Option<PathBuf>,
        maps: &SeaBeeMapHandles,
    ) -> Result<()> {
        // verify policy
        self.verify_new_policy(new_policy, pol_path, sig_path)?;

        // assign policy id
        new_policy.id = self.get_unused_policy_id()?;

        // add policy to kernel
        if let Err(e) = self.add_new_policy_to_kernel(maps, new_policy) {
            return Err(anyhow!(
                "failed to add new policy to kernel: {}\n{e}",
                new_policy.display_short()
            ));
        }

        // add policy to SeaBee
        self.policies
            .insert(new_policy.name.clone(), new_policy.clone());

        // debug
        debug!("add_new_policy: {}", new_policy.display_short());
        trace!("add_new_policy:\n{}", new_policy);

        Ok(())
    }

    /// Adds a [PolicyFile] to the kernel by updating the kernel policy map,
    /// labeling the policy scope, and labeling files for this policy
    fn add_new_policy_to_kernel(&self, maps: &SeaBeeMapHandles, policy: &PolicyFile) -> Result<()> {
        // add policy map
        kernel_api::update_kernel_policy_map(maps, policy.id, &policy.config)?;

        // label process scope
        for path in &policy.scope {
            kernel_api::add_path_to_scope(maps, path, policy.id)?;
        }

        // label files
        kernel_api::label_files_from_policy(policy, maps)?;

        debug!("pushed policy to kernel: {}", policy.display_short());
        Ok(())
    }

    /// Updates a policy by executing an [UpdateCommand].
    /// This updates the kernel structures, and the SeaBeePolicy internal map.
    /// This does not update the filesystem because that should be performed after update returns
    ///
    /// Errors
    /// - no matching policy was found
    /// - adding a file that is already protected or removing a file that is not protected
    /// - adding or removing a nonexistent file
    /// - failed to write updates to filesystem or to the kernel
    fn update_policy(
        &mut self,
        new_policy: &mut PolicyFile,
        key_id: Option<u32>,
        request: &SignedRequestInfo,
        maps: &SeaBeeMapHandles,
    ) -> Result<()> {
        // verify update
        self.verify_signature(&request.target_path, &request.sig_path, &None, key_id)?;

        // will not panic since existence was already checked
        let old_policy = self.policies.get(&new_policy.name).unwrap();

        // validate update
        if new_policy.version <= old_policy.version {
            return Err(anyhow!("Policy update requires incrementing version number. Here is the current policy:\n{}", old_policy));
        }
        if old_policy.scope != new_policy.scope {
            return Err(anyhow!("Not possible to change policy scope via an update. Instead, remove and replace policy.\nNew policy scope did not match old policy scope of: {}", old_policy.scope.iter().join(", ")));
        }

        // assign policy id, key id
        new_policy.id = old_policy.id;
        new_policy.key_id = old_policy.key_id;

        // update kernel policy map
        kernel_api::update_kernel_policy_map(maps, new_policy.id, &new_policy.config)?;

        // add files to kernel
        for file in new_policy.files.difference(&old_policy.files) {
            if let Err(e) = kernel_api::label_file_with_id(maps, file, new_policy.id) {
                return Err(anyhow!("Update policy command failed during update\n{e}\nSeaBee state corrupted. Recommended to restart SeaBee and restore correct state."));
            }
        }

        // remove files from kernel
        for file in old_policy.files.difference(&new_policy.files) {
            if let Err(e) = kernel_api::unlabel_file(maps, file) {
                return Err(anyhow!("Update policy command failed during update\n{e}\nSeaBee state corrupted. Recommended to restart SeaBee and restore correct state."));
            }
        }

        // update Seabee
        // this is only called when new_policy.name exists in self.policies inside of handle_update_command()
        // will not panic
        *self.policies.get_mut(&new_policy.name).unwrap() = new_policy.clone();

        Ok(())
    }

    /// Removes a policy from SeaBee, the SeaBee policy folder, and from the kerenl
    pub fn remove_policy(
        &mut self,
        request: SignedRequestInfo,
        maps: &SeaBeeMapHandles,
    ) -> Result<()> {
        // Get policy
        let yaml_path = &request.target_path;
        let sig_path = &request.sig_path;
        let input_policy = RemovePolicyYaml::from_path(yaml_path)?;
        let target_policy = self.policies.get(&input_policy.name).context(anyhow!(
            "No policy with name '{}' was found.",
            input_policy.name
        ))?;
        self.verify_signature(yaml_path, sig_path, &request.digest, target_policy.key_id)?;

        // check version number
        if target_policy.version != input_policy.version {
            return Err(anyhow!("Version did not match for policy named '{}'\nSeaBee version: {}, input version: {}", input_policy.name, target_policy.version, input_policy.version));
        }

        // Remove from fs
        fs_api::delete_seabee_file_and_sig(&target_policy.seabee_path, &FileType::Policy)?;
        // Remove from kernel
        if let Err(e) = kernel_api::remove_kernel_policy(maps, target_policy.id) {
            // try to restore file on filesystem and report error
            fs::write(
                &target_policy.seabee_path,
                serde_yaml::to_string(&target_policy)?,
            )?;
            return Err(anyhow!(
                "failed to remove policy id {} from kernel. Error: {e}",
                target_policy.id,
            ));
        }
        // Remove from seabee
        self.policies.remove(&target_policy.name.clone());
        Ok(())
    }

    fn list_keys(&self) -> String {
        let mut output = self.verification_keys.values().join("\n");
        output += &format!("\nListed {} Keys", self.verification_keys.len());
        output
    }

    fn show_key(&self, key_ident: KeyIdentifier) -> Result<String> {
        match key_ident {
            KeyIdentifier::File { ref path } => {
                let target_key = SeaBeeKey::new_key(path, 0)?;
                for key in self.verification_keys.values() {
                    if key.try_eq(&target_key)? {
                        return Ok(key.to_string());
                    }
                }
            }
            KeyIdentifier::Id { id } => {
                if let Some(key) = self.verification_keys.get(&id) {
                    return Ok(key.to_string());
                }
            }
        }
        Ok(format!("No key found for ident: '{}'", &key_ident))
    }

    pub fn add_key(
        &mut self,
        src_path: &PathBuf,
        sig_path: &Option<PathBuf>,
        sig_digest: &Option<SeaBeeDigest>,
    ) -> Result<String> {
        // Get Key
        if self.verify_keys {
            self.verify_signature(src_path, sig_path, sig_digest, Some(super::ROOT_KEY_ID))?;
        }
        let mut new_key = SeaBeeKey::new_key(src_path, self.get_next_key_id()?)?;
        new_key.seabee_path = fs_api::get_seabee_key_path(src_path)?;
        new_key.sig_path = fs_api::get_sig_path(&new_key.seabee_path, &FileType::Key)?;

        // Add key and sig to fs
        fs_api::save_seabee_file_and_sig(src_path, &new_key.seabee_path, sig_path, &FileType::Key)?;

        // add to seabee
        self.verification_keys.insert(new_key.id, new_key.clone());

        // Update keylist on filesystem
        if let Err(e) = self.export_keys() {
            // remove from seabee
            self.verification_keys.remove(&new_key.id);
            // remove from fs
            if let Err(fs_error) =
                fs_api::delete_seabee_file_and_sig(&new_key.seabee_path, &FileType::Key)
            {
                return Err(anyhow!("failed to export new keylist:\n{e}\nFailed to remove new key from filesystem:\n{fs_error}"));
            }
            // report error
            return Err(anyhow!("failed to export new keylist\n{e}"));
        }
        Ok(format!("Success!\n{new_key}"))
    }

    /// removes a key from the filesystem and from seabee.
    /// This does not revoke any other keys or policies signed by the target key.
    /// A reboot is needed to reverify all signatures on policies and keys
    /// You cannot revoke the root key.
    fn remove_key(&mut self, request: SignedRequestInfo) -> Result<String> {
        // Get target key
        let target_key = match self.get_key_by_path(&request.target_path)? {
            Some(key) => key,
            None => {
                return Err(anyhow!(
                    "No matching key found for {}",
                    request.target_path.display()
                ))
            }
        };
        if target_key.id == super::ROOT_KEY_ID {
            return Err(anyhow!("This is the root key and cannot be revoked. The root key is at '{}' and can only be changed while SeaBee is turned off.", SEABEE_ROOT_KEY_PATH));
        }

        // Verify request with either root key or target key
        let key_path = &request.target_path;
        let verify_key = self.verify_signature(
            key_path,
            &request.sig_path,
            &request.digest,
            Some(target_key.id),
        );
        let verify_root_key = self.verify_signature(
            key_path,
            &request.sig_path,
            &request.digest,
            Some(ROOT_KEY_ID),
        );
        if verify_key.is_err() && verify_root_key.is_err() {
            // if both verifications fail, return error
            verify_key?;
        }

        // remove from filesystem
        fs_api::delete_seabee_file_and_sig(&target_key.seabee_path, &FileType::Key)?;

        // remove from seabee
        self.verification_keys.remove(&target_key.id.clone());
        // update keylist
        if let Err(e) = self.export_keys() {
            //read file
            return Err(anyhow!("Key removed, but keylist was not correctly updated. This will cause an error on next restart.\nFix keylist manually at {}.\n{e}", constants::KEYLIST_PATH));
        }
        Ok(String::from("Success!"))
    }

    /// O(n) operation that returns the corresponding SeaBeeKey if one exists or None
    pub fn get_key_by_path(&self, path: &PathBuf) -> Result<Option<&SeaBeeKey>> {
        let input_key = SeaBeeKey::new_key(path, 0)?;

        for key in self.verification_keys.values() {
            if key.try_eq(&input_key)? {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }
}

fn get_command_from_stream(stream: &mut UnixStream) -> Result<SocketCommand> {
    let mut reader = std::io::BufReader::new(stream);
    let mut input = String::new();
    reader.read_line(&mut input)?;
    let command: SocketCommand = serde_json::from_str(&input)?;
    Ok(command)
}

fn write_result_to_stream(result: Result<String>, stream: &mut UnixStream) {
    let response = match result {
        Ok(r) => r,
        Err(e) => format!("Error executing command: {e}"),
    };

    // write response or error
    if let Err(e) = stream.write_all(response.as_bytes()) {
        error!("Failed to write respone to cli.\nError: {e}\nResponse: {response}");
    }
}

/// Checks for a runtime policy update command and executes it if a command is found
pub fn runtime_policy_update(sb: &mut crate::SeaBee) -> Result<()> {
    match sb.policy.listener.as_ref().unwrap().accept() {
        Ok((mut stream, _)) => {
            // timouts only fail if duration is 0
            stream.set_read_timeout(constants::SOCKET_TIMEOUT)?;
            stream.set_write_timeout(constants::SOCKET_TIMEOUT)?;

            // do policy update
            let result = match get_command_from_stream(&mut stream) {
                Ok(cmd) => sb.policy.handle_cli_command(cmd, &sb.maps),
                Err(e) => Err(e),
            };
            write_result_to_stream(result, &mut stream);
        }
        Err(e) => match e.kind() {
            std::io::ErrorKind::WouldBlock => {}
            _ => tracing::error!("incoming stream error: {e:?}"),
        },
    }

    Ok(())
}
