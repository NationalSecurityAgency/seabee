// SPDX-License-Identifier: Apache-2.0
use std::{
    fs,
    io::{ErrorKind, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

use crate::{
    constants,
    crypto::{self, SeaBeeDigest},
    utils,
};
use bpf::seabee::NO_POL_ID;

/// Used to query or modify seaBee policies
#[derive(Debug, Parser)]
#[command(version, about, long_about)]
pub struct SeaBeeCtlArgs {
    /// Do policy action
    #[command(subcommand)]
    cmd: SeaBeeCtlCommands,
}

#[derive(Clone, Debug, Subcommand)]
pub enum SeaBeeCtlCommands {
    /// Sign and verify policies locally
    #[command(flatten)]
    Local(LocalCommand),
    /// View, add, update, or remove SeaBee policies
    #[command(flatten)]
    Socket(SocketCommand),
}

#[derive(Clone, Debug, Subcommand)]
pub enum LocalCommand {
    /// List supported cryptographic algorithms
    Alg,
    /// Sign a policy with a private signing key
    Sign(crypto::SignInfo),
    /// Test verifying a policy with a public verification key
    Verify(crypto::VerifyInfoCLI),
    /// Remove SeaBee policies and keys.
    ///
    /// Only works while SeaBee is turned off. Inteded for debugging.
    #[command(subcommand)]
    Clean(CleanCommand),
    /// Control the saved SeaBee Config
    #[command(subcommand)]
    Config(ConfigCommand),
}

#[derive(Clone, Debug, Subcommand)]
pub enum CleanCommand {
    /// Remove all saved SeaBee policies
    Policy,
    /// Remove all saved SeaBee keys. Policies may not verify on next boot.
    Keys,
    /// Remove the SeaBee root key. SeaBee will not start without a root key installed.
    RootKey,
    /// Remove the SeaBee saved config
    Config,
    /// Remove all SeaBee saved data
    All,
}

#[derive(Clone, Debug, Subcommand)]
pub enum ConfigCommand {
    /// Get the current saved config from /etc/seabee/config.toml
    Get,
    /// Update the current saved config while SeaBee is turned off
    Update { path: PathBuf },
    /// Remove the current SeaBee saved config
    Remove,
}

#[derive(Clone, Debug, Deserialize, Serialize, Subcommand)]
pub enum SocketCommand {
    /// List all currently loaded policies
    List,
    /// Display a single loaded policy
    #[command(subcommand)]
    Show(ObjIdentifier),
    /// Add or update a policy from a path.
    ///
    /// If the name of the policy already exists, SeaBee will
    /// attempt to update. Otherwise SeaBee will add a new policy.
    /// You cannot change the policy scope via a policy update.
    /// You must increment policy version for update to be accepted.
    /// If SeaBee has verification enabled, then a signature will be needed as well.
    Update(SignedRequestInfo),
    /// Remove an existing policy with a remove request.
    ///
    /// A remove request is a yaml document with only the target policy name and version.
    /// A signature must acompany the remove request if verification is enabled.
    Remove(SignedRequestInfo),
    /// List all SeaBee verification keys
    ListKeys,
    /// Show a single SeaBee verification key
    #[command(subcommand)]
    ShowKey(KeyIdentifier),
    /// Add a new verification key
    ///
    /// If --verify-keys is enabled, a signature from the
    /// seabee root key is required on the new key file.
    AddKey(SignedRequestInfo),
    /// Remove an existing verification key
    ///
    /// A signature by the target key or the root key.
    /// Removing a key does not immediately revoke policies or other verification keys
    /// previosuly signed with this key. During reboot, policies and keys will be
    /// reverified with the new reduced set of keys.
    /// You cannot revoke the root key.
    RemoveKey(SignedRequestInfo),
}

/// Info needed to add, update, or remove a policy or key
#[derive(Args, Clone, Debug, Deserialize, Serialize)]
pub struct SignedRequestInfo {
    /// Depending on the type of request, this can be a path to a key, a policy, or a remove request.
    ///
    /// Use the path of the key for adding or removing a key.
    /// Use the path of the policy for adding or updating a policy.
    /// Use the path to a remove request for removing a policy.
    #[arg(short, long)]
    pub target_path: PathBuf,
    /// A valid signature for the object, needed if verification is enabled
    #[arg(short, long)]
    pub sig_path: Option<PathBuf>,
    /// Specify the digest for the signature if not using the default (sha3-256)
    #[arg(short, long)]
    pub digest: Option<SeaBeeDigest>,
}

impl std::fmt::Display for SocketCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketCommand::List => write!(f, "List"),
            SocketCommand::Show(ident) => write!(f, "Show: {ident}"),
            SocketCommand::Update(update_info) => {
                write!(f, "Update: {}", update_info.target_path.display())
            }
            SocketCommand::Remove(remove_info) => {
                write!(f, "Remove: {}", remove_info.target_path.display())
            }
            SocketCommand::ListKeys => write!(f, "Keylist"),
            SocketCommand::ShowKey(ident) => write!(f, "Show Key: {ident}"),
            SocketCommand::AddKey(key_info) => {
                write!(f, "Add Key: {}", key_info.target_path.display())
            }
            SocketCommand::RemoveKey(key_info) => {
                write!(f, "Remove Key: {}", key_info.target_path.display())
            }
        }
    }
}

// Ways to identify a SeaBee Key
#[derive(Clone, Debug, Deserialize, Serialize, Subcommand)]
pub enum KeyIdentifier {
    /// Identify by Id
    Id { id: u32 },
    /// Identify by a file path
    File { path: PathBuf },
}

impl std::fmt::Display for KeyIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyIdentifier::Id { id } => write!(f, "Id: {id}"),
            KeyIdentifier::File { path } => write!(f, "File: {}", path.display()),
        }
    }
}

/// Different ways to uniquely identify a SeaBee Object.
/// Path method will only use the name field of the policy at the path as an identifier.
#[derive(Clone, Debug, Deserialize, Serialize, Subcommand)]
pub enum ObjIdentifier {
    /// Identify by Id
    Id { id: u32 },
    /// Identify by name
    Name { name: String },
    /// Identify by a file path
    File { path: PathBuf },
}

impl Default for ObjIdentifier {
    fn default() -> Self {
        Self::Id { id: NO_POL_ID }
    }
}

impl std::fmt::Display for ObjIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjIdentifier::Id { id } => write!(f, "Id: {id}"),
            ObjIdentifier::Name { name } => write!(f, "Name: {name}"),
            ObjIdentifier::File { path } => write!(f, "File: {}", path.display()),
        }
    }
}

// Here starts the seabeectl functions

pub fn execute_args(args: SeaBeeCtlArgs) -> Result<()> {
    match args.cmd {
        SeaBeeCtlCommands::Local(cmd) => execute_local_command(cmd),
        SeaBeeCtlCommands::Socket(cmd) => execute_socket_command(cmd),
    }
}

/// Executes the command passed to the command line that requires interaction with SeaBee via domain socket
pub fn execute_socket_command(command: SocketCommand) -> Result<()> {
    let mut stream = init_stream()?;

    // serialize the command and write it to the stream, followed by a newline so the
    // BufReader knows that it is the end of the command.
    stream.write_all(serde_json::to_string(&command)?.as_bytes())?;
    stream.write_all(b"\n")?;

    // wait for the response and print it out to the console
    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    if response.contains("Error executing command:") {
        return Err(anyhow!("{}", response));
    }
    println!("{response}");

    Ok(())
}

pub fn execute_local_command(cmd: LocalCommand) -> Result<()> {
    // handle commands that don't need a socket connection
    let output = match &cmd {
        LocalCommand::Alg => crypto::list_crypto_alg(),
        LocalCommand::Sign(info) => crypto::sign_file(info)?,
        LocalCommand::Verify(info) => crypto::verify_policy_signature_cli(info)?,
        LocalCommand::Clean(subcmd) => seabeectl_clean(subcmd)?,
        LocalCommand::Config(subcmd) => seabeectl_config(subcmd)?,
    };

    println!("{output}");
    Ok(())
}

fn seabeectl_clean(cmd: &CleanCommand) -> Result<String> {
    match cmd {
        CleanCommand::All => utils::remove_if_exists(Path::new(constants::SEABEE_DIR))?,
        CleanCommand::Keys => {
            utils::remove_if_exists(Path::new(constants::KEY_DIR))?;
            utils::remove_if_exists(Path::new(constants::KEY_SIGNATURE_DIR))?;
            utils::remove_if_exists(Path::new(constants::KEYLIST_PATH))?;
        }
        CleanCommand::Policy => {
            utils::remove_if_exists(Path::new(constants::POLICY_DIR))?;
            utils::remove_if_exists(Path::new(constants::POL_SIGNATURE_DIR))?;
        }
        CleanCommand::RootKey => {
            utils::remove_if_exists(Path::new(constants::SEABEE_ROOT_KEY_PATH))?
        }
        CleanCommand::Config => utils::remove_if_exists(Path::new(constants::CONFIG_PATH))?,
    }
    Ok("Success!".to_string())
}

fn seabeectl_config(cmd: &ConfigCommand) -> Result<String> {
    match cmd {
        ConfigCommand::Get => return Ok(fs::read_to_string(constants::CONFIG_PATH)?),
        ConfigCommand::Remove => fs::remove_file(constants::CONFIG_PATH)?,
        ConfigCommand::Update { path } => update_config(path)?,
    };
    Ok("Success!".to_string())
}

fn update_config(path: &PathBuf) -> Result<()> {
    utils::create_dir_if_not_exists(constants::SEABEE_DIR)?;
    if let Err(e) = fs::copy(path, constants::CONFIG_PATH) {
        return Err(anyhow!(
            "Failed to update SeaBee saved config at {}\n{e}",
            path.display()
        ));
    }
    Ok(())
}

fn init_stream() -> Result<UnixStream> {
    let stream = match UnixStream::connect(constants::SOCKET_PATH) {
        Ok(sock) => sock,
        Err(e) => {
            return Err(match e.kind() {
                ErrorKind::NotFound => {
                    anyhow!("socket connect failed. Ensure SeaBee is running.\nerror: {e:?}")
                }
                ErrorKind::PermissionDenied => anyhow!(
                    "socket connect failed. Make sure to run seabeectl from {}.\nerror: {e:?}",
                    constants::SEABEECTL_EXE
                ),
                _ => anyhow!("socket connect failed.\nerror: {e:?}"),
            })
        }
    };

    stream.set_read_timeout(constants::SOCKET_TIMEOUT)?;
    stream.set_write_timeout(constants::SOCKET_TIMEOUT)?;
    Ok(stream)
}
