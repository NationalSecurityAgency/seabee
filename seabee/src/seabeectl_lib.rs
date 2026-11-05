// SPDX-License-Identifier: Apache-2.0
use std::{
    fs,
    io::{ErrorKind, Read, Write},
    os::unix::{fs::OpenOptionsExt, net::UnixStream},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
    symm::Cipher,
};
use serde::{Deserialize, Serialize};

use crate::{
    constants,
    crypto::{self, SeaBeeDigest},
    policy::policy_file,
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
    /// Only works while SeaBee is turned off. Intended for debugging.
    #[command(subcommand)]
    Clean(CleanCommand),
    /// Control the saved SeaBee Config
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Generate a shutdown request
    ///
    /// The request will have to be signed before it can be used
    ShutdownRequest {
        #[arg(default_value = "shutdown_request.yaml")]
        path: PathBuf,
    },
    /// Generate a key pair for signing SeaBee policies, keys and requests
    ///
    /// Writes <alg>-private-key.pem and <alg>-public-key.pem. The private key is
    /// encrypted with AES-256 and a passphrase unless --nopass is given.
    /// Existing files are never overwritten. To use the public key as the
    /// SeaBee root key, copy it to /etc/seabee/seabee_root_key.pem.
    Keygen(KeygenInfo),
}

/// Signature algorithms `seabeectl keygen` can create keys for
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum KeygenAlg {
    /// RSA 2048
    Rsa,
    /// ECDSA with NIST curve P-256
    Ecdsa,
}

/// Information needed to generate a key pair
#[derive(Args, Clone, Debug)]
pub struct KeygenInfo {
    /// Signature algorithm of the key pair
    #[arg(short, long, value_enum, default_value_t = KeygenAlg::Rsa)]
    pub alg: KeygenAlg,

    /// Directory for the key files
    #[arg(short, long, default_value = ".")]
    pub out_dir: PathBuf,

    /// Will not prompt for a passphrase and writes the private key unencrypted. Unencrypted private keys should not be used in production. Default is false (passphrase required).
    #[arg(short, long, default_value = "false")]
    pub nopass: bool,
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
    /// Get the current saved config from /etc/seabee/config.yaml
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
    /// A signature must accompany the remove request if verification is enabled.
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
    /// previously signed with this key. During reboot, policies and keys will be
    /// reverified with the new reduced set of keys.
    /// You cannot revoke the root key.
    RemoveKey(SignedRequestInfo),
    /// Shutdown SeaBee with a signed shutdown request
    ///
    /// A shutdown request is a yaml document with the the key "machine_id"
    /// and the value from /etc/machine-id. The request must be signed with
    /// the SeaBee root key. It is recommended to remove
    /// any signed shutdown requests after they have been used to prevent
    /// an attacker from maliciously replaying those requests.
    Shutdown(SignedRequestInfo),
}

/// Info needed to add, update, or remove a policy or key
#[derive(Args, Clone, Debug, Deserialize, Serialize)]
pub struct SignedRequestInfo {
    /// Depending on the type of request, this can be a path to a key, a policy, or a remove request.
    ///
    /// Use the path of the key for adding or removing a key.
    /// Use the path of the policy for adding or updating a policy.
    /// Use the path to a remove request for removing a policy.
    #[arg(short, long, value_parser = utils::str_to_abs_pathbuf)]
    pub target_path: PathBuf,
    /// A valid signature for the object, needed if verification is enabled
    #[arg(short, long, value_parser = utils::str_to_abs_pathbuf)]
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
            SocketCommand::Shutdown(shutdown_info) => {
                write!(f, "Shutdown: {}", shutdown_info.target_path.display())
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

    if response.contains("SeaBee failed to execute command:") {
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
        LocalCommand::ShutdownRequest { path } => seabeectl_generate_shutdown(path)?,
        LocalCommand::Keygen(info) => seabeectl_keygen(info)?,
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
    utils::verify_seabee_unloaded()?;
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

fn seabeectl_generate_shutdown(path: &PathBuf) -> Result<String> {
    // get machine_id
    let machine_id = fs::read_to_string("/etc/machine-id")
        .map_err(|e| anyhow!("failed to read /etc/machine-id: {e}"))?;
    // write machine_id to yaml file
    let shutdown_file = policy_file::ShutdownFile {
        machine_id: machine_id.trim().to_string(),
    };
    let shutdown_file_string = serde_yaml::to_string(&shutdown_file)
        .map_err(|e| anyhow!("failed to serialize shutdown file to string: {e}"))?;
    fs::write(path, shutdown_file_string)
        .map_err(|e| anyhow!("failed to write to shutdown file: {}\n{e}", path.display()))?;

    Ok(format!("Shutdown file written to {}", path.display()))
}

fn seabeectl_keygen(info: &KeygenInfo) -> Result<String> {
    let (name, key) = match info.alg {
        KeygenAlg::Rsa => ("rsa", PKey::from_rsa(Rsa::generate(2048)?)?),
        KeygenAlg::Ecdsa => {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            ("ecdsa", PKey::from_ec_key(EcKey::generate(&group)?)?)
        }
    };
    let private_path = info.out_dir.join(format!("{name}-private-key.pem"));
    let public_path = info.out_dir.join(format!("{name}-public-key.pem"));
    for path in [&private_path, &public_path] {
        if path.exists() {
            return Err(anyhow!("refusing to overwrite '{}'", path.display()));
        }
    }

    let private_pem = if info.nopass {
        key.private_key_to_pem_pkcs8()?
    } else {
        let passphrase = rpassword::prompt_password("Enter pem passphrase for private key:")?;
        if passphrase.is_empty() {
            return Err(anyhow!(
                "empty passphrase, use --nopass for an unencrypted private key"
            ));
        }
        if passphrase != rpassword::prompt_password("Verify pem passphrase:")? {
            return Err(anyhow!("passphrases do not match"));
        }
        // same format as `openssl genpkey -aes256`: encrypted PKCS#8, AES-256-CBC
        key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), passphrase.as_bytes())?
    };

    write_new_file(&private_path, &private_pem, 0o600)?;
    write_new_file(&public_path, &key.public_key_to_pem()?, 0o644)?;
    Ok(format!(
        "Wrote private key to '{}'\nWrote public key to '{}'",
        private_path.display(),
        public_path.display()
    ))
}

/// Creates `path` with `mode` and writes `contents`; fails if `path` exists
fn write_new_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| anyhow!("failed to create '{}'\n{e}", path.display()))?;
    file.write_all(contents)
        .map_err(|e| anyhow!("failed to write '{}'\n{e}", path.display()))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn keygen(alg: KeygenAlg, out_dir: &Path) -> Result<String> {
        seabeectl_keygen(&KeygenInfo {
            alg,
            out_dir: out_dir.to_path_buf(),
            nopass: true,
        })
    }

    #[test]
    fn test_keygen_writes_matching_key_pair() -> Result<()> {
        let dir = tempfile::tempdir()?;
        for (alg, name, bits) in [
            (KeygenAlg::Rsa, "rsa", 2048),
            (KeygenAlg::Ecdsa, "ecdsa", 256),
        ] {
            keygen(alg, dir.path())?;
            let private_path = dir.path().join(format!("{name}-private-key.pem"));
            let public_path = dir.path().join(format!("{name}-public-key.pem"));
            let private_key = PKey::private_key_from_pem(&fs::read(&private_path)?)?;
            let public_key = PKey::public_key_from_pem(&fs::read(&public_path)?)?;
            assert_eq!(private_key.bits(), bits);
            assert_eq!(
                private_key.public_key_to_der()?,
                public_key.public_key_to_der()?
            );
            let mode = fs::metadata(&private_path)?.permissions().mode() & 0o777;
            assert_eq!(mode & 0o077, 0, "private key readable by others: {mode:o}");
            // accepted as a SeaBee verification key
            crypto::SeaBeeKey::new_key(&public_path, 1)?;
        }
        Ok(())
    }

    #[test]
    fn test_keygen_refuses_to_overwrite() -> Result<()> {
        let dir = tempfile::tempdir()?;
        keygen(KeygenAlg::Ecdsa, dir.path())?;
        let public_path = dir.path().join("ecdsa-public-key.pem");
        let before = fs::read(&public_path)?;
        assert!(keygen(KeygenAlg::Ecdsa, dir.path()).is_err());
        assert_eq!(before, fs::read(&public_path)?);
        Ok(())
    }

    #[test]
    fn test_keygen_missing_out_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(keygen(KeygenAlg::Rsa, &dir.path().join("missing")).is_err());
    }
}
