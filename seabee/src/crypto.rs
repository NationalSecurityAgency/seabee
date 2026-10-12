// SPDX-License-Identifier: Apache-2.0
use std::{
    fmt,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use clap::Args;
use itertools::Itertools;
use openssl::{
    self,
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{Id, PKey, Public},
    sign::{Signer, Verifier},
};
use strum::IntoEnumIterator;
use zerocopy::IntoBytes;

use crate::{
    policy::policy_file::{FromYamlPath, PolicyFile},
    utils,
};

/// A key used to verify SeaBeePolicy Updates
#[derive(Debug, Clone)]
pub struct SeaBeeKey {
    // Where the key was added from, useful for printing
    added_from: PathBuf,
    /// The path on disk where this key is saved
    pub seabee_path: PathBuf,
    /// The path on disk where the signature for this key is saved
    pub sig_path: PathBuf,
    /// The digest used to sign this key
    pub sig_digest: SeaBeeDigest,
    /// The key itself, see `openssl::pkey::Pkey`
    pub key: PKey<Public>,
    /// The id used to identify this key
    pub id: u32,
}

impl SeaBeeKey {
    /// Create a new SeaBeeKey from a path and an id
    pub fn new_key(path: &PathBuf, id: u32) -> Result<Self> {
        utils::verify_file_has_ext(path, vec!["pem"])?;
        let key_file_bytes = utils::file_to_bytes(&path)?;
        let key = PKey::public_key_from_pem(&key_file_bytes)?;
        match key.id() {
            Id::RSA | Id::EC => {}
            other => {
                return Err(anyhow!(
                    "key has unsupported type: {:?}. Only EC and RSA keys are supported by SeaBee.",
                    other
                ))
            }
        };

        Ok(Self {
            added_from: std::path::absolute(path)?,
            seabee_path: PathBuf::new(),
            sig_path: PathBuf::new(),
            sig_digest: SeaBeeDigest::default(),
            key,
            id,
        })
    }

    /// Two SeaBeeKeys are equal if they are both RSA and have the same modulus (n)
    /// and exponent (e), or if they are both EC keys with the same curve and public point.
    pub fn try_eq(&self, other: &Self) -> Result<bool> {
        if self.key.id() == Id::EC && other.key.id() == Id::EC {
            return Ok(self.key.public_eq(&other.key));
        }
        if self.key.id() == Id::RSA && other.key.id() == Id::RSA {
            let our_key = self.key.rsa()?;
            let other_key = other.key.rsa()?;
            return Ok((our_key.e() == other_key.e()) && (our_key.n() == other_key.n()));
        }
        Ok(false)
    }
}

#[cfg(test)]
mod key_tests {
    use super::*;
    use openssl::{
        ec::{EcGroup, EcKey},
        nid::Nid,
    };

    #[test]
    fn ec_keys_on_different_curves_are_not_equal() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut keys = Vec::new();
        for (name, curve) in [("p256", Nid::X9_62_PRIME256V1), ("p384", Nid::SECP384R1)] {
            let group = EcGroup::from_curve_name(curve)?;
            let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
            let path = dir.path().join(format!("{name}.pem"));
            std::fs::write(&path, key.public_key_to_pem()?)?;
            keys.push(SeaBeeKey::new_key(&path, 0)?);
        }

        assert!(keys[0].try_eq(&keys[0])?);
        assert!(keys[1].try_eq(&keys[1])?);
        assert!(!keys[0].try_eq(&keys[1])?);
        assert!(!keys[1].try_eq(&keys[0])?);
        Ok(())
    }
}

impl fmt::Display for SeaBeeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key_type = match self.key.id() {
            Id::RSA => "RSA",
            Id::EC => "EC",
            _ => "Unsupported Type",
        };

        write!(
            f,
            "Added from: {}\nId: {}\nType: {}\nSize: {}",
            self.added_from.display(),
            self.id,
            key_type,
            self.key.bits()
        )
    }
}

/// SHA3: [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
/// SHA2: [NIST FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
#[derive(
    clap::ValueEnum,
    Clone,
    Debug,
    Default,
    serde::Deserialize,
    serde::Serialize,
    strum_macros::FromRepr,
    strum_macros::AsRefStr,
    strum_macros::EnumIter,
)]
pub enum SeaBeeDigest {
    sha3_224 = 1,
    #[default]
    sha3_256,
    sha3_384,
    sha3_512,
    sha224,
    sha256,
    sha384,
    sha512,
}

impl SeaBeeDigest {
    pub fn to_kebab_case(&self) -> String {
        self.as_ref().replace('_', "-")
    }
}

impl fmt::Display for SeaBeeDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_kebab_case())
    }
}

impl TryFrom<SeaBeeDigest> for MessageDigest {
    type Error = anyhow::Error;

    fn try_from(value: SeaBeeDigest) -> std::result::Result<Self, Self::Error> {
        MessageDigest::from_name(&value.to_kebab_case()).context(anyhow!(
            "Failed to convert '{}' to MessageDigest",
            &value.to_kebab_case()
        ))
    }
}

impl TryFrom<u32> for SeaBeeDigest {
    type Error = anyhow::Error;

    /// Tries to match u32 to a discriminant value for a SeaBeeDigest
    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match SeaBeeDigest::from_repr(value as usize) {
            Some(digest) => Ok(digest),
            None => Err(anyhow!("Could not convert u32 '{}' to SeaBeeDigest", value)),
        }
    }
}

/// Information needed to sign a policy
#[derive(Args, Debug, Clone)]
pub struct SignInfo {
    /// Path to a file to sign
    #[arg(short, long)]
    target_path: PathBuf,

    /// Path to a .pem containing the private signing key
    #[arg(short, long)]
    key_path: PathBuf,

    /// Output path for the signature
    #[arg(short, long, default_value = "signature.sign")]
    out_path: PathBuf,

    /// Message digest algorithm, overrides a digest specified in policy file.
    #[arg(short, long)]
    digest: Option<SeaBeeDigest>,

    /// Will not prompt for password. Note that unencrypted private keys are should not be used in production. Default is false (password required).
    #[arg(short, long, default_value = "false")]
    nopass: bool,
}

pub fn sign_file(info: &SignInfo) -> Result<String> {
    // verify input
    if !info.key_path.exists() {
        return Err(anyhow!(
            "key path does not exist: {}",
            info.key_path.display()
        ));
    }
    if !info.target_path.exists() {
        return Err(anyhow!(
            "target path does not exist: {}",
            info.target_path.display()
        ));
    }
    utils::verify_file_has_ext(&info.key_path, vec!["pem"])?;

    // get key and target
    let key_bytes = utils::file_to_bytes(&info.key_path)?;
    let target_bytes = utils::file_to_bytes(&info.target_path)?;

    // Get hash function
    let hash_func = get_digest_algorithm(&info.target_path, &info.digest)?;

    // Get private key
    let signing_key = if info.nopass {
        PKey::private_key_from_pem(&key_bytes)
            .map_err(|e| anyhow!("failed getting unencrypted private key from pem:\n{e}"))?
    } else {
        let passphrase = rpassword::prompt_password("Enter pem passphrase for signing key:")?;
        PKey::private_key_from_pem_passphrase(&key_bytes, passphrase.as_bytes())
            .map_err(|e| anyhow!("failed getting encrypted private key from pem:\n{e}"))?
    };

    // Create openssl signer with hash_func and key
    // This supports algorithms besides RSA and ECDSA, but I have those listed as supported since they are common and NIST approved
    let mut signer = Signer::new(hash_func, &signing_key)?;
    // Sign policy
    let signature = signer.sign_oneshot_to_vec(&target_bytes)?;
    // Output signature
    std::fs::write(&info.out_path, signature.as_bytes()).map_err(|e| {
        anyhow!(
            "Error write signature '{:?}' to file '{}'\n{}",
            signature,
            info.out_path.display(),
            e
        )
    })?;

    Ok(format!(
        "Successfully wrote signature to '{}'",
        &info.out_path.display()
    ))
}

/// Information needed to verify a policy.
/// Note that this is only provided for testing/debugging purposes.
#[derive(Args, Debug, Clone)]
pub struct VerifyInfoCLI {
    /// Path to a policy to verify
    #[arg(short, long)]
    pub target_path: PathBuf,

    /// Path the signature for the policy
    #[arg(short, long)]
    pub sig_path: PathBuf,

    /// Path to a pem file containing a verification key
    #[arg(short, long)]
    pub key_path: PathBuf,

    /// Message digest algorithm used to sign, overrides digest provided in policy file.
    #[arg(short, long)]
    pub digest: Option<SeaBeeDigest>,
}

/// verify a file through the cli using VerifyInfoCLI struct
pub fn verify_policy_signature_cli(info: &VerifyInfoCLI) -> Result<String> {
    // validate input
    if !info.key_path.exists() {
        return Err(anyhow!(
            "key path does not exist: {}",
            info.key_path.display()
        ));
    }
    if !info.target_path.exists() {
        return Err(anyhow!(
            "target path does not exist: {}",
            info.target_path.display()
        ));
    }
    if !info.sig_path.exists() {
        return Err(anyhow!(
            "signature path does not exist: {}",
            info.sig_path.display()
        ));
    }

    // get key and digest
    let key = SeaBeeKey::new_key(&info.key_path, 0)?;
    let digest = get_digest_algorithm(&info.target_path, &info.digest)?;

    if verify_file_signature(&info.target_path, &info.sig_path, digest, &key)? {
        Ok("Verified OK".to_string())
    } else {
        Ok("Verifcation failure".to_string())
    }
}

/// verify a file given a signature, digest algorithm, and key list
pub fn verify_file_signature(
    target_path: &Path,
    sig_path: &Path,
    digest: MessageDigest,
    key: &SeaBeeKey,
) -> Result<bool> {
    let policy_bytes = utils::file_to_bytes(&target_path)?;
    let sig_bytes = utils::file_to_bytes(&sig_path)?;

    // set up verifier
    let mut verifier = Verifier::new(digest, &key.key)?;
    // do verification
    match verifier.verify_oneshot(&sig_bytes, &policy_bytes) {
        Ok(result) => Ok(result),
        Err(e) => Err(openssl_to_anyhow_error(e)),
    }
}
fn openssl_to_anyhow_error(e: ErrorStack) -> anyhow::Error {
    let mut err_string = format!("{} openssl errors\n", e.errors().len());
    if e.errors().is_empty() {
        err_string.push_str("Maybe due to key type not matching signature type");
    }
    for err in e.errors() {
        err_string.push_str(&format!("- {:?}: {:?}", err.library(), err.reason()));
    }

    anyhow!("{}", err_string)
}

pub fn list_crypto_alg() -> String {
    let mut out = String::new();
    out.push_str("Digital Signature Algorithms: RSA, ECDSA\n");
    out.push_str(&format!(
        "Message Digest Algorithms: {}\n",
        SeaBeeDigest::iter().join(", ")
    ));
    out.push_str("Key formats: pem");
    out
}

pub fn get_digest_algorithm(
    policy_path: &Path,
    cli_digest: &Option<SeaBeeDigest>,
) -> Result<MessageDigest> {
    if cli_digest.is_some() {
        Ok(cli_digest.clone().unwrap().try_into()?)
    } else if let Ok(policy) = PolicyFile::from_path(policy_path) {
        Ok(policy.digest.try_into()?)
    } else {
        // Use default digest when one is not specified
        Ok(SeaBeeDigest::default().try_into()?)
    }
}
