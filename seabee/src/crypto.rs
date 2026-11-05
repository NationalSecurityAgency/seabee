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
    bn::BigNumContext,
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{HasPublic, Id, PKey, PKeyRef, Public},
    sign::{Signer, Verifier},
};
use strum::IntoEnumIterator;
use zerocopy::IntoBytes;

use crate::{
    policy::policy_file::{FromYamlPath, PolicyFile},
    utils,
};

/// Final parameter sets of FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA), in OID order.
/// Their OIDs are 2.16.840.1.101.3.4.3.17 through 2.16.840.1.101.3.4.3.31 (NIST CSOR).
const NIST_PQC_PARAM_SETS: [&str; 15] = [
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s",
    "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s",
    "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s",
    "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s",
    "SLH-DSA-SHAKE-256f",
];
/// DER of an AlgorithmIdentifier holding 2.16.840.1.101.3.4.3.x without parameters,
/// missing the last OID byte x
const NIST_SIG_ALG_ID_PREFIX: [u8; 12] = [
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
];
const NIST_PQC_FIRST_OID_ARC: u8 = 17;

/// Signature algorithm of a SeaBee key
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeaBeeKeyType {
    Rsa,
    Ec,
    /// FIPS 204 parameter set
    MlDsa(&'static str),
    /// FIPS 205 parameter set
    SlhDsa(&'static str),
}

impl SeaBeeKeyType {
    /// Returns the type of a key, or None if SeaBee does not support it
    pub fn from_pkey<T: HasPublic>(key: &PKeyRef<T>) -> Option<Self> {
        match key.id() {
            Id::RSA => Some(Self::Rsa),
            Id::EC => Some(Self::Ec),
            // OpenSSL 3.5 reports no legacy id for ML-DSA and SLH-DSA keys,
            // so identify them by the algorithm OID of the public key
            _ => Self::from_spki(&key.public_key_to_der().ok()?),
        }
    }

    /// Reads the algorithm of a DER SubjectPublicKeyInfo:
    /// SEQUENCE { SEQUENCE { OID }, BIT STRING }
    fn from_spki(spki: &[u8]) -> Option<Self> {
        if *spki.first()? != 0x30 {
            return None;
        }
        let len = *spki.get(1)?;
        let start = if len < 0x80 {
            2
        } else {
            2 + (len & 0x7f) as usize
        };
        let alg_id = spki.get(start..start + NIST_SIG_ALG_ID_PREFIX.len() + 1)?;
        if alg_id[..NIST_SIG_ALG_ID_PREFIX.len()] != NIST_SIG_ALG_ID_PREFIX {
            return None;
        }
        let index = alg_id[NIST_SIG_ALG_ID_PREFIX.len()].checked_sub(NIST_PQC_FIRST_OID_ARC)?;
        let name = *NIST_PQC_PARAM_SETS.get(index as usize)?;
        if index < 3 {
            Some(Self::MlDsa(name))
        } else {
            Some(Self::SlhDsa(name))
        }
    }

    /// RSA and ECDSA sign a digest of the message. ML-DSA and SLH-DSA sign the
    /// message itself, so a separate digest does not apply.
    pub fn uses_digest(&self) -> bool {
        matches!(self, Self::Rsa | Self::Ec)
    }
}

impl fmt::Display for SeaBeeKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa => write!(f, "RSA"),
            Self::Ec => write!(f, "EC"),
            Self::MlDsa(name) | Self::SlhDsa(name) => write!(f, "{name}"),
        }
    }
}

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
        if SeaBeeKeyType::from_pkey(&key).is_none() {
            return Err(anyhow!(
                "key has unsupported type: {:?}. Only EC, RSA, ML-DSA and SLH-DSA keys are supported by SeaBee.",
                key.id()
            ));
        }

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
    /// and exponent (e), or if they are both EC keys and EC_POINT_cmp returns 0.
    ///
    /// error if EC_POINT_cmp returns -1 or BN_CTX_new fails
    pub fn try_eq(&self, other: &Self) -> Result<bool> {
        if self.key.id() == Id::EC && other.key.id() == Id::EC {
            let mut ctx = BigNumContext::new()?;
            let ec_key = self.key.ec_key()?;
            return Ok(ec_key.public_key().eq(
                ec_key.group(),
                other.key.ec_key()?.public_key(),
                &mut ctx,
            )?);
        }
        if self.key.id() == Id::RSA && other.key.id() == Id::RSA {
            let our_key = self.key.rsa()?;
            let other_key = other.key.rsa()?;
            return Ok((our_key.e() == other_key.e()) && (our_key.n() == other_key.n()));
        }
        let our_type = SeaBeeKeyType::from_pkey(&self.key);
        if our_type.is_some_and(|t| !t.uses_digest())
            && our_type == SeaBeeKeyType::from_pkey(&other.key)
        {
            return Ok(self.key.public_key_to_der()? == other.key.public_key_to_der()?);
        }
        Ok(false)
    }
}

impl fmt::Display for SeaBeeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key_type = match SeaBeeKeyType::from_pkey(&self.key) {
            Some(key_type) => key_type.to_string(),
            None => "Unsupported Type".to_string(),
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
    let mut signer = match SeaBeeKeyType::from_pkey(&signing_key) {
        Some(key_type) if !key_type.uses_digest() => Signer::new_without_digest(&signing_key)?,
        _ => Signer::new(hash_func, &signing_key)?,
    };
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
    let mut verifier = match SeaBeeKeyType::from_pkey(&key.key) {
        Some(key_type) if !key_type.uses_digest() => Verifier::new_without_digest(&key.key)?,
        _ => Verifier::new(digest, &key.key)?,
    };
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
    out.push_str("Digital Signature Algorithms: RSA, ECDSA, ML-DSA, SLH-DSA\n");
    out.push_str(&format!(
        "Message Digest Algorithms (RSA and ECDSA only): {}\n",
        SeaBeeDigest::iter().join(", ")
    ));
    out.push_str(&format!(
        "ML-DSA and SLH-DSA parameter sets: {}\n",
        NIST_PQC_PARAM_SETS.join(", ")
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/crypto/keys");

    fn key_path(name: &str) -> PathBuf {
        PathBuf::from(KEY_DIR).join(name)
    }

    /// DER SubjectPublicKeyInfo header with a NIST signature OID ending in `arc`
    fn spki_header(arc: u8, long_form: bool) -> Vec<u8> {
        let mut der = if long_form {
            vec![0x30, 0x82, 0x07, 0xb2]
        } else {
            vec![0x30, 0x30]
        };
        der.extend_from_slice(&NIST_SIG_ALG_ID_PREFIX);
        der.push(arc);
        der.extend_from_slice(&[0x03, 0x21, 0x00]);
        der
    }

    #[test]
    fn test_spki_detects_all_fips_204_205_parameter_sets() {
        for (i, name) in NIST_PQC_PARAM_SETS.iter().enumerate() {
            let arc = NIST_PQC_FIRST_OID_ARC + i as u8;
            for long_form in [false, true] {
                let key_type = SeaBeeKeyType::from_spki(&spki_header(arc, long_form));
                let expected = if i < 3 {
                    SeaBeeKeyType::MlDsa(name)
                } else {
                    SeaBeeKeyType::SlhDsa(name)
                };
                assert_eq!(key_type, Some(expected));
            }
        }
    }

    #[test]
    fn test_spki_rejects_other_oids() {
        // 2.16.840.1.101.3.4.3.16 and .32 are outside FIPS 204/205
        assert_eq!(SeaBeeKeyType::from_spki(&spki_header(16, false)), None);
        assert_eq!(SeaBeeKeyType::from_spki(&spki_header(32, false)), None);
        let mut other_prefix = spki_header(17, false);
        other_prefix[11] = 0x02;
        assert_eq!(SeaBeeKeyType::from_spki(&other_prefix), None);
        assert_eq!(SeaBeeKeyType::from_spki(&[0x30]), None);
        assert_eq!(SeaBeeKeyType::from_spki(&[]), None);
    }

    #[test]
    fn test_new_key_accepts_ml_dsa_and_slh_dsa() -> Result<()> {
        let ml_dsa = SeaBeeKey::new_key(&key_path("ml-dsa-65-public.pem"), 1)?;
        let slh_dsa = SeaBeeKey::new_key(&key_path("slh-dsa-sha2-128s-public.pem"), 2)?;
        assert_eq!(
            SeaBeeKeyType::from_pkey(&ml_dsa.key),
            Some(SeaBeeKeyType::MlDsa("ML-DSA-65"))
        );
        assert_eq!(
            SeaBeeKeyType::from_pkey(&slh_dsa.key),
            Some(SeaBeeKeyType::SlhDsa("SLH-DSA-SHA2-128s"))
        );
        assert!(ml_dsa.to_string().contains("Type: ML-DSA-65"));
        Ok(())
    }

    #[test]
    fn test_new_key_still_rejects_dsa() {
        assert!(SeaBeeKey::new_key(&key_path("invalid/dsa-public.pem"), 1).is_err());
    }

    #[test]
    fn test_try_eq_ml_dsa_and_slh_dsa() -> Result<()> {
        let ml_dsa = SeaBeeKey::new_key(&key_path("ml-dsa-65-public.pem"), 1)?;
        let ml_dsa_again = SeaBeeKey::new_key(&key_path("ml-dsa-65-public.pem"), 2)?;
        let slh_dsa = SeaBeeKey::new_key(&key_path("slh-dsa-sha2-128s-public.pem"), 3)?;
        let ec = SeaBeeKey::new_key(&key_path("ecdsa-public.pem"), 4)?;
        assert!(ml_dsa.try_eq(&ml_dsa_again)?);
        assert!(!ml_dsa.try_eq(&slh_dsa)?);
        assert!(!ml_dsa.try_eq(&ec)?);
        assert!(!ec.try_eq(&ml_dsa)?);
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_without_digest() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("target.yaml");
        std::fs::write(&target, "name: pqc\n")?;
        for (private, public) in [
            ("ml-dsa-65-private.pem", "ml-dsa-65-public.pem"),
            (
                "slh-dsa-sha2-128s-private.pem",
                "slh-dsa-sha2-128s-public.pem",
            ),
        ] {
            let sig = dir.path().join(format!("{private}.sign"));
            let info = SignInfo {
                target_path: target.clone(),
                key_path: key_path(private),
                out_path: sig.clone(),
                digest: Some(SeaBeeDigest::sha512),
                nopass: true,
            };
            sign_file(&info)?;
            let key = SeaBeeKey::new_key(&key_path(public), 1)?;
            // the digest argument does not apply to ML-DSA and SLH-DSA
            assert!(verify_file_signature(
                &target,
                &sig,
                MessageDigest::sha256(),
                &key
            )?);
            let other = dir.path().join("other.yaml");
            std::fs::write(&other, "name: other\n")?;
            assert!(!verify_file_signature(
                &other,
                &sig,
                MessageDigest::sha256(),
                &key
            )?);
        }
        Ok(())
    }
}
