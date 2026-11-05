// SPDX-License-Identifier: Apache-2.0

/// This file tests the local commands of seabeectl including "alg", "sign", and "verify"
/// sign will use keys besides ECDSA or RSA since there is no reason to restrict it.
/// However, verify mirrors the seabeectl verify process and will not allow
/// key types besides ECDSA, RSA, ML-DSA or SLH-DSA
use std::fs;

use crate::{command::TestCommandBuilder, create_test};
use libtest_mimic;
use seabee::crypto;
use strum::IntoEnumIterator;

const POLICY: &str = "policies/test_policy.yaml";
const RSA_PRIV: &str = "crypto/keys/rsa-private.pem";
const RSA_PUB: &str = "crypto/keys/rsa-public.pem";
const EC_PRIV: &str = "crypto/keys/ecdsa-private.pem";
const EC_PUB: &str = "crypto/keys/ecdsa-public.pem";
const ML_DSA_PRIV: &str = "crypto/keys/ml-dsa-65-private.pem";
const ML_DSA_PUB: &str = "crypto/keys/ml-dsa-65-public.pem";
const SLH_DSA_PRIV: &str = "crypto/keys/slh-dsa-sha2-128s-private.pem";
const SLH_DSA_PUB: &str = "crypto/keys/slh-dsa-sha2-128s-public.pem";
const SHA3: &str = "sha3-256";

// invalid keys
const FAKE_KEY: &str = "crypto/keys/invalid/fakekey";
const DSA_PRIV: &str = "crypto/keys/invalid/dsa-private.pem";
const DSA_PUB: &str = "crypto/keys/invalid/dsa-public.pem";
const DNE: &str = "/some/nonexistant/file.abcdz";

fn seabeectl_sign(
    t: &str,
    k: &str,
    o: &str,
    d: &str,
    rc: i32,
    stdout: &str,
    stderr: &str,
) -> Result<(), libtest_mimic::Failed> {
    TestCommandBuilder::default()
        .program("seabeectl")
        .args(&["sign", "-t", t, "-k", k, "--nopass", "-d", d, "-o", o])
        .expected_rc(rc)
        .expected_stdout(stdout)
        .expected_stderr(stderr)
        .build()?
        .test()
}

fn seabeectl_verify(
    t: &str,
    k: &str,
    s: &str,
    d: &str,
    rc: i32,
    stdout: &str,
    stderr: &str,
) -> Result<(), libtest_mimic::Failed> {
    TestCommandBuilder::default()
        .program("seabeectl")
        .args(&["verify", "-t", t, "-k", k, "-s", s, "-d", d])
        .expected_rc(rc)
        .expected_stdout(stdout)
        .expected_stderr(stderr)
        .build()?
        .test()
}

fn seabeectl_sign_verify_default() -> Result<(), libtest_mimic::Failed> {
    // cannot have generic path due to parallelism
    let sig = "default_sig_test.sign";
    TestCommandBuilder::default()
        .program("seabeectl")
        .args(&["sign", "-t", POLICY, "-k", EC_PRIV, "--nopass", "-o", sig])
        .expected_rc(0)
        .expected_stdout("Success")
        .build()?
        .test()?;
    TestCommandBuilder::default()
        .program("seabeectl")
        .args(&["verify", "-t", POLICY, "-k", EC_PUB, "-s", sig])
        .expected_rc(0)
        .expected_stdout("Verified OK")
        .build()?
        .test()?;
    fs::remove_file(sig)?;
    Ok(())
}

/// Test that `seabeectl alg` works without error
fn seabeectl_alg() -> Result<(), libtest_mimic::Failed> {
    TestCommandBuilder::default()
        .program("seabeectl")
        .args(&["alg"])
        .expected_rc(0)
        .expected_stdout("RSA") // should appear in output
        .build()?
        .test()
}

fn seabeectl_local_invalid_digest() -> Result<(), libtest_mimic::Failed> {
    let sig = "invalid_sig"; // will not be created
    seabeectl_sign(POLICY, EC_PRIV, sig, "md5", 2, "", "invalid value")?;
    seabeectl_verify(POLICY, EC_PUB, sig, "md5", 2, "", "invalid value")?;
    Ok(())
}

fn seabeectl_local_invalid_key_ext() -> Result<(), libtest_mimic::Failed> {
    let sig = "invalid_key_ext.sign";
    seabeectl_sign(POLICY, FAKE_KEY, sig, SHA3, 1, "", "expected extension")?;
    // create sig path
    seabeectl_sign(POLICY, EC_PRIV, sig, SHA3, 0, "Success", "")?;
    seabeectl_verify(POLICY, FAKE_KEY, sig, SHA3, 1, "", "expected extension")?;
    fs::remove_file(sig)?;
    Ok(())
}

fn seabeectl_local_file_not_found() -> Result<(), libtest_mimic::Failed> {
    let sig = "invalid_sig"; // will not be created
    seabeectl_sign(
        DNE,
        RSA_PRIV,
        sig,
        SHA3,
        1,
        "",
        "target path does not exist",
    )?;
    seabeectl_sign(POLICY, DNE, sig, SHA3, 1, "", "key path does not exist")?;
    seabeectl_verify(DNE, RSA_PUB, sig, SHA3, 1, "", "target path does not exist")?;
    seabeectl_verify(POLICY, DNE, sig, SHA3, 1, "", "key path does not exist")?;
    seabeectl_verify(
        POLICY,
        RSA_PUB,
        DNE,
        SHA3,
        1,
        "",
        "signature path does not exist",
    )
}

fn seabeectl_verify_invalid_key_type() -> Result<(), libtest_mimic::Failed> {
    let sig = "test_verify_invalid_key_type.sign";
    seabeectl_sign(POLICY, DSA_PRIV, sig, SHA3, 0, "Success", "")?;
    seabeectl_verify(POLICY, DSA_PUB, sig, SHA3, 1, "", "unsupported type")?;
    fs::remove_file(sig)?;
    Ok(())
}

fn seabeectl_sign_verify_ecdsa() -> Result<(), libtest_mimic::Failed> {
    // cannot have generic path due to parallelism
    let sig = "sign_verify_ecdsa.sign";
    for digest in crypto::SeaBeeDigest::iter() {
        let digest = digest.to_kebab_case();
        seabeectl_sign(POLICY, EC_PRIV, sig, &digest, 0, "Success", "")?;
        seabeectl_verify(POLICY, EC_PUB, sig, &digest, 0, "Verified OK", "")?;
    }
    fs::remove_file(sig)?;
    Ok(())
}

fn seabeectl_sign_verify_rsa() -> Result<(), libtest_mimic::Failed> {
    // cannot have generic path due to parallelism
    let sig = "sign_verify_rsa.sign";
    for digest in crypto::SeaBeeDigest::iter() {
        let digest = digest.to_kebab_case();
        seabeectl_sign(POLICY, RSA_PRIV, sig, &digest, 0, "Success", "")?;
        seabeectl_verify(POLICY, RSA_PUB, sig, &digest, 0, "Verified OK", "")?;
    }
    fs::remove_file(sig)?;
    Ok(())
}

/// ML-DSA and SLH-DSA sign the message itself, so any digest is accepted and ignored
fn seabeectl_sign_verify_pqc() -> Result<(), libtest_mimic::Failed> {
    // cannot have generic path due to parallelism
    for (private, public, sig) in [
        (ML_DSA_PRIV, ML_DSA_PUB, "sign_verify_ml_dsa.sign"),
        (SLH_DSA_PRIV, SLH_DSA_PUB, "sign_verify_slh_dsa.sign"),
    ] {
        seabeectl_sign(POLICY, private, sig, SHA3, 0, "Success", "")?;
        seabeectl_verify(POLICY, public, sig, SHA3, 0, "Verified OK", "")?;
        fs::remove_file(sig)?;
    }
    Ok(())
}

pub fn tests() -> Vec<libtest_mimic::Trial> {
    vec![
        create_test!(seabeectl_alg),
        create_test!(seabeectl_local_invalid_digest),
        create_test!(seabeectl_local_invalid_key_ext),
        create_test!(seabeectl_local_file_not_found),
        create_test!(seabeectl_sign_verify_ecdsa),
        create_test!(seabeectl_sign_verify_rsa),
        create_test!(seabeectl_sign_verify_default),
        create_test!(seabeectl_sign_verify_pqc),
        create_test!(seabeectl_verify_invalid_key_type),
        //TODO: seabeectl clean cannot be tested while SeaBee is running
        //TODO: seabeectl config cannot be tested while SeaBee is running
    ]
}
