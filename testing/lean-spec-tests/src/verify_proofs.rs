//! Runner for leanSpec verify_proofs test vectors.
//!
//! Each vector emits an attestation_data, the resolved public keys, an
//! aggregation bitfield, the bound message and slot, and the proof
//! bytes. A conformant client recomputes the attestation hash tree
//! root, matches the emitted message field, then runs the Type-1
//! verifier and matches expect_valid.

use std::path::Path;

use alloy_primitives::hex;
use anyhow::{Context, bail};
use ream_post_quantum_crypto::{
    lean_multisig::aggregate::verify_aggregate_signature, leansig::public_key::PublicKey,
};
use tracing::{debug, info};
use tree_hash::TreeHash;

use crate::types::{TestFixture, verify_proofs::VerifyProofsTest};

/// Load a verify_proofs fixture file.
pub fn load_verify_proofs_test(
    path: impl AsRef<Path>,
) -> anyhow::Result<TestFixture<VerifyProofsTest>> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read test file {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse test file {}", path.display()))
}

/// Run a single verify_proofs vector.
///
/// Recomputes the attestation hash tree root, matches it against the
/// emitted message, runs the Type-1 verifier, and matches the verifier
/// outcome against expect_valid.
pub fn run_verify_proofs_test(name: &str, test: &VerifyProofsTest) -> anyhow::Result<()> {
    info!("Running verify_proofs test: {name}");
    debug!("  Network: {}", test.network);
    debug!("  Proof type: {}", test.proof_type);

    // SSZ hash check — a divergence here is an SSZ bug that would
    // surface long before the verifier ever runs.
    let computed_root = test.attestation_data.tree_hash_root();
    if computed_root != test.message {
        bail!(
            "Hash tree root mismatch: computed 0x{}, emitted 0x{}",
            hex::encode(computed_root),
            hex::encode(test.message),
        );
    }

    match test.proof_type.as_str() {
        "type_1" => run_type_1(test),
        other => bail!("Unsupported proof type: {other}"),
    }
}

fn run_type_1(test: &VerifyProofsTest) -> anyhow::Result<()> {
    let public_keys = test
        .public_keys
        .iter()
        .map(PublicKey::try_from)
        .collect::<anyhow::Result<Vec<_>>>()?;

    let proof_bytes = hex::decode(test.proof.data.trim_start_matches("0x"))
        .context("Failed to decode proof bytes")?;
    let message_bytes: [u8; 32] = test.message.into();
    let slot = u32::try_from(test.slot).context("Slot does not fit in u32")?;

    let result = verify_aggregate_signature(&public_keys, &message_bytes, &proof_bytes, slot);
    let verifier_accepted = result.is_ok();

    if verifier_accepted != test.expect_valid {
        let rejection_detail = result
            .as_ref()
            .err()
            .map(|err| format!(" ({err})"))
            .unwrap_or_default();
        let expect_valid = test.expect_valid;
        bail!(
            "Verifier outcome mismatch: accepted={verifier_accepted}, \
             expect_valid={expect_valid}{rejection_detail}",
        );
    }

    Ok(())
}
