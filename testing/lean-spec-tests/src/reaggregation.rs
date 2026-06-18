//! Runner for leanSpec reaggregation test vectors.
//!
//! Each vector emits a block's merged multi-message proof and the per-component
//! public key layout it was built with. A conformant client decodes that proof,
//! splits the attestation's single-message component back out by its index, and
//! verifies the recovered component on its own.
//!
//! The attestation is the first component of the block proof; the proposal
//! signature is last. So the attestation is recovered at index 0.

use std::path::Path;

use alloy_primitives::hex;
use anyhow::{anyhow, bail};
use ream_post_quantum_crypto::{
    lean_multisig::type_2::{type_1_verify, type_2_from_wire, type_2_setup, type_2_split},
    leansig::public_key::PublicKey,
};
use tracing::{debug, info};

use crate::types::{TestFixture, reaggregation::ReaggregationTest};

/// Index of the attestation's component in the block proof.
/// The proposal signature lands last, so the attestation is first.
const ATTESTATION_COMPONENT_INDEX: usize = 0;

/// Load a reaggregation test fixture from a JSON file.
pub fn load_reaggregation_test(
    path: impl AsRef<Path>,
) -> anyhow::Result<TestFixture<ReaggregationTest>> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path)
        .map_err(|err| anyhow!("Failed to read test file {}: {err}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|err| anyhow!("Failed to parse test file {}: {err}", path.display()))
}

/// Decode a 52-byte XMSS public key from a hex string.
fn decode_pubkey(pubkey: &str) -> anyhow::Result<PublicKey> {
    let bytes = hex::decode(pubkey.trim_start_matches("0x"))
        .map_err(|err| anyhow!("Failed to decode pubkey hex: {err}"))?;
    if bytes.len() != 52 {
        bail!("Expected 52-byte pubkey, got {} bytes", bytes.len());
    }
    Ok(PublicKey::from(&bytes[..]))
}

/// Run a single reaggregation vector.
///
/// Decodes the block proof, splits the attestation's component back out, and
/// verifies the recovered single-message proof.
pub fn run_reaggregation_test(test_name: &str, test: &ReaggregationTest) -> anyhow::Result<()> {
    info!("Running reaggregation test: {test_name}");
    debug!("  Network: {}", test.network);
    debug!("  Block attesters: {:?}", test.block_attesters);

    // Decode the per-component public key layout the block proof was built with.
    let public_keys_per_component: Vec<Vec<PublicKey>> = test
        .public_keys_per_message
        .iter()
        .map(|component| {
            component
                .iter()
                .map(|pubkey| decode_pubkey(pubkey))
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Compile the aggregation bytecode before any proof operation, the way the
    // block-proof verifier does. Decoding and splitting both read it.
    type_2_setup();

    // Reconstruct the block's merged multi-message proof from its wire bytes.
    let block_proof_bytes = hex::decode(test.block_proof.trim_start_matches("0x"))
        .map_err(|err| anyhow!("Failed to decode blockProof hex: {err}"))?;
    let block_proof = type_2_from_wire(&block_proof_bytes, &public_keys_per_component)?;

    // Split the attestation's component back out of the merged proof.
    let recovered = type_2_split(block_proof, ATTESTATION_COMPONENT_INDEX)?;

    // The split must extract the attestation's component, not the proposal's.
    // A wrong component index would recover a proof bound to the wrong message.
    let recovered_message = recovered.info.without_pubkeys.message;
    if recovered_message != test.attestation_message.0 {
        bail!(
            "split recovered the wrong component: bound to message 0x{}, expected 0x{}",
            hex::encode(recovered_message),
            hex::encode(test.attestation_message.0),
        );
    }
    let recovered_slot = u64::from(recovered.info.without_pubkeys.slot);
    if recovered_slot != test.attestation_slot {
        bail!(
            "recovered component slot mismatch: got {recovered_slot}, expected {}",
            test.attestation_slot,
        );
    }

    // The recovered single-message proof must verify on its own against the
    // block attesters' keys, which the split bound into it.
    type_1_verify(&recovered)?;

    Ok(())
}
