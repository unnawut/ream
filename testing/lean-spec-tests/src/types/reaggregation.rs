//! Intermediate JSON types for leanSpec reaggregation test fixtures.
//!
//! Each vector emits a block's merged multi-message proof, the per-component
//! public key layout it was built with, and the attesters that signed the
//! split-out attestation. A conformant client decodes the block proof, splits
//! the attestation's component back out, and verifies it.

use alloy_primitives::B256;
use serde::Deserialize;

/// One vector from a reaggregation_test fixture file.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReaggregationTest {
    pub network: String,
    pub lean_env: String,
    /// The block's merged multi-message proof, as hex.
    pub block_proof: String,
    /// Per-component public key layout the block proof was built with, as hex.
    /// Attestation keys first, the proposal key last.
    pub public_keys_per_message: Vec<Vec<String>>,
    /// Hash tree root of the split-out attestation.
    pub attestation_message: B256,
    /// Slot the recovered proof is bound to.
    pub attestation_slot: u64,
    /// Validators who signed the attestation carried in the block.
    pub block_attesters: Vec<u64>,
    /// Validators who signed the attestation the node already held locally.
    pub local_attesters: Vec<u64>,
    /// Union of the block and local attesters.
    pub combined_attesters: Vec<u64>,
    /// The re-aggregated single-message proof, as hex.
    pub reaggregated_proof: String,
}
