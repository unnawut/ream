//! Intermediate JSON types for leanSpec verify_proofs test fixtures.
//!
//! These types mirror the JSON the leanSpec filler emits and convert to
//! the ream-side public keys and proof bytes consumed by the verifier.

use alloy_primitives::B256;
use ream_consensus_lean::attestation::AttestationData;
use serde::Deserialize;

use super::ssz_test::{DataListJSON, ProofDataJSON, PublicKeyJSON};

/// One vector from a verify_proofs_test fixture file.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyProofsTest {
    pub network: String,
    pub lean_env: String,
    pub proof_type: String,
    pub attestation_data: AttestationData,
    pub expect_valid: bool,
    pub public_keys: Vec<PublicKeyJSON>,
    pub aggregation_bits: DataListJSON<bool>,
    pub message: B256,
    pub slot: u64,
    pub proof: ProofDataJSON,
}
