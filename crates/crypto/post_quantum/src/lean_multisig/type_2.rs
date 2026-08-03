use anyhow::{Result, anyhow};
use lean_multisig_type2::{
    MultiMessageAggregateSignature as MultiMessageAggregate,
    SingleMessageAggregateSignature as SingleMessageAggregate, XmssPublicKey, XmssSignature,
    aggregate_single_message_signatures, merge_single_message_aggregates, setup_prover,
    setup_verifier, split_multi_message_aggregate, verify_multi_message_aggregate,
    verify_single_message_aggregate,
};

use crate::leansig::{public_key::PublicKey, signature::Signature};

pub const LOG_INV_RATE: usize = 2;

pub fn type_2_setup() {
    setup_prover();
}

/// Initialize only the aggregation bytecode needed to *verify* aggregates.
/// Skips the prover-only DFT twiddle precomputation.
pub fn type_2_setup_verifier() {
    setup_verifier();
}

fn to_lib_public_key(public_key: &PublicKey) -> Result<XmssPublicKey> {
    public_key.as_lean_sig()
}

fn to_lib_signature(signature: &Signature) -> Result<XmssSignature> {
    signature.as_lean_sig()
}

pub fn type_1_from_wire(wire: &[u8], public_keys: &[PublicKey]) -> Result<SingleMessageAggregate> {
    let lib_public_keys = public_keys
        .iter()
        .map(to_lib_public_key)
        .collect::<Result<Vec<_>>>()?;
    SingleMessageAggregate::decompress_without_pubkeys(wire, lib_public_keys).ok_or_else(|| {
        anyhow!("Failed to decode single-message aggregate multi-signature from wire bytes")
    })
}

pub fn type_1_to_wire(proof: &SingleMessageAggregate) -> Vec<u8> {
    proof.compress_without_pubkeys()
}

pub fn type_1_aggregate(
    children: &[SingleMessageAggregate],
    raw_xmss: &[(PublicKey, Signature)],
    message: &[u8; 32],
    slot: u32,
) -> Result<SingleMessageAggregate> {
    type_2_setup();

    let raw: Vec<_> = raw_xmss
        .iter()
        .map(|(public_key, signature)| {
            Ok((to_lib_public_key(public_key)?, to_lib_signature(signature)?))
        })
        .collect::<Result<Vec<_>>>()?;

    aggregate_single_message_signatures(children, raw, *message, slot, LOG_INV_RATE)
        .map_err(|err| anyhow!("single-message aggregate aggregation failed: {err:?}"))
}

/// Union many child single-message aggregates into one via a BINARY TREE of
/// pairwise merges, instead of a single wide N-child [type_1_aggregate].
///
/// All children must be aggregates over the same `message`/`slot`; the result is
/// an equivalent single-message aggregate covering the union of their signers.
/// Because every node has fan-in 2 and each tier's merges are independent, the
/// tiers can be produced on separate machines (distributed proving): the tree's
/// critical path is `depth * one_2child_merge` (logarithmic in N), whereas a
/// single wide merge is linear in N. On one machine this does strictly more work
/// than the wide merge; the win comes from distributing the tiers (see the
/// aggregator gossip layer).
pub fn type_1_aggregate_tree(
    children: &[SingleMessageAggregate],
    message: &[u8; 32],
    slot: u32,
) -> Result<SingleMessageAggregate> {
    let mut level: Vec<SingleMessageAggregate> = match children {
        [] => return Err(anyhow!("type_1_aggregate_tree requires at least one child")),
        [single] => return Ok(single.clone()),
        _ => children.to_vec(),
    };

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(type_1_aggregate(
                    &[level[i].clone(), level[i + 1].clone()],
                    &[],
                    message,
                    slot,
                )?);
                i += 2;
            } else {
                // Odd node out carries up to the next tier unchanged.
                next.push(level[i].clone());
                i += 1;
            }
        }
        level = next;
    }

    level
        .pop()
        .ok_or_else(|| anyhow!("type_1_aggregate_tree produced no root"))
}

pub fn type_1_verify(proof: &SingleMessageAggregate) -> Result<()> {
    type_2_setup();
    verify_single_message_aggregate(proof)
        .map(|_| ())
        .map_err(|err| anyhow!("single-message aggregate verification failed: {err:?}"))
}

pub fn type_2_merge(parts: Vec<SingleMessageAggregate>) -> Result<MultiMessageAggregate> {
    type_2_setup();
    merge_single_message_aggregates(parts, LOG_INV_RATE)
        .map_err(|err| anyhow!("multi-message aggregate merge failed: {err:?}"))
}

pub fn type_2_to_wire(proof: &MultiMessageAggregate) -> Vec<u8> {
    proof.compress_without_pubkeys()
}

pub fn type_2_from_wire(
    wire: &[u8],
    public_keys_per_component: &[Vec<PublicKey>],
) -> Result<MultiMessageAggregate> {
    let lib_public_keys = public_keys_per_component
        .iter()
        .map(|public_keys| {
            public_keys
                .iter()
                .map(to_lib_public_key)
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()?;
    MultiMessageAggregate::decompress_without_pubkeys(wire, lib_public_keys).ok_or_else(|| {
        anyhow!("Failed to decode multi-message aggregate multi-signature from wire bytes")
    })
}

pub fn type_2_verify(proof: &MultiMessageAggregate) -> Result<()> {
    type_2_setup();
    verify_multi_message_aggregate(proof)
        .map(|_| ())
        .map_err(|err| anyhow!("multi-message aggregate verification failed: {err:?}"))
}

pub fn type_2_split(proof: MultiMessageAggregate, index: usize) -> Result<SingleMessageAggregate> {
    type_2_setup();
    split_multi_message_aggregate(proof, index, LOG_INV_RATE)
        .map_err(|err| anyhow!("multi-message aggregate split failed: {err:?}"))
}

pub fn type_2_verify_block(
    wire: &[u8],
    public_keys_per_component: &[Vec<PublicKey>],
    expected_bindings: &[([u8; 32], u32)],
) -> Result<()> {
    type_2_setup();

    let proof = type_2_from_wire(wire, public_keys_per_component)?;

    if proof.info.len() != expected_bindings.len() {
        return Err(anyhow!(
            "Block proof has {} components but {} bindings were expected",
            proof.info.len(),
            expected_bindings.len()
        ));
    }

    for (component, (message, slot)) in proof.info.iter().zip(expected_bindings.iter()) {
        if &component.without_pubkeys.message != message {
            return Err(anyhow!(
                "Block proof component message does not match block body"
            ));
        }
        if component.without_pubkeys.slot != *slot {
            return Err(anyhow!(
                "Block proof component slot does not match block body"
            ));
        }
    }

    verify_multi_message_aggregate(&proof)
        .map(|_| ())
        .map_err(|err| anyhow!("multi-message aggregate verification failed: {err:?}"))
}

#[cfg(test)]
mod tree_tests {
    use super::{type_1_aggregate, type_1_aggregate_tree, type_1_verify};
    use crate::leansig::private_key::PrivateKey;

    /// A binary-tree union of same-data fragments must produce a proof that
    /// verifies, exactly like the single wide merge — on ream's real leansig
    /// keys. (Structure differs, so we assert equivalence via verification, not
    /// wire equality.)
    #[test]
    fn tree_union_verifies_like_wide() {
        let message = [9u8; 32];
        let slot = 3u32;
        let epoch = slot; // aggregation binds sigs at epoch == slot

        // Build N leaves, each an aggregate over one validator's raw signature.
        let mut leaves = Vec::new();
        for _ in 0..5 {
            let (public_key, mut private_key) = PrivateKey::generate_key_pair(0, 16);
            let mut guard = 0;
            while !private_key.get_prepared_interval().contains(&(epoch as u64)) && guard < 64 {
                private_key.prepare_signature();
                guard += 1;
            }
            let signature = private_key.sign(&message, epoch).unwrap();
            leaves.push(type_1_aggregate(&[], &[(public_key, signature)], &message, slot).unwrap());
        }

        // 5 children exercises odd-node carry-up (5 -> 3 -> 2 -> 1).
        let wide = type_1_aggregate(&leaves, &[], &message, slot).unwrap();
        let tree = type_1_aggregate_tree(&leaves, &message, slot).unwrap();
        type_1_verify(&wide).expect("wide union verifies");
        type_1_verify(&tree).expect("tree union verifies");

        // Single-child tree is a no-op passthrough that still verifies.
        let one = type_1_aggregate_tree(&leaves[..1], &message, slot).unwrap();
        type_1_verify(&one).expect("single-child tree verifies");
    }
}
