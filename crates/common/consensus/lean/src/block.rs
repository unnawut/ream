use ethereum_hashing::hash;
use ream_pqc::PQSignature;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{
    VariableList,
    typenum::{
        U16777216, // 2**24
    },
};
use tree_hash_derive::TreeHash;

use crate::{Hash, vote::Vote};

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct SignedBlock {
    pub message: Block,
    pub signature: PQSignature,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode, Default, TreeHash)]
pub struct Block {
    pub slot: usize,
    pub proposer_index: usize,
    pub parent: Hash,
    pub votes: VariableList<Vote, U16777216>,
    pub state_root: Hash,
}

impl Block {
    pub fn compute_hash(&self) -> Hash {
        let serialized = serde_json::to_string(self).unwrap();
        Hash::from_slice(&hash(serialized.as_bytes()))
    }
}
