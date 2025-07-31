use ream_pqc::PublicKey;
use serde::{Deserialize, Serialize};
use tree_hash_derive::TreeHash;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TreeHash)]
pub struct Validator {
    pub index: usize,
    pub public_key: PublicKey,
}
