use alloy_primitives::Bytes;
use alloy_rpc_types::TransactionRequest;
use serde::Deserialize;

#[cfg(feature = "monad")]
use serde::Serialize;

/// Represents the options used in `anvil_reorg`
#[derive(Debug, Clone, Deserialize)]
pub struct ReorgOptions {
    // The depth of the reorg
    pub depth: u64,
    // List of transaction requests and blocks pairs to be mined into the new chain
    pub tx_block_pairs: Vec<(TransactionData, u64)>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
#[expect(clippy::large_enum_variant)]
pub enum TransactionData {
    JSON(TransactionRequest),
    Raw(Bytes),
}

/// The key a sender needs for a Monad encrypted transaction, as `monad_getEncryptionContext`
/// serves it.
#[cfg(feature = "monad")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionContext {
    /// The active encryption epoch.
    #[serde(with = "alloy_serde::quantity")]
    pub epoch: u64,
    /// The epoch's encryption key.
    pub encryption_key: Bytes,
    /// Whether the key is available to encrypt against.
    pub available: bool,
}
