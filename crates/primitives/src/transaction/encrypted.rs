//! Monad encrypted transactions, type `0x08`.

use alloy_consensus::{
    SignableTransaction, Transaction, TxEip1559, Typed2718,
    transaction::{RlpEcdsaDecodableTx, RlpEcdsaEncodableTx},
};
use alloy_eips::{eip2718::IsTyped2718, eip2930::AccessList, eip7702::SignedAuthorization};
use alloy_primitives::{Address, B256, Bytes, ChainId, Signature, TxKind, U256};
use alloy_rlp::{BufMut, Decodable, Encodable, Header};
use serde::{Deserialize, Serialize};

/// The EIP-2718 type byte of Monad encrypted transactions.
pub const ENCRYPTED_TX_TYPE_ID: u8 = 0x08;

/// `encrypted_fields` bits, assigned in field order.
const TO: u8 = 1 << 0;
const VALUE: u8 = 1 << 1;
const INPUT: u8 = 1 << 2;
const ACCESS_LIST: u8 = 1 << 3;
const ALL_FIELDS: u8 = TO | VALUE | INPUT | ACCESS_LIST;

/// The placeholder an encrypted `to` shows.
const PLACEHOLDER_TO: TxKind = TxKind::Call(Address::ZERO);

/// A Monad encrypted transaction, type `0x08`.
///
/// Each field that `encrypted_fields` names shows its placeholder: the zero address for `to`, zero
/// for `value`, and empty for `input` and `access_list`. The ciphertext carries their real values,
/// and the signature covers the whole transaction, ciphertext included.
///
/// Mined RPC views show the restored values in place of the placeholders, so deserialization
/// resets each encrypted field to its placeholder: the result is always the signed wire form.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(remote = "Self", rename_all = "camelCase")]
pub struct TxEncrypted {
    /// EIP-155 chain ID.
    #[serde(with = "alloy_serde::quantity")]
    pub chain_id: ChainId,
    /// The sender's nonce, never encrypted.
    #[serde(with = "alloy_serde::quantity")]
    pub nonce: u64,
    /// The EIP-1559 priority fee cap.
    #[serde(with = "alloy_serde::quantity")]
    pub max_priority_fee_per_gas: u128,
    /// The EIP-1559 fee cap.
    #[serde(with = "alloy_serde::quantity")]
    pub max_fee_per_gas: u128,
    /// The gas limit.
    #[serde(with = "alloy_serde::quantity", rename = "gas", alias = "gasLimit")]
    pub gas_limit: u64,
    /// The recipient, or contract creation. Encryptable as bit 0.
    #[serde(default)]
    pub to: TxKind,
    /// The value sent. The specification lets bit 1 encrypt it, but nodes do not accept that yet.
    pub value: U256,
    /// Calldata, or initcode for a creation. Encryptable as bit 2.
    pub input: Bytes,
    /// The access list. Encryptable as bit 3.
    #[serde(deserialize_with = "alloy_serde::null_as_default")]
    pub access_list: AccessList,
    /// The epoch whose key encrypted the ciphertext.
    #[serde(with = "alloy_serde::quantity")]
    pub epoch: u64,
    /// One bit for each encrypted field.
    #[serde(with = "alloy_serde::quantity")]
    pub encrypted_fields: u8,
    /// The BTX ciphertext of the encrypted fields' real values.
    pub ciphertext: Bytes,
}

impl TxEncrypted {
    /// Builds the transaction a sender encrypts, following the specification's construction.
    ///
    /// Returns `tx` with the fields that `encrypted_fields` names at their placeholders and an
    /// empty ciphertext, together with the payload to encrypt: one RLP list of those fields' real
    /// values, in field order.
    pub fn from_eip1559(tx: TxEip1559, epoch: u64, encrypted_fields: u8) -> (Self, Vec<u8>) {
        let tx = Self {
            chain_id: tx.chain_id,
            nonce: tx.nonce,
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
            max_fee_per_gas: tx.max_fee_per_gas,
            gas_limit: tx.gas_limit,
            to: tx.to,
            value: tx.value,
            input: tx.input,
            access_list: tx.access_list,
            epoch,
            encrypted_fields,
            ciphertext: Bytes::new(),
        };
        let mut fields = Vec::new();
        if tx.encrypts(TO) {
            tx.to.encode(&mut fields);
        }
        if tx.encrypts(VALUE) {
            tx.value.encode(&mut fields);
        }
        if tx.encrypts(INPUT) {
            tx.input.encode(&mut fields);
        }
        if tx.encrypts(ACCESS_LIST) {
            tx.access_list.encode(&mut fields);
        }
        let header = Header { list: true, payload_length: fields.len() };
        let mut payload = Vec::with_capacity(header.length_with_payload());
        header.encode(&mut payload);
        payload.extend(fields);
        (tx.conceal(), payload)
    }

    /// Returns the associated data that binds the ciphertext to the chain ID, the sender and the
    /// nonce: their RLP encodings, one after another.
    ///
    /// Monad nodes build it this way. The specification binds a digest of the whole transaction
    /// instead.
    pub fn associated_data(&self, sender: Address) -> Vec<u8> {
        let mut associated_data = Vec::new();
        self.chain_id.encode(&mut associated_data);
        sender.encode(&mut associated_data);
        self.nonce.encode(&mut associated_data);
        associated_data
    }

    /// Checks that `encrypted_fields` names one or more fields other than `value`, and that each
    /// shows its placeholder.
    pub fn validate_encrypted_fields(&self) -> Result<(), &'static str> {
        if self.encrypted_fields == 0 || self.encrypted_fields & !ALL_FIELDS != 0 {
            return Err("encrypted_fields must name one or more of to, input and access_list");
        }
        // The specification allows an encrypted value, but nodes do not accept one yet.
        if self.encrypts(VALUE) {
            return Err("nodes do not accept an encrypted value yet");
        }
        let placeholders = (!self.encrypts(TO) || self.to == PLACEHOLDER_TO)
            && (!self.encrypts(VALUE) || self.value.is_zero())
            && (!self.encrypts(INPUT) || self.input.is_empty())
            && (!self.encrypts(ACCESS_LIST) || self.access_list.is_empty());
        if !placeholders {
            return Err("each encrypted field must show its placeholder");
        }
        Ok(())
    }

    /// Returns the EIP-1559 transaction with the same fields, showing the placeholders.
    pub fn to_eip1559(&self) -> TxEip1559 {
        TxEip1559 {
            chain_id: self.chain_id,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            to: self.to,
            value: self.value,
            access_list: self.access_list.clone(),
            input: self.input.clone(),
        }
    }

    /// Restores the encrypted fields from a decrypted payload, all or nothing.
    ///
    /// The payload must be one RLP list, with no trailing bytes, holding exactly the fields that
    /// `encrypted_fields` names, in field order.
    pub fn decode_payload(&self, mut payload: &[u8]) -> alloy_rlp::Result<TxEip1559> {
        let mut fields = Header::decode_bytes(&mut payload, true)?;
        if !payload.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        let mut tx = self.to_eip1559();
        if self.encrypts(TO) {
            tx.to = Decodable::decode(&mut fields)?;
        }
        if self.encrypts(VALUE) {
            tx.value = Decodable::decode(&mut fields)?;
        }
        if self.encrypts(INPUT) {
            tx.input = Decodable::decode(&mut fields)?;
        }
        if self.encrypts(ACCESS_LIST) {
            tx.access_list = Decodable::decode(&mut fields)?;
        }
        if !fields.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        Ok(tx)
    }

    /// Resets each encrypted field to its placeholder.
    pub fn conceal(mut self) -> Self {
        if self.encrypts(TO) {
            self.to = PLACEHOLDER_TO;
        }
        if self.encrypts(VALUE) {
            self.value = U256::ZERO;
        }
        if self.encrypts(INPUT) {
            self.input = Bytes::new();
        }
        if self.encrypts(ACCESS_LIST) {
            self.access_list = AccessList::default();
        }
        self
    }

    const fn encrypts(&self, field: u8) -> bool {
        self.encrypted_fields & field != 0
    }
}

impl Serialize for TxEncrypted {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Self::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for TxEncrypted {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::deserialize(deserializer).map(Self::conceal)
    }
}

impl RlpEcdsaEncodableTx for TxEncrypted {
    fn rlp_encoded_fields_length(&self) -> usize {
        self.chain_id.length()
            + self.nonce.length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.input.0.length()
            + self.access_list.length()
            + self.epoch.length()
            + self.encrypted_fields.length()
            + self.ciphertext.0.length()
    }

    fn rlp_encode_fields(&self, out: &mut dyn BufMut) {
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.input.0.encode(out);
        self.access_list.encode(out);
        self.epoch.encode(out);
        self.encrypted_fields.encode(out);
        self.ciphertext.0.encode(out);
    }
}

impl RlpEcdsaDecodableTx for TxEncrypted {
    const DEFAULT_TX_TYPE: u8 = ENCRYPTED_TX_TYPE_ID;

    fn rlp_decode_fields(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self {
            chain_id: Decodable::decode(buf)?,
            nonce: Decodable::decode(buf)?,
            max_priority_fee_per_gas: Decodable::decode(buf)?,
            max_fee_per_gas: Decodable::decode(buf)?,
            gas_limit: Decodable::decode(buf)?,
            to: Decodable::decode(buf)?,
            value: Decodable::decode(buf)?,
            input: Decodable::decode(buf)?,
            access_list: Decodable::decode(buf)?,
            epoch: Decodable::decode(buf)?,
            encrypted_fields: Decodable::decode(buf)?,
            ciphertext: Decodable::decode(buf)?,
        })
    }
}

/// Returns the fields as they appear on the wire, so encrypted fields show their placeholders.
impl Transaction for TxEncrypted {
    fn chain_id(&self) -> Option<ChainId> {
        Some(self.chain_id)
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    fn gas_price(&self) -> Option<u128> {
        None
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        Some(self.max_priority_fee_per_gas)
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        None
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.max_priority_fee_per_gas
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        alloy_eips::eip1559::calc_effective_gas_price(
            self.max_fee_per_gas,
            self.max_priority_fee_per_gas,
            base_fee,
        )
    }

    fn is_dynamic_fee(&self) -> bool {
        true
    }

    fn kind(&self) -> TxKind {
        self.to
    }

    fn is_create(&self) -> bool {
        self.to.is_create()
    }

    fn value(&self) -> U256 {
        self.value
    }

    fn input(&self) -> &Bytes {
        &self.input
    }

    fn access_list(&self) -> Option<&AccessList> {
        Some(&self.access_list)
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        None
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        None
    }
}

impl Typed2718 for TxEncrypted {
    fn ty(&self) -> u8 {
        ENCRYPTED_TX_TYPE_ID
    }
}

impl IsTyped2718 for TxEncrypted {
    fn is_type(type_id: u8) -> bool {
        type_id == ENCRYPTED_TX_TYPE_ID
    }
}

impl SignableTransaction<Signature> for TxEncrypted {
    fn set_chain_id(&mut self, chain_id: ChainId) {
        self.chain_id = chain_id;
    }

    fn encode_for_signing(&self, out: &mut dyn BufMut) {
        out.put_u8(ENCRYPTED_TX_TYPE_ID);
        self.encode(out);
    }

    fn payload_len_for_signature(&self) -> usize {
        self.length() + 1
    }
}

impl Encodable for TxEncrypted {
    fn encode(&self, out: &mut dyn BufMut) {
        self.rlp_encode(out);
    }

    fn length(&self) -> usize {
        self.rlp_encoded_length()
    }
}

impl Decodable for TxEncrypted {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::rlp_decode(buf)
    }
}

/// How far an encrypted transaction has got, as queries report it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DecryptionStatus {
    /// Not yet mined, so not yet decrypted.
    Pending,
    /// Mined with its encrypted fields restored.
    Succeeded,
    /// Mined without a usable payload, so it executed nothing.
    Failed,
}

/// Why a mined encrypted transaction executed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DecryptionFailure {
    /// The ciphertext did not decrypt under the node's key.
    DecryptionFailed,
    /// The plaintext did not decode as the encrypted fields.
    InvalidPayload,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FoundryTxEnvelope;
    use alloy_consensus::{Signed, transaction::Recovered};
    use alloy_eips::{
        eip2718::{Decodable2718, Encodable2718},
        eip2930::AccessListItem,
    };
    use alloy_network::{
        AnyRpcTransaction, AnyTxEnvelope, AnyTxType, UnknownTxEnvelope, UnknownTypedTransaction,
    };
    use alloy_primitives::{address, b256, bytes, hex};
    use alloy_rpc_types::Transaction as RpcTransaction;
    use alloy_serde::{OtherFields, WithOtherFields};

    /// The Phase 2 SDK's committed vector (`monad-ts`, `packages/viem/test/encrypted/vector.json`):
    /// a creation with every field but `value` encrypted, signed with the key `0x01` repeated 32
    /// times.
    const SIGNED: &str = concat!(
        "08f901f2820539070103830186a09400000000000000000000000000000000000000008080c0010db90188af",
        "6eedd36eafd7cf71e0608b0fd9393f2333b89f1606e3ac28e79f841a4000354264f97e50b35f138d4e30d076",
        "a8bc02b7f78f535118f0f46debc6b644e7c65400000104d08b8078a3f1c288ae02d37a1988df970ab95afce4",
        "095d87d6def37642994103745cb4cbed5231b9301b49732596d91c98967814b5b95526a7ce86cc518fbcdfd9",
        "cf8b1ec8f055dec614efb783f352db46afb41f76611990d6c98601f658d74bc21e1290eae4a0bf2da99b1f0c",
        "768809c9e95191dc5cd1a426348fcf4e42a872bf438088c08e693f87c1dbdd4e10afd770ee1f63a5287d413a",
        "fa9be87cff8d9c2e14706315367ee978c90fa841f8c11551d6ae24cfc28eda75a3ec84bb916e2226bb791151",
        "375b1208afb46372f937220ab8d54180d7bc54de66ca21eb5f87f7c267dd13e680966d189dd80ae4ee1a034c",
        "ca55095b8bad21d66049d5ea933983c8977ed21eec7b40259e28f13f8aa08d443ea6829a5c18543afb8390cc",
        "9b4d5acff64cdc723b8ee880c3b908274a85599c979871cda50033efa6c630246102015696f15a80a0e20489",
        "972c03c57adbc2ff5543fb481c9b63604c5beefbfd872d73c75f06e298a01ad36ea7dfe74744c4ae1f10e50d",
        "e06d802eb7b4245f431685f97ac0dc382484",
    );
    const SENDER: Address = address!("0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1");

    fn vector() -> Signed<TxEncrypted> {
        let FoundryTxEnvelope::Encrypted(tx) =
            FoundryTxEnvelope::decode_2718(&mut hex::decode(SIGNED).unwrap().as_slice()).unwrap()
        else {
            panic!("expected an encrypted transaction")
        };
        tx
    }

    /// A call that sets every encryptable field.
    fn call() -> TxEip1559 {
        let target = Address::repeat_byte(0x11);
        TxEip1559 {
            chain_id: 1337,
            gas_limit: 100_000,
            max_fee_per_gas: 3,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(target),
            value: U256::from(123),
            input: bytes!("123400"),
            access_list: AccessList(vec![AccessListItem {
                address: target,
                storage_keys: vec![B256::repeat_byte(0x01)],
            }]),
            ..Default::default()
        }
    }

    /// Hides the fields that `encrypted_fields` names, returning the transaction and its payload.
    fn encrypt_fields(tx: &TxEip1559, encrypted_fields: u8) -> (TxEncrypted, Vec<u8>) {
        TxEncrypted::from_eip1559(tx.clone(), 1, encrypted_fields)
    }

    fn list(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        Header { list: true, payload_length: payload.len() }.encode(&mut out);
        out.extend_from_slice(payload);
        out
    }

    /// Builds a transaction view the way Anvil shows a mined encrypted transaction.
    fn rpc_view(signed: &Signed<TxEncrypted>, fields: OtherFields) -> AnyRpcTransaction {
        let envelope = AnyTxEnvelope::Unknown(UnknownTxEnvelope {
            hash: *signed.hash(),
            inner: UnknownTypedTransaction {
                ty: AnyTxType(ENCRYPTED_TX_TYPE_ID),
                fields,
                memo: Default::default(),
            },
        });
        AnyRpcTransaction::from(WithOtherFields::new(RpcTransaction {
            inner: Recovered::new_unchecked(envelope, SENDER),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            effective_gas_price: None,
            block_timestamp: None,
        }))
    }

    #[test]
    fn committed_vector_matches_the_sdk() {
        let signed = vector();
        let tx = signed.tx();

        assert_eq!(
            FoundryTxEnvelope::Encrypted(signed.clone()).encoded_2718(),
            hex::decode(SIGNED).unwrap()
        );
        assert_eq!(
            *signed.hash(),
            b256!("0x49fa983346fa3be15c124cecbeaf58924a8824d8c75dedc3ccaf71a130af09aa")
        );
        assert_eq!(
            signed.signature_hash(),
            b256!("0x51e5b3106a78cf162af7298b7beea2b810ffa4e666e55e64fca9ad03dbc10916")
        );
        assert_eq!(signed.recover_signer().unwrap(), SENDER);
        // RLP of chain ID 1337, the sender and nonce 7, one after another.
        assert_eq!(
            tx.associated_data(SENDER),
            hex!("820539941a642f0e3c3af545e7acbd38b07251b3990914f107")
        );
        assert_eq!(tx.validate_encrypted_fields(), Ok(()));

        let restored = tx.decode_payload(&hex!("c7808460006000c0")).unwrap();
        assert_eq!(restored.to, TxKind::Create);
        assert_eq!(restored.input, bytes!("60006000"));
        assert_eq!((restored.chain_id, restored.nonce, restored.gas_limit), (1337, 7, 100_000));
    }

    #[test]
    fn every_mask_restores_its_fields() {
        let call = call();
        for encrypted_fields in 1..=ALL_FIELDS {
            let (tx, payload) = TxEncrypted::from_eip1559(call.clone(), 1, encrypted_fields);
            // Nodes do not accept an encrypted value yet.
            let valid = encrypted_fields & VALUE == 0;
            assert_eq!(tx.validate_encrypted_fields().is_ok(), valid, "mask {encrypted_fields}");
            assert_eq!(tx.decode_payload(&payload).unwrap(), call, "mask {encrypted_fields}");
        }
    }

    #[test]
    fn payload_encoding_matches_the_sdk() {
        let call = call();
        let address = "11".repeat(20);
        assert_eq!(hex::encode(encrypt_fields(&call, 5).1), format!("d994{address}83123400"));
        assert_eq!(
            hex::encode(encrypt_fields(&call, 10).1),
            format!("f83b7bf838f794{address}e1a0{}", "01".repeat(32))
        );

        // A creation and a call to the zero address differ inside the payload.
        let tx = encrypt_fields(&TxEip1559::default(), ALL_FIELDS).0;
        assert_eq!(tx.decode_payload(&hex!("c4808080c0")).unwrap().to, TxKind::Create);
        assert_eq!(
            tx.decode_payload(&hex::decode(format!("d894{}8080c0", "00".repeat(20))).unwrap())
                .unwrap()
                .to,
            TxKind::Call(Address::ZERO)
        );
    }

    #[test]
    fn invalid_masks_and_placeholders_are_rejected() {
        let call = call();
        for encrypted_fields in [0, 0x10, 0x1f, 0x80] {
            assert!(encrypt_fields(&call, encrypted_fields).0.validate_encrypted_fields().is_err());
        }
        for encrypted_fields in [TO, INPUT, ACCESS_LIST] {
            let mut tx = encrypt_fields(&call, encrypted_fields).0;
            match encrypted_fields {
                TO => tx.to = TxKind::Create,
                INPUT => tx.input = bytes!("00"),
                _ => tx.access_list = AccessList(vec![AccessListItem::default()]),
            }
            assert!(tx.validate_encrypted_fields().is_err(), "mask {encrypted_fields}");
        }
    }

    #[test]
    fn payload_decoding_is_all_or_nothing() {
        let call = call();
        let (tx, payload) = encrypt_fields(&call, ALL_FIELDS);
        let fields = &payload[2..];
        let mut trailing = payload.clone();
        trailing.push(0x80);
        let mut extra = fields.to_vec();
        extra.push(0x80);
        let to_and_value = &encrypt_fields(&call, TO | VALUE).1[2..];

        for (name, bad) in [
            ("trailing bytes", trailing),
            ("an extra field", list(&extra)),
            ("a missing field", list(to_and_value)),
            ("a string, not a list", hex::decode("83123400").unwrap()),
            ("an empty payload", Vec::new()),
            ("a 19-byte recipient", list(&[&hex!("93")[..], &[0x11; 19]].concat())),
            ("a value with a leading zero", list(&[&fields[..21], &hex!("82007b")[..]].concat())),
            ("a non-canonical single byte", list(&[&fields[..21], &hex!("00")[..]].concat())),
            ("a list as input", list(&[&fields[..22], &hex!("c3123400")[..]].concat())),
        ] {
            assert!(tx.decode_payload(&bad).is_err(), "{name}");
        }
    }

    #[test]
    fn malformed_envelopes_are_rejected() {
        let signed = hex::decode(SIGNED).unwrap();
        let decode = |bytes: &[u8]| FoundryTxEnvelope::decode_2718(&mut &bytes[..]);
        assert!(decode(&signed[..signed.len() - 1]).is_err(), "truncated");

        let (tx, signature, _) = vector().into_parts();
        let mut fields = Vec::new();
        tx.rlp_encode_fields(&mut fields);
        let with_signature = |parity: &[u8], extra: &[u8]| {
            let mut payload = fields.clone();
            payload.extend_from_slice(extra);
            payload.extend_from_slice(parity);
            signature.r().encode(&mut payload);
            signature.s().encode(&mut payload);
            [&[ENCRYPTED_TX_TYPE_ID][..], &list(&payload)].concat()
        };
        let mut parity = Vec::new();
        signature.v().encode(&mut parity);
        assert_eq!(decode(&with_signature(&parity, &[])).unwrap().encoded_2718(), signed);
        assert!(decode(&with_signature(&hex!("02"), &[])).is_err(), "parity 2");
        assert!(decode(&with_signature(&parity, &hex!("80"))).is_err(), "an extra field");
        assert!(
            decode(&[&[ENCRYPTED_TX_TYPE_ID][..], &list(&fields)].concat()).is_err(),
            "unsigned"
        );
    }

    #[test]
    fn mined_view_round_trips_to_the_envelope() {
        let signed = vector();
        let mut fields = OtherFields::try_from(serde_json::to_value(&signed).unwrap()).unwrap();
        assert_eq!(fields.get("type"), None);
        assert_eq!(fields.get("gas"), Some(&serde_json::json!("0x186a0")));
        assert_eq!(fields.get("encryptedFields"), Some(&serde_json::json!("0xd")));

        // A mined view shows the restored fields in place of the placeholders.
        fields.insert("to".to_string(), serde_json::Value::Null);
        fields.insert("input".to_string(), serde_json::json!("0x60006000"));
        let view = rpc_view(&signed, fields);

        let expected = hex::decode(SIGNED).unwrap();
        assert_eq!(FoundryTxEnvelope::encode_rpc_2718(&view).unwrap(), expected);
        let json = serde_json::to_value(&view).unwrap();
        let envelope = FoundryTxEnvelope::try_from(
            serde_json::from_value::<AnyRpcTransaction>(json.clone()).unwrap(),
        )
        .unwrap();
        assert_eq!(envelope.encoded_2718(), expected);
        assert_eq!(envelope.hash(), *signed.hash());

        // A client that deserializes the view as the envelope gets the wire form too.
        let envelope = serde_json::from_value::<FoundryTxEnvelope>(json).unwrap();
        assert_eq!(envelope.encoded_2718(), expected);
        assert_eq!(envelope.recover().unwrap(), SENDER);
    }
}
