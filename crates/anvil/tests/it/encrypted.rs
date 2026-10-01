//! Monad encrypted transactions, type `0x08`, decrypted with the test key.

use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, address, b256, bytes, hex};
use alloy_provider::Provider;
use alloy_rpc_types::{AccessList, AccessListItem, anvil::Forking};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anvil::{NodeConfig, NodeHandle, eth::backend::btx::TestKey, spawn, try_spawn};
use anvil_core::types::EncryptionContext;
use foundry_common::provider::RetryProvider;
use foundry_primitives::TxEncrypted;
use serde_json::{Value, json};

/// The trapdoor of the SDK's fixtures and mock.
const TRAPDOOR: u64 = 42;
/// The one epoch Anvil serves.
const EPOCH: u64 = 1;
/// Every field nodes accept encrypted: `to`, `input` and `access_list`.
const ALL_FIELDS: u8 = 0x0d;
/// Stores its first calldata word in slot 0, accepting any value.
const STORE: Bytes = bytes!("60003560005500");
/// Deploys [`STORE`].
const DEPLOY_STORE: Bytes = bytes!("666000356000550060005260076019f3");
/// Reverts without data.
const REVERT: Bytes = bytes!("60006000fd");
const STORE_ADDRESS: Address = address!("0x0000000000000000000000000000000000005702");
const REVERT_ADDRESS: Address = address!("0x0000000000000000000000000000000000005703");
const RECIPIENT: Address = address!("0x0000000000000000000000000000000000005704");
const WORD: B256 = b256!("0x00000000000000000000000000000000000000000000000000000000000000ab");
const GAS: u64 = 100_000;
const MAX_FEE: u128 = 1_000_000_000_000;
const PRIORITY_FEE: u128 = 1_000_000_000;

/// Reads one of the SDK's fixtures (`monad-ts`), copied to `test-data/encrypted`.
fn fixture(name: &str) -> Value {
    let path = format!("{}/test-data/encrypted/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn fixture_bytes(value: &Value) -> Bytes {
    value.as_str().unwrap().parse().unwrap()
}

fn config() -> NodeConfig {
    NodeConfig::test_monad().with_monad_encryption_trapdoor(Some(U256::from(TRAPDOOR)))
}

fn key() -> TestKey {
    TestKey::new(U256::from(TRAPDOOR)).unwrap()
}

/// A transaction from `nonce` with fee caps that cover every test's base fee.
fn tx(chain_id: u64, nonce: u64, to: TxKind, value: u64, input: Bytes) -> TxEip1559 {
    TxEip1559 {
        chain_id,
        nonce,
        gas_limit: GAS,
        max_fee_per_gas: MAX_FEE,
        max_priority_fee_per_gas: PRIORITY_FEE,
        to,
        value: U256::from(value),
        input,
        access_list: AccessList::default(),
    }
}

/// Encrypts `payload` for `tx`, as `signer` sends it, under `key`.
fn ciphertext(tx: &TxEncrypted, payload: &[u8], signer: &PrivateKeySigner, key: &TestKey) -> Bytes {
    key.encrypt(payload, tx.associated_data(signer.address()).as_slice(), [1; 16]).into()
}

fn seal(tx: TxEncrypted, signer: &PrivateKeySigner) -> Bytes {
    let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    tx.into_signed(signature).encoded_2718().into()
}

/// Encrypts `payload` for the concealed `tx` under `key` and signs the result.
fn sign(tx: TxEncrypted, payload: &[u8], signer: &PrivateKeySigner, key: &TestKey) -> Bytes {
    seal(TxEncrypted { ciphertext: ciphertext(&tx, payload, signer, key), ..tx }, signer)
}

/// Builds a signed encrypted transaction that hides the fields of `tx` that `encrypted_fields`
/// names, as the SDK does.
fn encrypted(tx: TxEip1559, encrypted_fields: u8, signer: &PrivateKeySigner) -> Bytes {
    let (tx, payload) = TxEncrypted::from_eip1559(tx, EPOCH, encrypted_fields);
    sign(tx, &payload, signer, &key())
}

async fn request(provider: &RetryProvider, method: &'static str, params: Value) -> Value {
    provider.raw_request(method.into(), params).await.unwrap()
}

/// Submits a transaction without waiting for it to be mined, returning its hash.
async fn submit(provider: &RetryProvider, raw: &Bytes) -> Value {
    request(provider, "eth_sendRawTransaction", json!([raw])).await
}

/// Submits a transaction and returns its receipt once mined.
async fn send(provider: &RetryProvider, raw: &Bytes) -> Value {
    request(provider, "eth_sendRawTransactionSync", json!([raw])).await
}

async fn rejection(provider: &RetryProvider, raw: &Bytes) -> String {
    provider
        .raw_request::<_, Value>("eth_sendRawTransaction".into(), json!([raw]))
        .await
        .unwrap_err()
        .to_string()
}

async fn transaction(provider: &RetryProvider, hash: &Value) -> Value {
    request(provider, "eth_getTransactionByHash", json!([hash])).await
}

async fn balance(provider: &RetryProvider, address: Address) -> U256 {
    provider.get_balance(address).await.unwrap()
}

async fn setup(config: NodeConfig) -> (NodeHandle, RetryProvider, PrivateKeySigner, u64) {
    let (api, handle) = spawn(config).await;
    api.anvil_set_code(STORE_ADDRESS, STORE).await.unwrap();
    api.anvil_set_code(REVERT_ADDRESS, REVERT).await.unwrap();
    let provider = handle.http_provider();
    let signer = handle.dev_wallets().next().unwrap();
    let chain_id = provider.get_chain_id().await.unwrap();
    (handle, provider, signer, chain_id)
}

fn quantity(value: u64) -> Value {
    json!(format!("{value:#x}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn encryption_context_serves_the_fixture_key() {
    let (_api, handle) = spawn(config()).await;

    let context: EncryptionContext =
        handle.http_provider().raw_request("monad_getEncryptionContext".into(), ()).await.unwrap();

    // The SDK's first BTX vector uses the same trapdoor.
    let vector = &fixture("btx-vectors.json")[0];
    assert_eq!(vector["trapdoor"], format!("{TRAPDOOR:064x}"));
    let encryption_key = hex::decode(vector["encryptionKey"].as_str().unwrap()).unwrap();
    assert_eq!(
        context,
        EncryptionContext { epoch: EPOCH, encryption_key: encryption_key.into(), available: true }
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn encryption_context_needs_the_flag() {
    let (_api, handle) = spawn(NodeConfig::test_monad()).await;

    let err = handle
        .http_provider()
        .raw_request::<_, EncryptionContext>("monad_getEncryptionContext".into(), ())
        .await
        .unwrap_err()
        .to_string();

    assert!(err.contains("Not implemented"), "unexpected error: {err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_transactions_need_a_local_monad_chain() {
    async fn refusal(config: NodeConfig) -> String {
        let Err(err) = try_spawn(config).await else { panic!("expected Anvil to refuse") };
        err.to_string()
    }

    assert_eq!(
        refusal(NodeConfig::test().with_monad_encryption_trapdoor(Some(U256::from(TRAPDOOR))))
            .await,
        "encrypted transactions require `--network monad`"
    );
    assert_eq!(
        refusal(config().with_eth_rpc_url(Some("http://127.0.0.1:1"))).await,
        "encrypted transactions cannot be used with forking"
    );
    assert_eq!(
        refusal(NodeConfig::test_monad().with_monad_encryption_trapdoor(Some(U256::ZERO))).await,
        "the encryption trapdoor must be a scalar in [1, q)"
    );
}

/// The SDK's committed vector (`monad-ts`, `packages/viem/test/encrypted/vector.json`) runs end to
/// end: a creation with every field but `value` encrypted.
#[tokio::test(flavor = "multi_thread")]
async fn sdk_vector_executes_under_its_original_identity() {
    let vector = fixture("sdk-vector.json");
    let (api, handle) = spawn(config().with_chain_id(Some(1337u64)).with_base_fee(Some(1))).await;
    let provider = handle.http_provider();
    let sender: Address = vector["sender"].as_str().unwrap().parse().unwrap();
    api.anvil_set_balance(sender, U256::from(10).pow(U256::from(18))).await.unwrap();
    api.anvil_set_nonce(sender, U256::from(7)).await.unwrap();
    let signed = fixture_bytes(&vector["signed"]);

    let receipt = send(&provider, &signed).await;

    let hash = &receipt["transactionHash"];
    assert_eq!(*hash, vector["transactionHash"]);
    let created = sender.create(7);
    assert_eq!(receipt["status"], "0x1");
    assert_eq!(receipt["type"], "0x8");
    assert_eq!(receipt["decryptionStatus"], "succeeded");
    assert_eq!(receipt["contractAddress"], json!(created));
    assert_eq!(receipt["to"], Value::Null);
    let view = transaction(&provider, hash).await;
    assert_eq!(view["from"], json!(sender));
    assert_eq!(view["to"], Value::Null);
    assert_eq!(view["input"], "0x60006000");
    assert_eq!(view["ciphertext"], vector["ciphertext"]);
    let raw = request(&provider, "eth_getRawTransactionByHash", json!([hash])).await;
    assert_eq!(raw, vector["signed"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn transfers_calls_and_creations_change_state() {
    let (_handle, provider, signer, chain_id) = setup(config()).await;
    let sender = signer.address();

    let transfer = tx(chain_id, 0, TxKind::Call(RECIPIENT), 1_000, Bytes::new());
    assert_eq!(
        send(&provider, &encrypted(transfer, ALL_FIELDS, &signer)).await["to"],
        json!(RECIPIENT)
    );
    assert_eq!(balance(&provider, RECIPIENT).await, U256::from(1_000));

    let call = tx(chain_id, 1, TxKind::Call(STORE_ADDRESS), 0, WORD.into());
    send(&provider, &encrypted(call, ALL_FIELDS, &signer)).await;
    assert_eq!(
        provider.get_storage_at(STORE_ADDRESS, U256::ZERO).await.unwrap(),
        U256::from_be_bytes(WORD.0)
    );

    let creation = tx(chain_id, 2, TxKind::Create, 0, DEPLOY_STORE);
    let receipt = send(&provider, &encrypted(creation, ALL_FIELDS, &signer)).await;
    let created = sender.create(2);
    assert_eq!(receipt["status"], "0x1");
    assert_eq!(receipt["contractAddress"], json!(created));
    assert_eq!(receipt["to"], Value::Null);
    assert_eq!(provider.get_code_at(created).await.unwrap(), STORE);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_field_bit_restores_its_field() {
    let (_handle, provider, signer, chain_id) = setup(config()).await;
    let access_list =
        AccessList(vec![AccessListItem { address: STORE_ADDRESS, storage_keys: vec![B256::ZERO] }]);

    let mut nonce = 0;
    for encrypted_fields in (1..=ALL_FIELDS).filter(|mask| mask & !ALL_FIELDS == 0) {
        let word = B256::with_last_byte(encrypted_fields);
        let call = TxEip1559 {
            access_list: access_list.clone(),
            ..tx(chain_id, nonce, TxKind::Call(STORE_ADDRESS), nonce + 1, word.into())
        };
        let receipt = send(&provider, &encrypted(call, encrypted_fields, &signer)).await;

        let view = transaction(&provider, &receipt["transactionHash"]).await;
        assert_eq!(view["decryptionStatus"], "succeeded", "mask {encrypted_fields}");
        assert_eq!(
            view["encryptedFields"],
            quantity(encrypted_fields.into()),
            "mask {encrypted_fields}"
        );
        assert_eq!(view["to"], json!(STORE_ADDRESS), "mask {encrypted_fields}");
        assert_eq!(view["value"], quantity(nonce + 1), "mask {encrypted_fields}");
        assert_eq!(view["input"], json!(word), "mask {encrypted_fields}");
        assert_eq!(view["accessList"], json!(access_list), "mask {encrypted_fields}");
        assert_eq!(
            provider.get_storage_at(STORE_ADDRESS, U256::ZERO).await.unwrap(),
            U256::from_be_bytes(word.0),
            "mask {encrypted_fields}"
        );
        nonce += 1;
    }
    let sum = (1..=nonce).sum::<u64>();
    assert_eq!(balance(&provider, STORE_ADDRESS).await, U256::from(sum));
}

#[tokio::test(flavor = "multi_thread")]
async fn placeholder_payloads_decrypt_and_reverts_keep_their_status() {
    let (_handle, provider, signer, chain_id) = setup(config()).await;

    // A payload equal to the placeholders still decrypts: a call to the zero address.
    let noop = tx(chain_id, 0, TxKind::Call(Address::ZERO), 0, Bytes::new());
    let receipt = send(&provider, &encrypted(noop, ALL_FIELDS, &signer)).await;
    assert_eq!(receipt["status"], "0x1");
    assert_eq!(receipt["decryptionStatus"], "succeeded");

    // A revert is an ordinary execution failure, not a decryption failure.
    let call = tx(chain_id, 1, TxKind::Call(REVERT_ADDRESS), 0, Bytes::new());
    let receipt = send(&provider, &encrypted(call, ALL_FIELDS, &signer)).await;
    assert_eq!(receipt["status"], "0x0");
    assert_eq!(receipt["decryptionStatus"], "succeeded");
    assert_eq!(receipt.get("failureReason"), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn failures_are_included_charged_and_keep_the_nonce_sequence() {
    let (_handle, provider, signer, chain_id) = setup(config()).await;
    let sender = signer.address();
    let call = |nonce, input| tx(chain_id, nonce, TxKind::Call(STORE_ADDRESS), 0, input);

    // Encrypted under another key, which admission cannot tell: the proof binds the sender and
    // nonce, not the key.
    let (wrong_key, payload) = TxEncrypted::from_eip1559(call(0, WORD.into()), EPOCH, ALL_FIELDS);
    let wrong_key = sign(wrong_key, &payload, &signer, &TestKey::new(U256::from(43)).unwrap());
    // Encrypted correctly, but the payload does not hold the encrypted fields.
    let (malformed, _) = TxEncrypted::from_eip1559(call(1, WORD.into()), EPOCH, ALL_FIELDS);
    let malformed = sign(malformed, &hex::decode("c0").unwrap(), &signer, &key());
    // Decrypts, but its calldata costs more intrinsic gas than the gas limit allows.
    let late_check = TxEip1559 { gas_limit: 21_000, ..call(2, Bytes::from(vec![0xff; 64])) };
    let late_check = encrypted(late_check, ALL_FIELDS, &signer);

    let mut hashes = Vec::new();
    for (raw, gas, status, reason) in [
        (wrong_key, GAS, "failed", Some("decryptionFailed")),
        (malformed, GAS, "failed", Some("invalidPayload")),
        (late_check, 21_000, "succeeded", None),
    ] {
        let before = balance(&provider, sender).await;
        let receipt = send(&provider, &raw).await;
        hashes.push(receipt["transactionHash"].clone());
        assert_eq!(receipt["status"], "0x0", "{reason:?}");
        assert_eq!(receipt["decryptionStatus"], status, "{reason:?}");
        assert_eq!(receipt.get("failureReason").and_then(Value::as_str), reason);
        assert_eq!(receipt["gasUsed"], quantity(gas), "{reason:?}");
        let price: U256 = serde_json::from_value(receipt["effectiveGasPrice"].clone()).unwrap();
        assert_eq!(before - balance(&provider, sender).await, U256::from(gas) * price);
        assert_eq!(provider.get_storage_at(STORE_ADDRESS, U256::ZERO).await.unwrap(), U256::ZERO);
    }

    // No field is restored after a failed decryption.
    let view = transaction(&provider, &hashes[0]).await;
    assert_eq!(view["decryptionStatus"], "failed");
    assert_eq!(view["to"], json!(Address::ZERO));
    assert_eq!(view["input"], "0x");

    // The failures used their nonces, so the next transactions follow on.
    let receipt = send(&provider, &encrypted(call(3, WORD.into()), ALL_FIELDS, &signer)).await;
    assert_eq!(receipt["status"], "0x1");
    assert_eq!(provider.get_transaction_count(sender).await.unwrap(), 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn ordinary_and_encrypted_transactions_share_one_nonce_sequence() {
    let (_handle, provider, signer, chain_id) = setup(config().with_no_mining(true)).await;
    let sender = signer.address();

    let mut hashes = Vec::new();
    for nonce in 0..4 {
        let transfer = tx(chain_id, nonce, TxKind::Call(RECIPIENT), 1, Bytes::new());
        let raw = if nonce % 2 == 0 {
            let signature = signer.sign_hash_sync(&transfer.signature_hash()).unwrap();
            transfer.into_signed(signature).encoded_2718().into()
        } else {
            encrypted(transfer, ALL_FIELDS, &signer)
        };
        hashes.push(submit(&provider, &raw).await);
    }
    request(&provider, "evm_mine", json!([])).await;

    let block = request(&provider, "eth_getBlockByNumber", json!(["latest", true])).await;
    let transactions = block["transactions"].as_array().unwrap();
    assert_eq!(
        transactions.iter().map(|tx| &tx["hash"]).collect::<Vec<_>>(),
        hashes.iter().collect::<Vec<_>>()
    );
    assert_eq!(transactions[1]["type"], "0x8");
    assert_eq!(transactions[1]["to"], json!(RECIPIENT));
    assert_eq!(provider.get_transaction_count(sender).await.unwrap(), 4);
    assert_eq!(balance(&provider, RECIPIENT).await, U256::from(4));
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_views_stay_concealed_and_replays_are_refused() {
    let (_handle, provider, signer, chain_id) = setup(config().with_no_mining(true)).await;
    let call = tx(chain_id, 0, TxKind::Call(STORE_ADDRESS), 7, WORD.into());
    let raw = encrypted(call, ALL_FIELDS, &signer);
    let hash = submit(&provider, &raw).await;

    let pending = transaction(&provider, &hash).await;
    assert_eq!(pending["type"], "0x8");
    assert_eq!(pending["decryptionStatus"], "pending");
    assert_eq!(pending["blockNumber"], Value::Null);
    assert_eq!(pending["from"], json!(signer.address()));
    assert_eq!(pending["to"], json!(Address::ZERO));
    assert_eq!(pending["value"], "0x7");
    assert_eq!(pending["input"], "0x");
    assert_eq!(pending["epoch"], quantity(EPOCH));
    // The pending block leaves encrypted transactions out, so nothing executes them early.
    let block = request(&provider, "eth_getBlockByNumber", json!(["pending", false])).await;
    assert_eq!(block["transactions"], json!([]));
    assert_eq!(request(&provider, "eth_getRawTransactionByHash", json!([hash])).await, json!(raw));

    request(&provider, "evm_mine", json!([])).await;
    let mined = transaction(&provider, &hash).await;
    assert_eq!(mined["decryptionStatus"], "succeeded");
    assert_eq!(mined["to"], json!(STORE_ADDRESS));
    assert_eq!(mined["value"], "0x7");
    assert_eq!(mined["input"], json!(WORD));
    for field in ["hash", "from", "nonce", "r", "s", "yParity", "ciphertext"] {
        assert_eq!(mined[field], pending[field], "{field}");
    }
    assert_eq!(request(&provider, "eth_getRawTransactionByHash", json!([hash])).await, json!(raw));

    // Traces recorded while mining remain; replays would need the plaintext.
    let trace = request(&provider, "debug_traceTransaction", json!([hash, {}])).await;
    assert_eq!(trace["failed"], false);
    for (method, params) in [
        ("trace_replayTransaction", json!([hash, ["trace"]])),
        ("trace_rawTransaction", json!([raw, ["trace"]])),
    ] {
        let err = provider.raw_request::<_, Value>(method.into(), params).await.unwrap_err();
        let err = err.to_string();
        assert!(err.contains("encrypted transactions cannot be replayed"), "{method}: {err}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn admission_rejects_invalid_encrypted_transactions() {
    let (handle, provider, signer, chain_id) = setup(config()).await;
    let call = tx(chain_id, 0, TxKind::Call(STORE_ADDRESS), 0, WORD.into());
    let (concealed, payload) = TxEncrypted::from_eip1559(call.clone(), EPOCH, ALL_FIELDS);

    let mut tampered = ciphertext(&concealed, &payload, &signer, &key()).to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    let tampered = seal(TxEncrypted { ciphertext: tampered.into(), ..concealed.clone() }, &signer);
    let stale = sign(TxEncrypted { epoch: 2, ..concealed.clone() }, &payload, &signer, &key());
    let unassigned = sign(
        TxEncrypted { encrypted_fields: 0x10, ..concealed.clone() },
        &payload,
        &signer,
        &key(),
    );
    let encrypted_value = sign(
        TxEncrypted { encrypted_fields: 0x0f, ..concealed.clone() },
        &payload,
        &signer,
        &key(),
    );
    let revealed = sign(
        TxEncrypted { to: TxKind::Call(STORE_ADDRESS), ..concealed.clone() },
        &payload,
        &signer,
        &key(),
    );
    // Another sender reuses a ciphertext: the associated data binds it to its sender.
    let copied = TxEncrypted {
        ciphertext: ciphertext(&concealed, &payload, &signer, &key()),
        ..concealed.clone()
    };
    let copied = seal(copied, &handle.dev_wallets().nth(1).unwrap());

    for (raw, expected) in [
        (tampered, "invalid ciphertext: the client proof does not verify"),
        (stale, "encryption epoch 2 is not the active epoch 1"),
        (unassigned, "invalid encrypted transaction: encrypted_fields must name"),
        (encrypted_value, "invalid encrypted transaction: nodes do not accept an encrypted value"),
        (revealed, "invalid encrypted transaction: each encrypted field must show its placeholder"),
        (copied, "invalid ciphertext: the client proof does not verify"),
    ] {
        let err = rejection(&provider, &raw).await;
        assert!(err.contains(expected), "expected {expected:?}, got {err}");
    }

    for config in [NodeConfig::test_monad(), NodeConfig::test()] {
        let (_handle, provider, signer, chain_id) = setup(config).await;
        let call = tx(chain_id, 0, TxKind::Call(STORE_ADDRESS), 0, WORD.into());
        let err = rejection(&provider, &encrypted(call, ALL_FIELDS, &signer)).await;
        assert!(err.contains("encrypted transaction received but is not supported"), "{err}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshots_and_resets_need_no_new_state() {
    let (api, handle) = spawn(config()).await;
    let provider = handle.http_provider();
    let signer = handle.dev_wallets().next().unwrap();
    let chain_id = provider.get_chain_id().await.unwrap();
    let raw =
        encrypted(tx(chain_id, 0, TxKind::Call(RECIPIENT), 5, Bytes::new()), ALL_FIELDS, &signer);

    let snapshot = api.evm_snapshot().await.unwrap();
    let hash = send(&provider, &raw).await["transactionHash"].clone();
    assert!(api.evm_revert(snapshot).await.unwrap());
    assert_eq!(transaction(&provider, &hash).await, Value::Null);
    assert_eq!(balance(&provider, RECIPIENT).await, U256::ZERO);

    // The same bytes mine again under the same hash, after a revert and after a reset.
    for reset in [false, true] {
        if reset {
            api.anvil_reset(None).await.unwrap();
        }
        let receipt = send(&provider, &raw).await;
        assert_eq!(receipt["transactionHash"], hash);
        assert_eq!(receipt["decryptionStatus"], "succeeded");
        assert_eq!(balance(&provider, RECIPIENT).await, U256::from(5));
    }

    let forking =
        Forking { json_rpc_url: Some("http://127.0.0.1:1".to_string()), block_number: None };
    let err = api.anvil_reset(Some(forking)).await.unwrap_err().to_string();
    assert!(err.contains("encrypted transactions cannot be used with forking"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn dumps_show_restored_fields_under_the_same_key_only() {
    let (api, handle) = spawn(config()).await;
    let provider = handle.http_provider();
    let signer = handle.dev_wallets().next().unwrap();
    let chain_id = provider.get_chain_id().await.unwrap();
    let raw =
        encrypted(tx(chain_id, 0, TxKind::Call(RECIPIENT), 5, Bytes::new()), ALL_FIELDS, &signer);
    let hash = send(&provider, &raw).await["transactionHash"].clone();
    let state = api.anvil_dump_state(None).await.unwrap();

    for (config, restored) in [(config(), true), (NodeConfig::test_monad(), false)] {
        let (api, handle) = spawn(config).await;
        assert!(api.anvil_load_state(state.clone()).await.unwrap());
        let provider = handle.http_provider();

        let view = transaction(&provider, &hash).await;
        let receipt = request(&provider, "eth_getTransactionReceipt", json!([hash])).await;
        assert_eq!(receipt["status"], "0x1");
        assert_eq!(
            request(&provider, "eth_getRawTransactionByHash", json!([hash])).await,
            json!(raw)
        );
        assert_eq!(balance(&provider, RECIPIENT).await, U256::from(5));
        if restored {
            assert_eq!(
                (&view["to"], &view["decryptionStatus"]),
                (&json!(RECIPIENT), &json!("succeeded"))
            );
            assert_eq!(receipt["decryptionStatus"], "succeeded");
        } else {
            // Without the trapdoor the node cannot tell what the transaction did.
            assert_eq!((&view["to"], view.get("decryptionStatus")), (&json!(Address::ZERO), None));
            assert_eq!(receipt.get("decryptionStatus"), None);
        }
    }
}
