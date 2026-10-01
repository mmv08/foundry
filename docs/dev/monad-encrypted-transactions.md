# Monad encrypted transactions in Anvil

Experimental, for internal testing only. Monad Anvil can admit, mine and serve type `0x08`
encrypted transactions, so the `monad-ts` SDK can run against real EVM execution. The protocol
rules come from the encrypted transaction specification; this page covers what Anvil adds and where
it departs.

## Running it

Build Anvil with the `monad` feature and pass the flag:

```sh
cargo build -p anvil --features monad
./target/debug/anvil --network monad --monad.encrypted-transactions
```

Without the flag, Anvil behaves as before and rejects type `0x08`. The flag needs `--network monad`,
and Anvil refuses it with forking, both at startup and on `anvil_reset`.

## The key

The flag's optional value is the trapdoor of a test key, a scalar in `[1, q)`. It defaults to 42,
the trapdoor of the SDK's fixtures and mock, so the same fixtures replay against both.
`monad_getEncryptionContext` serves the key: `{ epoch, encryptionKey, available }`, with the one
epoch Anvil knows, 1, and the production batch size, 256.

**The test key is insecure.** Anvil holds the trapdoor and decrypts every transaction alone: there
is no threshold, no share release and no privacy. Anyone who knows the trapdoor can read every
encrypted transaction.

## What happens to a transaction

- **Admission.** `eth_sendRawTransaction` applies Anvil's usual checks, then those the type adds:
  `encrypted_fields` names one or more of `to`, `input` and `access_list` and nothing else, each
  encrypted field shows its placeholder, the epoch is 1, and the ciphertext's proof verifies
  against the associated data built from the chain ID, the recovered sender and the nonce.
- **Pending.** The pool keeps the ciphertext. Views show the placeholders with
  `decryptionStatus: "pending"`, and the pending block leaves encrypted transactions out, so no
  simulation sees the plaintext.
- **Mining.** The Monad block executor decrypts, decodes the payload all or nothing, and runs the
  restored fields as an EIP-1559 transaction from the recovered sender.
- **Queries.** Mined views show the restored `to`, `input` and `accessList` under the original
  hash and signature, with `decryptionStatus`. Receipts keep type `0x8` and add
  `decryptionStatus`, and `failureReason` when decryption failed. Raw-transaction queries return
  the signed bytes.

## Development defaults

These are not production fee rules.

- A transaction without a usable payload executes nothing. It uses its nonce and pays its gas limit
  at its effective gas price, as Monad charges every transaction. Its receipt has status 0, the gas
  limit as `gasUsed`, and a `failureReason` of `decryptionFailed` or `invalidPayload`.
- A transaction whose restored fields fail intrinsic gas, the calldata floor or the initcode limit
  pays the same charge. Its receipt reads like a revert with `decryptionStatus: "succeeded"`, and
  Anvil's log names the check.
- Encrypted transactions are priced as EIP-1559 transactions, with no surcharge.

## State

Anvil stores nothing new. The outcome of a mined encrypted transaction follows from its envelope,
its sender and the key, so mining computes it to decide what runs, and each view and receipt
computes it again. Snapshots, revert, reset, pruning and dumps therefore need no new hooks. The
costs: every view of a mined encrypted transaction repeats one decryption, and a dump shows the
restored fields only on a node started with the same trapdoor. Elsewhere its views show the
placeholders, and views and receipts carry no decryption status.

## Limits

- No encrypted `value`. The specification allows one, but Monad nodes do not accept it yet, so
  admission rejects it too.
- The associated data follows Monad nodes, not the specification: the RLP encodings of the chain
  ID, the sender and the nonce, one after another, in place of a digest of the whole transaction.
- No forking, fork replay or historical keys.
- Replays and simulations of signed encrypted transactions fail, among them
  `trace_replayTransaction`, `trace_rawTransaction`, `eth_callBundle` and block replays that
  include one. Traces recorded while mining, such as `debug_traceTransaction` serves, still work.
- One epoch, with no rotation or availability controls.
- No batch limit: Anvil decrypts one transaction at a time, and automine mines one per block.
- No impersonated or node-signed encrypted transactions; submit signed bytes.
- Anvil's generic checks treat this type as they treat the others: it accepts high-`s` signatures
  and ignores bytes after the envelope, which the specification rejects.
