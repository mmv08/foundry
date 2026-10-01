//! A test-only BTX key for Monad encrypted transactions.
//!
//! INSECURE: one process holds the trapdoor and decrypts every ciphertext at once. There is no
//! threshold, no share release and no privacy. This ports the SDK's test decryptor (`monad-ts`,
//! `packages/btx/src/testing.ts`), which follows the BTX section of the encrypted transaction
//! specification, so Anvil opens the same ciphertexts the SDK and its mock produce.

use alloy_primitives::{U256, U512, uint};
use blst::{
    BLST_ERROR, blst_fp12, blst_p1, blst_p1_add_or_double, blst_p1_affine,
    blst_p1_affine_generator, blst_p1_affine_in_g1, blst_p1_affine_is_inf, blst_p1_compress,
    blst_p1_from_affine, blst_p1_generator, blst_p1_mult, blst_p1_to_affine, blst_p1_uncompress,
    blst_p2, blst_p2_affine, blst_p2_generator, blst_p2_mult, blst_p2_to_affine,
};

/// The order `q` of the BLS12-381 scalar field.
const Q: U256 = uint!(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001_U256);
/// Scalars below `q` fit in this many bits.
const SCALAR_BITS: usize = 255;
/// The production batch size `B_max`; the encryption key is `[τ^(B_max+1)]_T`.
const MAX_BATCH_SIZE: u64 = 256;
/// Byte length of a compressed G1 point.
const G1_SIZE: usize = 48;
/// Byte length of the seed `S` and the masked seed `C_1`.
const SEED_SIZE: usize = 16;
/// Byte length of a scalar.
const SCALAR_SIZE: usize = 32;
/// Byte length of the proof `π = (c, s)`.
const PROOF_SIZE: usize = 2 * SCALAR_SIZE;
/// Byte length of the `len(C_2)` prefix and of the plaintext-length prefix inside `C_2`.
const LENGTH_SIZE: usize = 4;
/// Byte length of an encoded G_T element.
const GT_SIZE: usize = 576;

/// Why admission rejects a ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BtxError {
    #[error("the ciphertext length is invalid")]
    InvalidLength,
    #[error("R is not a canonical G1 point in the prime-order subgroup")]
    InvalidPoint,
    #[error("a proof scalar is not below the group order")]
    InvalidScalar,
    #[error("R is the identity")]
    InvalidCiphertext,
    #[error("the client proof does not verify")]
    ClientNizkFailed,
}

/// An encryption key together with the trapdoor that decrypts under it.
pub struct TestKey {
    /// `h = g_2·τ^(B_max+1)`, the slot of the reference string that key generation withholds, so
    /// the pairing `e(R, h)` is the pad `ek·r`.
    hole: blst_p2_affine,
    /// `ek = e(g_1, h)`, in its canonical encoding.
    encryption_key: [u8; GT_SIZE],
}

impl TestKey {
    /// Derives the key from its trapdoor `τ`, which must be in `[1, q)`.
    pub fn new(trapdoor: U256) -> eyre::Result<Self> {
        eyre::ensure!(
            !trapdoor.is_zero() && trapdoor < Q,
            "the encryption trapdoor must be a scalar in [1, q)"
        );
        let power = trapdoor.pow_mod(U256::from(MAX_BATCH_SIZE + 1), Q).to_le_bytes::<32>();
        let mut hole = blst_p2::default();
        let mut hole_affine = blst_p2_affine::default();
        // SAFETY: blst reads `SCALAR_BITS` bits of the 32-byte little-endian scalar and writes
        // only to its output points.
        unsafe {
            blst_p2_mult(&raw mut hole, blst_p2_generator(), power.as_ptr(), SCALAR_BITS);
            blst_p2_to_affine(&raw mut hole_affine, &raw const hole);
        }
        // SAFETY: blst returns a pointer to a static point.
        let encryption_key = pairing(unsafe { &*blst_p1_affine_generator() }, &hole_affine);
        Ok(Self { hole: hole_affine, encryption_key })
    }

    /// Returns the encryption key a sender encrypts against.
    pub const fn encryption_key(&self) -> &[u8; GT_SIZE] {
        &self.encryption_key
    }

    /// Admits and decrypts one ciphertext, returning its plaintext, or `None` (⊥) when admission,
    /// the padding or the guardrail fails.
    pub fn decrypt(&self, ciphertext: &[u8], associated_data: &[u8]) -> Option<Vec<u8>> {
        let ciphertext = Ciphertext::admit(ciphertext, associated_data).ok()?;
        let pad = pairing(&ciphertext.commitment, &self.hole);
        let mut seed = h_kem(&pad, ciphertext.commitment_bytes, associated_data);
        xor(&mut seed, ciphertext.masked_seed);
        let mut padded = vec![0; ciphertext.masked_payload.len()];
        prg(&kdf(&seed, associated_data), &mut padded);
        xor(&mut padded, ciphertext.masked_payload);
        let plaintext = unpad(&padded)?;
        // P was unmasked with this seed, so the independent check is R = g_1·r. Once R matches,
        // the pairing pad equals ek·r and C_1 needs no second check.
        let r = expand_r(&h_rho(associated_data, &padded, &seed));
        (!r.is_zero() && mul(generator(), r) == from_affine(&ciphertext.commitment))
            .then(|| plaintext.to_vec())
    }

    /// Encrypts a payload under this key without padding, as a sender would, with randomness fixed
    /// by the seed. For tests: with the trapdoor, the pad `ek·r` is the pairing `e(R, h)`.
    #[doc(hidden)]
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
        seed: [u8; SEED_SIZE],
    ) -> Vec<u8> {
        let padded = [&(plaintext.len() as u32).to_be_bytes()[..], plaintext].concat();
        let r = expand_r(&h_rho(associated_data, &padded, &seed));
        let commitment = mul(generator(), r);
        let commitment_bytes = compress(&commitment);
        let mut masked_seed = h_kem(
            &pairing(&to_affine(&commitment), &self.hole),
            &commitment_bytes,
            associated_data,
        );
        xor(&mut masked_seed, &seed);
        let mut masked_payload = vec![0; padded.len()];
        prg(&kdf(&seed, associated_data), &mut masked_payload);
        xor(&mut masked_payload, &padded);
        // The Schnorr proof of knowledge of r, s = k - c·r, with a nonce k fixed by the seed.
        let nonce = expand_r(&h_rho(associated_data, &masked_payload, &seed));
        let c = challenge(
            &commitment_bytes,
            &compress(&mul(generator(), nonce)),
            &masked_seed,
            &masked_payload,
            associated_data,
        );
        let s = nonce.add_mod(Q - c.mul_mod(r, Q), Q);
        [
            &commitment_bytes[..],
            &masked_seed,
            &(masked_payload.len() as u32).to_be_bytes(),
            &masked_payload,
            &c.to_be_bytes::<SCALAR_SIZE>(),
            &s.to_be_bytes::<SCALAR_SIZE>(),
        ]
        .concat()
    }
}

/// Decodes a ciphertext and verifies its proof against the associated data, as admission does:
/// the specification's `deserialize_ciphertext` and `verify_ciphertext`.
pub fn admit(ciphertext: &[u8], associated_data: &[u8]) -> Result<(), BtxError> {
    Ciphertext::admit(ciphertext, associated_data).map(drop)
}

/// An admitted ciphertext `(R, C_1, C_2, π)`, borrowing its wire bytes.
struct Ciphertext<'a> {
    commitment: blst_p1_affine,
    commitment_bytes: &'a [u8; G1_SIZE],
    masked_seed: &'a [u8; SEED_SIZE],
    masked_payload: &'a [u8],
}

impl<'a> Ciphertext<'a> {
    /// Decodes the wire form `R ∥ C_1 ∥ u32be(len(C_2)) ∥ C_2 ∥ c ∥ s`, rejecting anything but its
    /// one canonical encoding, then checks `R` and the Schnorr proof.
    fn admit(bytes: &'a [u8], associated_data: &[u8]) -> Result<Self, BtxError> {
        let (commitment_bytes, rest) =
            bytes.split_first_chunk::<G1_SIZE>().ok_or(BtxError::InvalidLength)?;
        let (masked_seed, rest) =
            rest.split_first_chunk::<SEED_SIZE>().ok_or(BtxError::InvalidLength)?;
        let (length, rest) =
            rest.split_first_chunk::<LENGTH_SIZE>().ok_or(BtxError::InvalidLength)?;
        let (masked_payload, proof) =
            rest.split_last_chunk::<PROOF_SIZE>().ok_or(BtxError::InvalidLength)?;
        if masked_payload.len() != u32::from_be_bytes(*length) as usize {
            return Err(BtxError::InvalidLength);
        }

        let commitment = decode_g1(commitment_bytes)?;
        let c = decode_scalar(&proof[..SCALAR_SIZE])?;
        let s = decode_scalar(&proof[SCALAR_SIZE..])?;
        // SAFETY: blst only reads the decoded point.
        if unsafe { blst_p1_affine_is_inf(&raw const commitment) } {
            return Err(BtxError::InvalidCiphertext);
        }
        // T' = g_1·s + R·c reproduces the challenge only for a sender who knows r.
        let nonce_commitment = add(&mul(generator(), s), &mul(&from_affine(&commitment), c));
        let expected = challenge(
            commitment_bytes,
            &compress(&nonce_commitment),
            masked_seed,
            masked_payload,
            associated_data,
        );
        if expected != c {
            return Err(BtxError::ClientNizkFailed);
        }
        Ok(Self { commitment, commitment_bytes, masked_seed, masked_payload })
    }
}

/// Decodes a compressed G1 point, rejecting non-canonical encodings, points off the curve and
/// points outside the prime-order subgroup.
fn decode_g1(bytes: &[u8; G1_SIZE]) -> Result<blst_p1_affine, BtxError> {
    let mut point = blst_p1_affine::default();
    // SAFETY: blst reads 48 bytes and writes only to `point`.
    let valid = unsafe {
        blst_p1_uncompress(&raw mut point, bytes.as_ptr()) == BLST_ERROR::BLST_SUCCESS
            && blst_p1_affine_in_g1(&raw const point)
    };
    valid.then_some(point).ok_or(BtxError::InvalidPoint)
}

/// Decodes a 32-byte big-endian scalar, rejecting values at or above `q`.
fn decode_scalar(bytes: &[u8]) -> Result<U256, BtxError> {
    let scalar = U256::from_be_slice(bytes);
    (scalar < Q).then_some(scalar).ok_or(BtxError::InvalidScalar)
}

fn generator() -> &'static blst_p1 {
    // SAFETY: blst returns a pointer to a static point.
    unsafe { &*blst_p1_generator() }
}

fn to_affine(point: &blst_p1) -> blst_p1_affine {
    let mut out = blst_p1_affine::default();
    // SAFETY: blst reads `point` and writes only to `out`.
    unsafe { blst_p1_to_affine(&raw mut out, point) };
    out
}

fn from_affine(point: &blst_p1_affine) -> blst_p1 {
    let mut out = blst_p1::default();
    // SAFETY: blst reads `point` and writes only to `out`.
    unsafe { blst_p1_from_affine(&raw mut out, point) };
    out
}

/// Returns `point·scalar` for a scalar below `q`.
fn mul(point: &blst_p1, scalar: U256) -> blst_p1 {
    let mut out = blst_p1::default();
    // SAFETY: blst reads `SCALAR_BITS` bits of the 32-byte little-endian scalar and writes only
    // to `out`.
    unsafe { blst_p1_mult(&raw mut out, point, scalar.to_le_bytes::<32>().as_ptr(), SCALAR_BITS) };
    out
}

fn add(a: &blst_p1, b: &blst_p1) -> blst_p1 {
    let mut out = blst_p1::default();
    // SAFETY: blst reads both points and writes only to `out`.
    unsafe { blst_p1_add_or_double(&raw mut out, a, b) };
    out
}

/// Encodes a G1 point in its compressed form; the identity has one encoding.
fn compress(point: &blst_p1) -> [u8; G1_SIZE] {
    let mut out = [0; G1_SIZE];
    // SAFETY: blst writes exactly 48 bytes.
    unsafe { blst_p1_compress(out.as_mut_ptr(), point) };
    out
}

/// Returns `e(p, q)` in CatBLST's canonical order: Fp2 index, then Fp6 half, then Fp component,
/// each limb 48 big-endian bytes. The SDK encodes keys the same way.
fn pairing(p: &blst_p1_affine, q: &blst_p2_affine) -> [u8; GT_SIZE] {
    blst_fp12::miller_loop(q, p).final_exp().to_bendian()
}

/// Starts a Blake3 hash in derive-key mode; the context keys the hash and is not absorbed.
fn derive(context: &str) -> blake3::Hasher {
    blake3::Hasher::new_derive_key(context)
}

/// Absorbs a variable-length input as its 8-byte big-endian length, then its bytes.
fn absorb_lp(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn squeeze<const N: usize>(hasher: &blake3::Hasher) -> [u8; N] {
    let mut out = [0; N];
    hasher.finalize_xof().fill(&mut out);
    out
}

/// Reduces 64 big-endian bytes modulo `q`.
fn reduce(wide: [u8; 64]) -> U256 {
    (U512::from_be_bytes(wide) % U512::from(Q)).to()
}

/// `H_rho(AD, P, S)`: the coins that fix the encryption randomness.
fn h_rho(associated_data: &[u8], padded: &[u8], seed: &[u8; SEED_SIZE]) -> [u8; SEED_SIZE] {
    let mut hasher = derive("btx/coins/v1");
    absorb_lp(&mut hasher, associated_data);
    absorb_lp(&mut hasher, padded);
    squeeze(hasher.update(seed))
}

/// `expand_r`: the encryption scalar derived from the coins.
fn expand_r(coins: &[u8; SEED_SIZE]) -> U256 {
    reduce(squeeze(derive("btx/r/v1").update(coins)))
}

/// `H_kem(pad, R, AD)`: the mask that hides the seed.
fn h_kem(
    pad: &[u8; GT_SIZE],
    commitment: &[u8; G1_SIZE],
    associated_data: &[u8],
) -> [u8; SEED_SIZE] {
    let mut hasher = derive("btx/kem/v1");
    hasher.update(pad).update(commitment);
    absorb_lp(&mut hasher, associated_data);
    squeeze(&hasher)
}

/// `KDF(S, AD)`: the key of the stream that masks the padded plaintext.
fn kdf(seed: &[u8; SEED_SIZE], associated_data: &[u8]) -> [u8; 32] {
    let mut hasher = derive("btx/dem/v1");
    hasher.update(seed);
    absorb_lp(&mut hasher, associated_data);
    squeeze(&hasher)
}

/// `PRG(k, len)`: fills `out` with keyed Blake3 output.
fn prg(key: &[u8; 32], out: &mut [u8]) {
    blake3::Hasher::new_keyed(key).finalize_xof().fill(out);
}

/// `challenge(R, T, C_1, C_2, AD)`: the Fiat-Shamir scalar of the proof.
fn challenge(
    commitment: &[u8; G1_SIZE],
    nonce_commitment: &[u8; G1_SIZE],
    masked_seed: &[u8; SEED_SIZE],
    masked_payload: &[u8],
    associated_data: &[u8],
) -> U256 {
    let mut hasher = derive("btx/nizk/v1");
    hasher.update(commitment).update(nonce_commitment).update(masked_seed);
    absorb_lp(&mut hasher, masked_payload);
    absorb_lp(&mut hasher, associated_data);
    reduce(squeeze(&hasher))
}

/// Recovers `M` from `P = u32be(|M|) ∥ M ∥ 0x00…`, or `None` when the length overruns or the
/// filler is not zero.
fn unpad(padded: &[u8]) -> Option<&[u8]> {
    let (length, rest) = padded.split_first_chunk::<LENGTH_SIZE>()?;
    let (plaintext, filler) = rest.split_at_checked(u32::from_be_bytes(*length) as usize)?;
    filler.iter().all(|&byte| byte == 0).then_some(plaintext)
}

fn xor(out: &mut [u8], mask: &[u8]) {
    for (byte, mask) in out.iter_mut().zip(mask) {
        *byte ^= mask;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;
    use serde_json::Value;

    fn fixture(name: &str) -> Value {
        let path = format!("{}/test-data/encrypted/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn bytes(value: &Value) -> Vec<u8> {
        hex::decode(value.as_str().unwrap()).unwrap()
    }

    /// The SDK's BTX vectors (`monad-ts`, `packages/btx/tests/fixtures/vectors.json`).
    #[test]
    fn sdk_btx_vectors_decrypt() {
        for vector in fixture("btx-vectors.json").as_array().unwrap() {
            // Anvil's key uses the production batch size; one vector changes it.
            if vector["maxBatchSize"] != MAX_BATCH_SIZE {
                continue;
            }
            let name = &vector["name"];
            let key = TestKey::new(U256::from_be_slice(&bytes(&vector["trapdoor"]))).unwrap();
            assert_eq!(key.encryption_key().as_slice(), bytes(&vector["encryptionKey"]), "{name}");
            assert_eq!(
                key.decrypt(&bytes(&vector["ciphertext"]), &bytes(&vector["associatedData"])),
                Some(bytes(&vector["plaintext"])),
                "{name}"
            );
        }
    }

    /// The Rust node's admission vectors, as the SDK stores them
    /// (`monad-ts`, `packages/btx/tests/fixtures/rust-admission.json`).
    #[test]
    fn rust_admission_vectors() {
        let fixture = fixture("btx-rust-admission.json");
        for case in fixture["cases"].as_array().unwrap() {
            let mut ciphertext = bytes(&fixture["ciphertext"]);
            if let Some(truncate) = case["truncate"].as_u64() {
                ciphertext.truncate(ciphertext.len() - truncate as usize);
            }
            if let Some(append) = case.get("append") {
                ciphertext.extend(bytes(append));
            }
            if let Some(offset) = case["offset"].as_u64() {
                let replace = bytes(&case["replace"]);
                let offset = offset as usize;
                ciphertext[offset..offset + replace.len()].copy_from_slice(&replace);
            }
            let associated_data = bytes(case.get("ad").unwrap_or(&fixture["ad"]));
            let expected = match case["expect"].as_str().unwrap() {
                "ok" => Ok(()),
                "invalid_length" => Err(BtxError::InvalidLength),
                "invalid_point" => Err(BtxError::InvalidPoint),
                "identity_point" => Err(BtxError::InvalidCiphertext),
                "invalid_scalar" => Err(BtxError::InvalidScalar),
                "client_nizk_failed" => Err(BtxError::ClientNizkFailed),
                other => panic!("unknown expectation {other}"),
            };
            assert_eq!(admit(&ciphertext, &associated_data), expected, "{}", case["name"]);
        }
    }

    /// The SDK's transaction vector (`monad-ts`, `packages/viem/test/encrypted/vector.json`)
    /// decrypts under the mock's trapdoor, and under no other.
    #[test]
    fn sdk_transaction_vector_decrypts_under_its_key_only() {
        let vector = fixture("sdk-vector.json");
        let ciphertext = bytes(&vector["ciphertext"]);
        let associated_data = bytes(&vector["associatedData"]);
        let trapdoor: u64 = vector["trapdoor"].as_str().unwrap().parse().unwrap();

        let key = TestKey::new(U256::from(trapdoor)).unwrap();
        assert_eq!(key.decrypt(&ciphertext, &associated_data), Some(bytes(&vector["plaintext"])));
        let other = TestKey::new(U256::from(trapdoor + 1)).unwrap();
        assert_eq!(other.decrypt(&ciphertext, &associated_data), None);
        assert_eq!(key.decrypt(&ciphertext, &associated_data[1..]), None);
    }

    #[test]
    fn encrypted_payloads_decrypt_and_bind_their_associated_data() {
        let key = TestKey::new(U256::from(42)).unwrap();
        for plaintext in [&b""[..], b"payload", &[0; 300]] {
            let ciphertext = key.encrypt(plaintext, b"ad", [7; SEED_SIZE]);
            assert_eq!(admit(&ciphertext, b"ad"), Ok(()));
            assert_eq!(key.decrypt(&ciphertext, b"ad"), Some(plaintext.to_vec()));
            assert_eq!(admit(&ciphertext, b"other"), Err(BtxError::ClientNizkFailed));
        }
    }

    #[test]
    fn trapdoor_must_be_a_nonzero_scalar() {
        assert!(TestKey::new(U256::ZERO).is_err());
        assert!(TestKey::new(Q).is_err());
        assert!(TestKey::new(Q - U256::from(1)).is_ok());
    }

    #[test]
    fn unpad_requires_zero_filler_within_the_buffer() {
        assert_eq!(unpad(&hex!("00000002abcd0000")), Some(&hex!("abcd")[..]));
        assert_eq!(unpad(&hex!("00000002abcd0001")), None);
        assert_eq!(unpad(&hex!("00000005abcd")), None);
        assert_eq!(unpad(&hex!("000000")), None);
    }
}
