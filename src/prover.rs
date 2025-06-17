use p521::ecdsa::{signature::Signer, Signature, SigningKey, signature::Verifier, VerifyingKey};
use rand_core::OsRng;
use tfhe::{ClientKey, CompressedCompactPublicKey, CompressedServerKey, FheInt64, FheBool};
use tfhe::safe_serialization::{safe_serialize, safe_deserialize};
use crate::addon;

//const fs = require('fs');
//const crypto = require("crypto");
//const { subtle } = globalThis.crypto;

// verify signed message sent by company with its public key
//async function signatureVerify(pubKey, signature, data) {
//    const ec = new TextEncoder();
//    const verified = await subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-384' }}, pubKey, signature, ec.encode(data));
//    return verified;
//}

pub fn signature_verify(pub_key: VerifyingKey, signature: Signature, data: &[u8]) -> bool {
    let verified = pub_key.verify(data, &signature).is_ok();
    return verified;
}

pub fn compute_result(evaluator: CompressedServerKey, cipher1: FheInt64, cipher2: FheInt64) -> FheBool{
    let comp_result = addon::less_than_equal(cipher1, cipher2, evaluator);
    return comp_result;
}

pub fn prover_encrypt(value: i64, encryptor: CompressedCompactPublicKey) -> FheInt64 {
    let cipher = addon::encrypt_public_key(value, encryptor);
    return cipher;
}

//async function proverCalculate(issuancePlaintext, signPublicKey, signature, thresholdCiphertext, encryptor, evaluator) {
//    let ver = await signatureVerify(signPublicKey, signature, thresholdCiphertext);
//    if (ver) {
//        let issuanceCiphertext = await proverEncrypt(issuancePlaintext, encryptor);
//        let result = await computeResult(evaluator, thresholdCiphertext, issuanceCiphertext);
//        return result;
//    }
//}

pub fn prover_calculate(issuance_plaintext: i64, sign_public_key: VerifyingKey, signature: Signature, threshold_ciphertext_ser: Vec<u8>, encryptor: CompressedCompactPublicKey, evaluator: CompressedServerKey) -> FheBool {
    let ver = signature_verify(sign_public_key, signature, &threshold_ciphertext_ser);
    println!("Verification result: {}", ver);
    assert!(ver);
    let threshold_ciphertext: FheInt64 = safe_deserialize(threshold_ciphertext_ser.as_slice(), 1 << 20).unwrap();
    let issuance_ciphertext = prover_encrypt(issuance_plaintext, encryptor);
    let result = compute_result(evaluator, threshold_ciphertext, issuance_ciphertext);
    return result;
}