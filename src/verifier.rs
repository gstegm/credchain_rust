use std::fs;
use p521::ecdsa::{signature::Signer, Signature, SigningKey, signature::Verifier, VerifyingKey};
use p521::EncodedPoint;
use rand::rngs::OsRng;
use tfhe::{ClientKey, CompressedPublicKey, CompressedServerKey, FheInt64, FheBool};
use tfhe::safe_serialization::{safe_serialize, safe_deserialize};
use serde::{Deserialize, Serialize};
use serde_json::Result;
use crate::{addon, verifier};

pub fn generate_encryption_keys() -> (ClientKey, CompressedServerKey, CompressedPublicKey){
    let (decryptor, evaluator, encryptor) = addon::get_keys();
    return (decryptor, evaluator, encryptor);
}

// function to generate signing keys
//async function generateSignatureKeys(namedCurve = 'P-521') {
//    const { publicKey, privateKey } = await subtle.generateKey({
//      name: 'ECDSA',
//      namedCurve,
//    }, true, ['sign', 'verify']);
//    const keys = {
//        publicKey: publicKey,
//        privateKey: privateKey,
//    }
//    return keys;
//  }

pub fn generate_signature_keys () -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
    let verifying_key = VerifyingKey::from(&signing_key); // Serialize with `::to_encoded_point()`
    return (signing_key, verifying_key)
}

// function to sign a message (ciphertext)
//async function verifierSign(key, data) {
//    const ec = new TextEncoder();
//    const signature = await subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-384' }}, key, ec.encode(data))
//    return signature;
//}

pub fn verifier_sign (key: SigningKey, data: &[u8]) -> Signature {
    let signature:Signature = key.sign(data);
    return signature;
}

pub fn verifier_encrypt(value: i64, decryptor:ClientKey) -> FheInt64 {
    let cipher = addon::encrypt(value, decryptor);
    return cipher;
}


pub fn verifier_decrypt(value: FheBool, decryptor: ClientKey) -> bool {
    let result_student = addon::decrypt(value, decryptor);
    println!("Decoded Result: {}", result_student);
    if (result_student) {
        println!("VALID Issuance Date");
        return true;
    } else {
        println!("INVALID Issuance Date");
        return false;
    }
}

// wrapper functions
//async function verifierSetUp(thresholdPlaintext) {
//    let instances = await generateEncryptionKeys();
//    let signingKeys = await generateSignatureKeys();
//
//    let encryptor = instances.encryptor;
//    let decryptor = instances.decryptor;
//    let evaluator  = instances.evaluator;
//
//    let signPublicKey = signingKeys.publicKey;
//    let signPrivateKey = signingKeys.privateKey;
//
//    let thresholdCiphertext = await verifierEncrypt(thresholdPlaintext, encryptor);
//    let signature = await verifierSign(signPrivateKey, thresholdCiphertext);
//
//    let verifierSetUpData =  {
//        signPublicKey: signPublicKey,
//        verifierSignature: signature,
//        thresholdCiphertext: thresholdCiphertext,
//        verifierEncryptor: encryptor,
//        verifierDecryptor: decryptor,
//        proverEvaluator: evaluator,
//    }
//
//    // Save the results to file
//    fs.writeFileSync('./HomomorphicEncryption/verifierSetupData.json', JSON.stringify(verifierSetUpData));
//
//    return verifierSetUpData;
//}

#[derive(Serialize, Deserialize)]
struct VerifierSetupData {
    verifying_key_enc: EncodedPoint, 
    signature: Signature, 
    threshold_ciphertext_ser: Vec<u8>, 
    encryptor: CompressedPublicKey, 
    decryptor: ClientKey, 
    evaluator: CompressedServerKey,
}

pub fn verifier_set_up(threshold_plaintext: i64) -> (VerifyingKey, Signature, Vec<u8>, CompressedPublicKey, ClientKey, CompressedServerKey) {
    let (decryptor, evaluator, encryptor) = generate_encryption_keys();
    let (signing_key, verifying_key) = generate_signature_keys();
    let verifying_key_enc = verifying_key.to_encoded_point(false);

    let threshold_ciphertext = verifier_encrypt(threshold_plaintext, decryptor.clone());

    let mut threshold_ciphertext_ser = vec![];
    safe_serialize(&threshold_ciphertext, &mut threshold_ciphertext_ser, 1 << 20).unwrap();
    let signature: Signature = signing_key.sign(&threshold_ciphertext_ser);
    // write to file system here

    let verifierSetupData = VerifierSetupData {
        verifying_key_enc: verifying_key_enc,
        signature: signature, 
        threshold_ciphertext_ser: threshold_ciphertext_ser.clone(), 
        encryptor: encryptor.clone(), 
        decryptor: decryptor.clone(), 
        evaluator: evaluator.clone(),
    };

    let j = serde_json::to_string(&verifierSetupData).unwrap();
    fs::write("verifierSetupData.json", j);
    return (verifying_key, signature, threshold_ciphertext_ser, encryptor, decryptor, evaluator);
}

//async function verifierProve(proverResult, decryptor) {
//    let result = await verifierDecrypt(proverResult, decryptor);
//    return result;
//}

pub fn verifier_prove(prover_result: FheBool, decryptor: ClientKey) -> bool {
    let result = verifier_decrypt(prover_result, decryptor);
    return result;
}