use std::time::Instant;
use tfhe::prelude::*;
use tfhe::{set_server_key, ClientKey, ConfigBuilder, FheInt64, FheBool, CompressedPublicKey, CompressedServerKey};

pub fn get_keys() -> (ClientKey, CompressedServerKey, CompressedPublicKey) {
    let now = Instant::now();
    let config = ConfigBuilder::default().build();
    let client_key= ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);
    let compressed_public_key = CompressedPublicKey::new(&client_key);
    let elapsed = now.elapsed();
    println!("get_keys elapsed: {:.2?}", elapsed);
    return (client_key, compressed_server_key, compressed_public_key);
}

pub fn encrypt(plain: i64, client_key: ClientKey) -> FheInt64 {
    let now = Instant::now();
    let cipher = FheInt64::encrypt(plain, &client_key);
    let elapsed = now.elapsed();
    println!("encrypt elapsed: {:.2?}", elapsed);
    return cipher;
}

pub fn encrypt_public_key(plain: i64, compressed_public_key: CompressedPublicKey) -> FheInt64 {
    let now = Instant::now();
    let public_key = compressed_public_key.decompress();
    let cipher = FheInt64::encrypt(plain, &public_key);
    let elapsed = now.elapsed();
    println!("encrypt_public_key elapsed: {:.2?}", elapsed);
    return cipher;
}

pub fn encrypt_bool_public_key(plain: bool, compressed_public_key:CompressedPublicKey) -> FheBool {
    let now = Instant::now();
    let public_key = compressed_public_key.decompress();
    let cipher = FheBool::encrypt(plain, &public_key);
    let elapsed = now.elapsed();
    println!("encrypt_bool_public_key elapsed: {:.2?}", elapsed);
    return cipher;
}

pub fn greater_than(cipher_a: FheInt64, cipher_b: FheInt64, compressed_server_key: CompressedServerKey) -> FheBool {
    let now = Instant::now();
    //let gpu_key = compressed_server_key.decompress_to_gpu();
    let server_key = compressed_server_key.decompress();
    //set_server_key(gpu_key);
    set_server_key(server_key);

    let gtresult = cipher_a.gt(cipher_b.clone());
    let elapsed = now.elapsed();
    println!("greater_than elapsed: {:.2?}", elapsed);
    return gtresult;
}

pub fn less_than_equal(cipher_a: FheInt64, cipher_b: FheInt64, compressed_server_key:CompressedServerKey) -> FheBool {
    let now = Instant::now();
    //let gpu_key = compressed_server_key.decompress_to_gpu();
    let server_key = compressed_server_key.decompress();
    //set_server_key(gpu_key);
    set_server_key(server_key);

    let leresult = cipher_a.le(cipher_b.clone());
    let elapsed = now.elapsed();
    println!("less_than_equal elapsed: {:.2?}", elapsed);
    return leresult;
}

pub fn flip_bit(cipher_a: FheBool, compressed_server_key:CompressedServerKey) -> FheBool{
    let now = Instant::now();
    //let gpu_key = compressed_server_key.decompress_to_gpu();
    let server_key = compressed_server_key.decompress();
    //set_server_key(gpu_key);
    set_server_key(server_key);

    let flipresult = !cipher_a;
    let elapsed = now.elapsed();
    println!("flip_bit elapsed: {:.2?}", elapsed);
    return flipresult;
}

pub fn decrypt(cipher: FheBool, client_key:ClientKey) -> bool {
    let now = Instant::now();
    let plain: bool = cipher.decrypt(&client_key);
    let elapsed = now.elapsed();
    println!("decrypt elapsed: {:.2?}", elapsed);
    return plain;
}