use era_crypto::certificate::EraKeyPair;
use era_crypto::hybrid_certificate::HybridKeyPair;
use era_crypto::pem_support::{
    export_hybrid_private_key_as_pem, export_hybrid_public_key_as_pem, export_private_key_as_pem,
    export_public_key_as_pem,
};
use std::fs;
use std::path::PathBuf;

#[test]
fn generate_valid_keys() {
    let keypair = EraKeyPair::generate().expect("Failed to generate");
    let cert = keypair.certificate();

    let public_pem = export_public_key_as_pem(&cert).expect("Export public");
    let private_pem = export_private_key_as_pem(&keypair).expect("Export private");

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let bench_data = root.join("bench_data");

    if !bench_data.exists() {
        fs::create_dir_all(&bench_data).expect("Create dir");
    }

    fs::write(bench_data.join("public_new.pem"), public_pem).expect("Write public");
    fs::write(bench_data.join("private_new.pem"), private_pem).expect("Write private");

    println!("Generated keys in {:?}", bench_data);
}

#[test]
fn generate_valid_hybrid_keys() {
    let keypair = HybridKeyPair::generate();
    let cert = keypair.certificate();

    let public_pem = export_hybrid_public_key_as_pem(&cert).expect("Export hybrid public");
    let private_pem = export_hybrid_private_key_as_pem(&keypair).expect("Export hybrid private");

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let bench_data = root.join("bench_data");

    if !bench_data.exists() {
        fs::create_dir_all(&bench_data).expect("Create dir");
    }

    fs::write(bench_data.join("hybrid_public.pem"), public_pem).expect("Write hybrid public");
    fs::write(bench_data.join("hybrid_private.pem"), private_pem).expect("Write hybrid private");

    println!("Generated hybrid keys in {:?}", bench_data);
}
