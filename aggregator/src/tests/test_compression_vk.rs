use std::{fs, path::Path, process};

use ark_std::{end_timer, start_timer, test_rng};
use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::commitment::Params,
};
use snark_verifier::{
    loader::halo2::halo2_ecc::halo2_base::{halo2_proofs, utils::fs::gen_srs},
    pcs::kzg::{Bdfg21, Kzg},
};
use snark_verifier_sdk::{
    evm_verify, gen_evm_proof_shplonk, gen_evm_verifier, gen_pk, gen_snark_shplonk,
    verify_snark_shplonk, CircuitExt,
};

use crate::{
    chunk::{mock_chunk_circuit::MockChunkCircuit, padded_chunk_circuit::PaddedChunkHashCircuit},
    compression_layer_evm, compression_layer_snark, layer_0, ChunkHash, CompressionCircuit,
};

#[test]
fn test_two_layer_proof_compression() {
    env_logger::init();
    let invalid_vk = mock_hash_2_layer_proof_compression();
    padded_hash_2_layer_proof_compression(&invalid_vk);
}

fn padded_hash_2_layer_proof_compression(invalid_vk: &VerifyingKey<G1Affine>) {
    if std::path::Path::new("data").is_dir() {
        println!("data folder already exists\n");
    } else {
        println!("Generating data folder used for testing\n");
        std::fs::create_dir("data").unwrap();
    }

    let dir = format!("data/padded_{}", process::id());
    let path = Path::new(dir.as_str());
    fs::create_dir(path).unwrap();

    let k0 = 19;
    let k1 = 25;
    let k2 = 25;

    let mut rng = test_rng();
    let layer_2_params = gen_srs(k2);

    let real_chunk = ChunkHash::mock_random_chunk_hash_for_testing(&mut rng);
    let pad_chunk = ChunkHash::padded_chunk_hash(&real_chunk);
    let circuit = PaddedChunkHashCircuit::new(pad_chunk);
    let layer_0_snark = layer_0!(circuit, PaddedChunkHashCircuit, layer_2_params, k0, path);

    std::env::set_var("COMPRESSION_CONFIG", "./configs/compression_wide.config");
    let layer_1_snark = compression_layer_snark!(layer_0_snark, layer_2_params, k1, path, 1);

    std::env::set_var("COMPRESSION_CONFIG", "./configs/compression_thin.config");

    let param = {
        let mut param = layer_2_params.clone();
        param.downsize(k2);
        param
    };

    let mut rng = test_rng();

    let compression_circuit =
        CompressionCircuit::new(&param, layer_1_snark, false, &mut rng).unwrap();

    let pk = gen_pk(&param, &compression_circuit, None);
    let vk = pk.get_vk();
    println!("vk: {:?}", vk);

    let snark = gen_snark_shplonk(&param, &pk, circuit, &mut rng, None::<String>);
    println!(
        "verify with valid vk: {}",
        verify_snark_shplonk::<CompressionCircuit>(&param, snark.clone(), vk)
    );
    println!(
        "verify with invalid vk: {}",
        verify_snark_shplonk::<CompressionCircuit>(&param, snark, invalid_vk)
    );
}

fn mock_hash_2_layer_proof_compression() -> VerifyingKey<G1Affine> {
    if std::path::Path::new("data").is_dir() {
        println!("data folder already exists\n");
    } else {
        println!("Generating data folder used for testing\n");
        std::fs::create_dir("data").unwrap();
    }

    let dir = format!("data/mock_{}", process::id());
    let path = Path::new(dir.as_str());
    fs::create_dir(path).unwrap();

    let k0 = 19;
    let k1 = 25;
    let k2 = 25;

    let mut rng = test_rng();
    let layer_2_params = gen_srs(k2);

    let circuit = MockChunkCircuit::random(&mut rng, true);
    let layer_0_snark = layer_0!(circuit, MockChunkCircuit, layer_2_params, k0, path);

    std::env::set_var("COMPRESSION_CONFIG", "./configs/compression_wide.config");
    let layer_1_snark = compression_layer_snark!(layer_0_snark, layer_2_params, k1, path, 1);

    std::env::set_var("COMPRESSION_CONFIG", "./configs/compression_thin.config");

    let param = {
        let mut param = layer_2_params.clone();
        param.downsize(k2);
        param
    };

    let mut rng = test_rng();

    let compression_circuit =
        CompressionCircuit::new(&param, layer_1_snark, false, &mut rng).unwrap();

    let pk = gen_pk(&param, &compression_circuit, None);
    let vk = pk.get_vk();
    println!("vk: {:?}", vk);
    vk.clone()
}
