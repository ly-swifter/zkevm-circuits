use std::{fs, path::Path, process};

use ark_std::{end_timer, start_timer, test_rng};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr, poly::commitment::Params};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::{gen_pk, gen_snark_shplonk, verify_snark_shplonk, CircuitExt};

use crate::{
    chunk::padded_chunk_circuit::PaddedChunkHashCircuit, layer_0, ChunkHash, CompressionCircuit,
};

#[test]
fn test_padded_chunk_prover() {
    env_logger::init();

    if std::path::Path::new("data").is_dir() {
        println!("data folder already exists\n");
    } else {
        println!("Generating data folder used for testing\n");
        std::fs::create_dir("data").unwrap();
    }

    let dir = format!("data/{}", process::id());
    let path = Path::new(dir.as_str());
    fs::create_dir(path).unwrap();

    let k0 = 8;
    let k1 = 22;

    let mut rng = test_rng();
    let params = gen_srs(k1);

    let real_chunk = ChunkHash::mock_random_chunk_hash_for_testing(&mut rng);
    let pad_chunk = ChunkHash::padded_chunk_hash(&real_chunk);
    let circuit = PaddedChunkHashCircuit::new(pad_chunk);
    let layer_0_snark = layer_0!(circuit, PaddedChunkHashCircuit, params, k0, path);

    std::env::set_var("COMPRESSION_CONFIG", "./configs/compression_wide.config");
    // layer 1 proof compression
    {
        let param = {
            let mut param = params;
            param.downsize(k1);
            param
        };
        let compression_circuit =
            CompressionCircuit::new(&param, layer_0_snark, true, &mut rng).unwrap();
        let instance = compression_circuit.instances();
        println!("instance length {:?}", instance[0].len());

        let mock_prover = MockProver::<Fr>::run(k1, &compression_circuit, instance).unwrap();

        mock_prover.assert_satisfied_par()
    }
}
