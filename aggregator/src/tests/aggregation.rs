use std::{fs, path::Path, process};

use ark_std::{end_timer, start_timer, test_rng};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr, poly::commitment::Params};
use itertools::Itertools;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::{gen_pk, gen_snark_shplonk, verify_snark_shplonk, CircuitExt};

use crate::{
    aggregation::AggregationCircuit,
    batch::BatchHash,
    chunk::{mock_chunk_circuit::MockChunkCircuit, padded_chunk_circuit::PaddedChunkHashCircuit},
    compression_layer_snark,
    constants::MAX_AGG_SNARKS,
    layer_0, ChunkHash, CompressionCircuit,
};

// #[cfg(feature = "disable_proof_aggregation")]
#[test]
fn test_aggregation_circuit() {
    env_logger::init();

    // This set up requires one round of keccak for chunk's data hash
    let circuit = build_new_aggregation_circuit(2);
    let instance = circuit.instances();
    let mock_prover = MockProver::<Fr>::run(25, &circuit, instance).unwrap();
    mock_prover.assert_satisfied_par();
}

/// - Test full proof generation and verification.
/// - Test a same pk can be used for various number of chunk proofs.
#[ignore = "it takes too much time"]
#[test]
fn test_aggregation_circuit_full() {
    env_logger::init();
    let process_id = process::id();

    let dir = format!("data/{}", process_id);
    let path = Path::new(dir.as_str());
    fs::create_dir(path).unwrap();

    // This set up requires one round of keccak for chunk's data hash
    let circuit = build_new_aggregation_circuit(2);
    let instance = circuit.instances();
    let mock_prover = MockProver::<Fr>::run(25, &circuit, instance).unwrap();
    mock_prover.assert_satisfied_par();

    let mut rng = test_rng();
    let param = gen_srs(25);

    let pk = gen_pk(&param, &circuit, None);
    log::trace!("finished pk generation for circuit");

    let snark = gen_snark_shplonk(&param, &pk, circuit.clone(), &mut rng, None::<String>);
    log::trace!("finished snark generation for circuit");

    assert!(verify_snark_shplonk::<AggregationCircuit>(
        &param,
        snark,
        pk.get_vk()
    ));
    log::trace!("finished verification for circuit");

    // This set up requires two rounds of keccak for chunk's data hash
    let circuit = build_new_aggregation_circuit(5);
    let snark = gen_snark_shplonk(&param, &pk, circuit, &mut rng, None::<String>);
    log::trace!("finished snark generation for circuit");

    assert!(verify_snark_shplonk::<AggregationCircuit>(
        &param,
        snark,
        pk.get_vk()
    ));
    log::trace!("finished verification for circuit");
}

fn build_new_aggregation_circuit(num_chunks: usize) -> AggregationCircuit {
    std::env::set_var("COMPRESSION_CONFIG", "./configs/compression_wide.config");

    // inner circuit: Mock circuit
    let k0 = 8;
    let k1 = 23;

    let mut rng = test_rng();
    let params0 = gen_srs(k0);
    let params1 = gen_srs(k1);

    let mut chunks_without_padding = (0..num_chunks)
        .map(|_| ChunkHash::mock_random_chunk_hash_for_testing(&mut rng))
        .collect_vec();
    for i in 0..num_chunks - 1 {
        chunks_without_padding[i + 1].prev_state_root = chunks_without_padding[i].post_state_root;
    }
    // ==========================
    // real chunks
    // ==========================
    let real_snarks = {
        let circuits = chunks_without_padding
            .iter()
            .map(|&chunk| MockChunkCircuit::new(false, 0, chunk))
            .collect_vec();
        circuits
            .iter()
            .map(|&circuit| {
                let layer_0_snark = layer_0!(circuit, MockChunkCircuit, params0, k0, path);
                compression_layer_snark!(layer_0_snark, params1, k1, path, 1)
            })
            .collect_vec()
    };

    // ==========================
    // padded chunks
    // ==========================
    let padded_snarks = {
        let padded_chunk = ChunkHash::padded_chunk_hash(&chunks_without_padding[num_chunks - 1]);
        let circuit = PaddedChunkHashCircuit::new(padded_chunk);
        let layer_0_snark = layer_0!(circuit, PaddedChunkHashCircuit, params0, k0, path);
        let layer_1_snark = compression_layer_snark!(layer_0_snark, params1, k1, path, 1);
        vec![layer_1_snark; MAX_AGG_SNARKS - num_chunks]
    };

    // ==========================
    // batch
    // ==========================
    let batch_hash = BatchHash::construct(&chunks_without_padding);

    AggregationCircuit::new(
        &params1,
        [real_snarks, padded_snarks].concat().as_ref(),
        rng,
        batch_hash,
    )
    .unwrap()
}
