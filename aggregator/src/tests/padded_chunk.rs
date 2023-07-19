use ark_std::{end_timer, start_timer, test_rng};
use halo2_proofs::poly::commitment::Params;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::{gen_pk, gen_snark_shplonk, verify_snark_shplonk, CircuitExt};

use crate::{chunk::padded_chunk_circuit::PaddedChunkHashCircuit, layer_0, ChunkHash};

#[test]
fn test_padded_chunk_prover() {
    // inner circuit: Mock circuit
    let k0 = 8;

    let mut rng = test_rng();
    let params = gen_srs(k0);

    let real_chunk = ChunkHash::mock_random_chunk_hash_for_testing(&mut rng);
    let pad_chunk = ChunkHash::padded_chunk_hash(&real_chunk);
    let circuit = PaddedChunkHashCircuit::new(pad_chunk);
    layer_0!(circuit, PaddedChunkHashCircuit, params, k0, path);
}
