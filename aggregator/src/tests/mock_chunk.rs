use ark_std::test_rng;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use snark_verifier_sdk::CircuitExt;

use crate::{chunk::mock_chunk_circuit::MockChunkCircuit, constants::LOG_DEGREE};

#[test]
fn test_mock_chunk_prover() {
    let mut rng = test_rng();

    let circuit = MockChunkCircuit::random(&mut rng, true);
    let instance = circuit.instances();

    let mock_prover = MockProver::<Fr>::run(LOG_DEGREE, &circuit, instance).unwrap();

    mock_prover.assert_satisfied_par();

    let circuit = MockChunkCircuit::random(&mut rng, false);
    let instance = circuit.instances();

    let mock_prover = MockProver::<Fr>::run(LOG_DEGREE, &circuit, instance).unwrap();

    mock_prover.assert_satisfied_par();
}
