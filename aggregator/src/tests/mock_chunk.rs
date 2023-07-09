use std::iter;

use ark_std::test_rng;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base;
use snark_verifier_sdk::CircuitExt;

use crate::{constants::ACC_LEN, rlc::RlcConfig, ChunkHash, LOG_DEGREE};

mod circuit;
mod circuit_ext;

#[derive(Debug, Default, Clone, Copy)]
/// A mock chunk circuit
///
/// This mock chunk circuit simulates a zkEVM circuit.
/// It's public inputs consists of 64 elements:
/// - data hash
/// - public input hash
pub(crate) struct MockChunkCircuit {
    pub(crate) is_fresh: bool,
    pub(crate) chain_id: u64,
    pub(crate) chunk: ChunkHash,
}

impl MockChunkCircuit {
    #[allow(dead_code)]
    pub(crate) fn new(is_fresh: bool, chain_id: u64, chunk: ChunkHash) -> Self {
        MockChunkCircuit {
            is_fresh,
            chain_id,
            chunk,
        }
    }
}

impl MockChunkCircuit {
    pub(crate) fn random<R: rand::RngCore>(r: &mut R, is_fresh: bool) -> Self {
        Self {
            is_fresh,
            chain_id: 0,
            chunk: ChunkHash::mock_random_chunk_hash_for_testing(r),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct MockConfig {
    pub(crate) rlc_config: RlcConfig,
    /// Instance for public input; stores
    /// - accumulator from aggregation (12 elements); if not fresh
    /// - batch_public_input_hash (32 elements)
    pub(crate) instance: Column<Instance>,
}

impl Circuit<Fr> for MockChunkCircuit {
    type Config = MockConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        meta.set_minimum_degree(4);
        let rlc_config = RlcConfig::configure(meta);
        // Instance column stores public input column
        // - the accumulator
        // - the batch public input hash
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self::Config {
            rlc_config,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;
        let mut cells = vec![];

        layouter.assign_region(
            || "mock circuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let acc_len = if self.is_fresh { 0 } else { ACC_LEN };
                let mut index = 0;
                for (_i, byte) in iter::repeat(0)
                    .take(acc_len)
                    .chain(self.chunk.public_input_hash().as_bytes().iter().copied())
                    .enumerate()
                {
                    let cell = config
                        .rlc_config
                        .load_private(&mut region, &Fr::from(byte as u64), &mut index)
                        .unwrap();
                    cells.push(cell)
                }
                Ok(())
            },
        )?;

        println!("cells len: {}", cells.len());
        for (i, cell) in cells.into_iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.instance, i)?;
        }
        Ok(())
    }
}

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
