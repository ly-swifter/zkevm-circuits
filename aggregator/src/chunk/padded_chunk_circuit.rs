use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
};

#[cfg(feature = "skip_first_pass")]
use snark_verifier::loader::halo2::halo2_ecc::halo2_base;
use snark_verifier_sdk::CircuitExt;

use crate::{constants::DIGEST_LEN, ChunkHash};

#[derive(Clone)]
pub struct PaddedChunkHashCircuit {
    padded_chunk: ChunkHash,
}

impl PaddedChunkHashCircuit {
    #[allow(dead_code)]
    pub(crate) fn new(padded_chunk: ChunkHash) -> Self {
        Self { padded_chunk }
    }

    pub(crate) fn instance(&self) -> Vec<Fr> {
        self.padded_chunk
            .public_input_hash()
            .as_bytes()
            .iter()
            .map(|x| Fr::from(*x as u64))
            .collect()
    }
}

#[derive(Clone)]
pub struct PaddedChunkHashCircuitConfig {
    /// Instance for public input; stores
    /// - batch_public_input_hash (32 elements)
    instance: Column<Instance>,
    /// Advice column to store the public input
    advice: Column<Advice>,
}

impl Circuit<Fr> for PaddedChunkHashCircuit {
    type Config = PaddedChunkHashCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // Instance column stores public input column
        // - the batch public input hash
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        // Advice column also stores public input column
        // - the batch public input hash
        let advice = meta.advice_column();
        meta.enable_equality(advice);

        Self::Config { instance, advice }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        #[cfg(feature = "skip_first_pass")]
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;
        let cells = layouter.assign_region(
            || "padded chunk circuit",
            |mut region| -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
                #[cfg(feature = "skip_first_pass")]
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let mut cells = vec![];
                for (index, element) in self.instance().iter().enumerate() {
                    cells.push(region.assign_advice(
                        || "public input",
                        config.advice,
                        index,
                        || Value::known(*element),
                    )?);
                }

                Ok(cells)
            },
        )?;

        for (index, element) in cells.iter().enumerate() {
            layouter.constrain_instance(element.cell(), config.instance, index)?;
        }

        Ok(())
    }
}

impl CircuitExt<Fr> for PaddedChunkHashCircuit {
    fn num_instance(&self) -> Vec<usize> {
        vec![DIGEST_LEN]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instance()]
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        None
    }

    fn selectors(_config: &Self::Config) -> Vec<Selector> {
        vec![]
    }
}
