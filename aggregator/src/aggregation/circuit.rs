use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::{Circuit, ConstraintSystem, Error, Selector},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::commitment::ParamsKZG,
    },
};
use itertools::Itertools;
use rand::Rng;
use snark_verifier::{
    loader::{
        halo2::{
            halo2_ecc::halo2_base::{
                self, gates::GateInstructions, AssignedValue, Context, ContextParams, QuantumCell,
            },
            Halo2Loader,
        },
        native::NativeLoader,
    },
    pcs::kzg::{Bdfg21, Kzg, KzgAccumulator, KzgSuccinctVerifyingKey},
    util::arithmetic::fe_to_limbs,
};
use snark_verifier_sdk::{
    aggregate, flatten_accumulator, gen_dummy_snark, types::Svk, CircuitExt, Snark, SnarkWitness,
};
use zkevm_circuits::util::Challenges;

use crate::{
    batch::BatchHash,
    constants::{ACC_LEN, BITS, DIGEST_LEN, LIMBS, MAX_AGG_SNARKS},
    core::{assign_batch_hashes, chunk_is_valid, extract_accumulators_and_proof},
    ConfigParams,
};

use super::AggregationConfig;

// use crate::{
//     aggregation::{config::AggregationConfig, util::is_smaller_than},
//     assigned_cell_to_value,
//     constants::{ACC_LEN, BITS, DIGEST_LEN, LIMBS},
//     core::{assert_hash_relations, assign_batch_hashes, extract_accumulators_and_proof},
//     param::ConfigParams,
//     BatchHash, ChunkHash, MAX_AGG_SNARKS,
// };

/// Aggregation circuit that does not re-expose any public inputs from aggregated snarks
#[derive(Clone)]
pub struct AggregationCircuit {
    pub(crate) svk: KzgSuccinctVerifyingKey<G1Affine>,
    // the input snarks for the aggregation circuit
    // it is padded already so it will have a fixed length of MAX_AGG_SNARKS
    pub(crate) snarks_with_padding: Vec<SnarkWitness>,
    // the public instance for this circuit consists of
    // - an accumulator (12 elements)
    // - the batch's public_input_hash (32 elements)
    // - the number of snarks that is aggregated (1 element)
    pub(crate) flattened_instances: Vec<Fr>,
    // accumulation scheme proof, private input
    pub(crate) as_proof: Value<Vec<u8>>,
    // batch hash circuit for which the snarks are generated
    // the chunks in this batch are also padded already
    pub(crate) batch_hash: BatchHash,
}

impl AggregationCircuit {
    pub fn new(
        params: &ParamsKZG<Bn256>,
        snarks_with_padding: &[Snark],
        rng: impl Rng + Send,
        batch_hash: BatchHash,
    ) -> Self {
        let timer = start_timer!(|| "generate aggregation circuit");

        // sanity check: snarks's public input matches chunk_hashes
        for (chunk, snark) in batch_hash
            .chunks_with_padding
            .iter()
            .zip(snarks_with_padding.iter())
        {
            let chunk_hash_bytes = chunk.public_input_hash();
            let snark_hash_bytes = &snark.instances[0];

            assert_eq!(snark_hash_bytes.len(), ACC_LEN + DIGEST_LEN);

            for i in 0..32 {
                // for each snark,
                //  first 12 elements are accumulator
                //  next 32 elements are public_input_hash
                //  accumulator + public_input_hash = snark public input
                assert_eq!(
                    Fr::from(chunk_hash_bytes.as_bytes()[i] as u64),
                    snark_hash_bytes[i + ACC_LEN]
                );
            }
        }

        // extract the accumulators and proofs
        let svk = params.get_g()[0].into();
        // this aggregates MULTIPLE snarks
        //  (instead of ONE as in proof compression)
        let (accumulator, as_proof) =
            extract_accumulators_and_proof(params, &snarks_with_padding, rng).unwrap();
        let KzgAccumulator::<G1Affine, NativeLoader> { lhs, rhs } = accumulator;
        let acc_instances = [lhs.x, lhs.y, rhs.x, rhs.y]
            .map(fe_to_limbs::<Fq, Fr, LIMBS, BITS>)
            .concat();

        // extract batch's public input hash
        let public_input_hash = &batch_hash.instances_exclude_acc()[0];

        // the public instance for this circuit consists of
        // - an accumulator (12 elements)
        // - the batch's public_input_hash (32 elements)
        // - the number of snarks that is aggregated (1 element)
        let flattened_instances: Vec<Fr> = [
            acc_instances.as_slice(),
            public_input_hash.as_slice(),
            &[Fr::from(batch_hash.number_of_valid_chunks as u64)],
        ]
        .concat();

        end_timer!(timer);
        Self {
            svk,
            snarks_with_padding: snarks_with_padding.iter().cloned().map_into().collect(),
            flattened_instances,
            as_proof: Value::known(as_proof),
            batch_hash,
        }
    }
}

impl Circuit<Fr> for AggregationCircuit {
    type Config = (AggregationConfig, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let params = ConfigParams::aggregation_param();
        let challenges = Challenges::construct(meta);
        let config = AggregationConfig::configure(meta, &params, challenges);
        log::info!(
            "aggregation circuit configured with k = {} and {:?} advice columns",
            params.degree,
            params.num_advice
        );
        (config, challenges)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let (config, challenge) = config;

        let witness_time = start_timer!(|| "synthesize | Aggregation Circuit");

        config
            .range()
            .load_lookup_table(&mut layouter)
            .expect("load range lookup table");

        // let chunk_is_valid = chunk_is_valid(
        //     &config.flex_gate(),
        //     &mut layouter,
        //     self.batch_hash.number_of_valid_chunks,
        // );

        // ==============================================
        // step 2: public input aggregation circuit
        // ==============================================
        // extract all the hashes and load them to the hash table
        let challenges = challenge.values(&layouter);

        let timer = start_timer!(|| ("load aux table").to_string());
        config
            .keccak_circuit_config
            .load_aux_tables(&mut layouter)?;
        end_timer!(timer);

        let timer = start_timer!(|| ("extract hash").to_string());
        // orders:
        // - batch_public_input_hash
        // - chunk\[i\].piHash for i in \[0, MAX_AGG_SNARKS)
        // - batch_data_hash_preimage
        let preimages = self.batch_hash.extract_hash_preimages();
        assert_eq!(
            preimages.len(),
            MAX_AGG_SNARKS + 2,
            "error extracting preimages"
        );
        end_timer!(timer);

        let timer = start_timer!(|| ("assign cells").to_string());
        let (hash_preimage_cells, hash_digest_cells) = assign_batch_hashes(
            &config,
            &mut layouter,
            challenges,
            &preimages,
            self.batch_hash.number_of_valid_chunks,
        )
        .unwrap();
        end_timer!(timer);

        // for i in 0..MAX_AGG_SNARKS + 2 {
        //     println!("{}-th hash", i);
        //     println!("preimage");
        //     for (j, e) in hash_preimage_cells[i].iter().enumerate() {
        //         println!("{} {:?}", j, e.value());
        //     }

        //     println!("digest");
        //     for (j, e) in hash_digest_cells[i].iter().enumerate() {
        //         println!("{} {:?}", j, e.value());
        //     }

        //     println!("===============\n");
        // }

        let mut first_pass = halo2_base::SKIP_FIRST_PASS;

        end_timer!(witness_time);
        Ok(())
    }
}

impl CircuitExt<Fr> for AggregationCircuit {
    fn num_instance(&self) -> Vec<usize> {
        // 12 elements from accumulator
        // 32 elements from batch's public_input_hash
        vec![ACC_LEN + DIGEST_LEN]
    }

    // 12 elements from accumulator
    // 32 elements from batch's public_input_hash
    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.flattened_instances.clone()]
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        // the accumulator are the first 12 cells in the instance
        Some((0..ACC_LEN).map(|idx| (0, idx)).collect())
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        // - advice columns from flex gate
        // - selector from RLC gate
        config.0.flex_gate().basic_gates[0]
            .iter()
            .map(|gate| gate.q_enable)
            .into_iter()
            .collect()
    }
}
