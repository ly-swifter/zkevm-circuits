use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use zkevm_circuits::{
    keccak_circuit::{
        keccak_packed_multi::multi_keccak, KeccakCircuitConfig, KeccakCircuitConfigArgs,
    },
    table::KeccakTable,
    util::{Challenges, SubCircuitConfig},
};

use crate::{
    constants::LOG_DEGREE,
    core::assign_batch_hashes,
    rlc::{rlc, RlcConfig},
    util::capacity,
};

#[derive(Default, Debug, Clone)]
struct DynamicHashCircuit {
    inputs: Vec<u8>,
}

#[derive(Debug, Clone)]
struct DynamicHashCircuitConfig {
    /// Keccak circuit configurations
    pub keccak_circuit_config: KeccakCircuitConfig<Fr>,
    /// RLC config
    pub rlc_config: RlcConfig,
}

impl Circuit<Fr> for DynamicHashCircuit {
    type Config = (DynamicHashCircuitConfig, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // RLC configuration
        let rlc_config = RlcConfig::configure(meta);

        // hash config
        let challenges = Challenges::construct(meta);
        // hash configuration for aggregation circuit
        let keccak_circuit_config = {
            let keccak_table = KeccakTable::construct(meta);
            let challenges_exprs = challenges.exprs(meta);

            let keccak_circuit_config_args = KeccakCircuitConfigArgs {
                keccak_table,
                challenges: challenges_exprs,
            };

            KeccakCircuitConfig::new(meta, keccak_circuit_config_args)
        };
        // enable equality for the data RLC column
        meta.enable_equality(keccak_circuit_config.keccak_table.input_rlc);

        let config = DynamicHashCircuitConfig {
            rlc_config,
            keccak_circuit_config,
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let (config, challenges) = config;

        let challenge = challenges.values(&layouter);

        println!("challenge: {:?}", challenge);
        let witness =
            multi_keccak(&[self.inputs.clone()], challenge, capacity(1 << LOG_DEGREE)).unwrap();

        // compute rlc in the clear
        let rlc = {
            let mut challenge_fr = Fr::zero();
            challenge.keccak_input().map(|x| challenge_fr = x);
            rlc(
                &self
                    .inputs
                    .iter()
                    .map(|&x| Fr::from(x as u64))
                    .collect::<Vec<_>>(),
                &challenge_fr,
            )
        };

        println!("rlc: {:?}", rlc);
        for (i, row) in witness.iter().enumerate().take(1200) {
            if row.is_final {
                println!("{}-th row:\n{:?}", i, row);
                println!("======================");
            }
        }

        layouter.assign_region(
            || "mock circuit",
            |mut region| {
                // keccak part
                let mut data_rlc_cells = vec![];
                for (offset, keccak_row) in witness.iter().enumerate() {
                    let row =
                        config
                            .keccak_circuit_config
                            .set_row(&mut region, offset, keccak_row)?;
                    if offset % 300 == 0 && data_rlc_cells.len() < 4 {
                        // second element is data rlc
                        data_rlc_cells.push(row[1].clone());
                    }
                }

                // rlc part
                let mut offset = 0;
                let challenge = {
                    let mut tmp = Fr::zero();
                    challenge.keccak_input().map(|x| tmp = x);
                    config
                        .rlc_config
                        .load_private(&mut region, &tmp, &mut offset)?
                };

                let rlc_inputs = self
                    .inputs
                    .iter()
                    .map(|&x| {
                        config
                            .rlc_config
                            .load_private(&mut region, &Fr::from(x as u64), &mut offset)
                            .unwrap()
                    })
                    .collect::<Vec<_>>();

                let rlc_cell =
                    config
                        .rlc_config
                        .rlc(&mut region, &rlc_inputs, &challenge, &mut offset)?;

                // rlc should be either one of data_rlc_cells[1], data_rlc_cells[2] and
                // data_rlc_cells[3] so we compute prod =
                // (data_rlc_cells[1]-rlc)*(data_rlc_cells[2]-rlc)*(data_rlc_cells[3]-rlc)
                // and constraint prod is zero
                let tmp1 = config.rlc_config.sub(
                    &mut region,
                    &data_rlc_cells[1],
                    &rlc_cell,
                    &mut offset,
                )?;
                let tmp2 = config.rlc_config.sub(
                    &mut region,
                    &data_rlc_cells[2],
                    &rlc_cell,
                    &mut offset,
                )?;
                let tmp3 = config.rlc_config.sub(
                    &mut region,
                    &data_rlc_cells[3],
                    &rlc_cell,
                    &mut offset,
                )?;
                let tmp = config
                    .rlc_config
                    .mul(&mut region, &tmp1, &tmp2, &mut offset)?;
                let tmp = config
                    .rlc_config
                    .mul(&mut region, &tmp, &tmp3, &mut offset)?;

                println!("rlc_cell is {:?}", rlc_cell.value());
                println!("rlc 1 is {:?}", data_rlc_cells[1].value());
                println!("rlc 2 is {:?}", data_rlc_cells[2].value());
                println!("rlc 3 is {:?}", data_rlc_cells[3].value());
                println!("tmp1 is {:?}", tmp1.value());
                println!("tmp2 is {:?}", tmp2.value());
                println!("tmp3 is {:?}", tmp3.value());
                println!("tmp is {:?}", tmp.value());
                config
                    .rlc_config
                    .enforce_zero(&mut region, &tmp, &mut offset)?;

                Ok(())
            },
        )?;
        Ok(())
    }
}

#[test]
fn test_hashes() {
    let k = 19;
    const LEN: usize = 200;
    let a = (0..LEN).map(|x| x as u8).collect::<Vec<u8>>();
    // let a = vec![1; LEN];
    let circuit = DynamicHashCircuit { inputs: a };
    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied_par();

    // assert!(false);
}
