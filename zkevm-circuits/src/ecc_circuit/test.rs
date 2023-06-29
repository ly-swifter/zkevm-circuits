use std::{
    marker::PhantomData,
    ops::{Add, Mul},
};

use bus_mapping::circuit_input_builder::{EcAddOp, EcMulOp, EcPairingOp, PrecompileEcParams};
use eth_types::Field;
use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Fr, G1Affine},
};
use rand::{CryptoRng, RngCore};

use crate::ecc_circuit::EccCircuit;

fn run<F: Field>(
    k: u32,
    max_ec_ops: PrecompileEcParams,
    add_ops: Vec<EcAddOp>,
    mul_ops: Vec<EcMulOp>,
    pairing_ops: Vec<EcPairingOp>,
) {
    let circuit = EccCircuit::<F> {
        max_add_ops: max_ec_ops.ec_add,
        max_mul_ops: max_ec_ops.ec_mul,
        max_pairing_ops: max_ec_ops.ec_pairing,
        add_ops,
        mul_ops,
        pairing_ops,
        _marker: PhantomData,
    };

    let prover = match MockProver::run(k, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

trait GenRand {
    fn gen_rand<R: RngCore + CryptoRng>(r: &mut R) -> Self;
}

impl GenRand for EcAddOp {
    fn gen_rand<R: RngCore + CryptoRng>(mut r: &mut R) -> Self {
        let p = G1Affine::random(&mut r);
        let q = G1Affine::random(&mut r);
        // TODO: tmp change.
        // let r = p.add(&q).into();
        let r = G1Affine::random(&mut r);
        Self { p, q, r }
    }
}

impl GenRand for EcMulOp {
    fn gen_rand<R: RngCore + CryptoRng>(mut r: &mut R) -> Self {
        let p = G1Affine::random(&mut r);
        let s = <Fr as halo2_proofs::arithmetic::Field>::random(&mut r);
        let r = p.mul(&s).into();
        Self { p, s, r }
    }
}

fn gen<T: GenRand, R: RngCore + CryptoRng>(mut r: &mut R, max_len: usize) -> Vec<T> {
    std::iter::repeat(0)
        .take(max_len)
        .map(move |_| T::gen_rand(&mut r))
        .collect()
}

#[test]
fn test_ecc_circuit() {
    use crate::ecc_circuit::util::LOG_TOTAL_NUM_ROWS;
    use halo2_proofs::halo2curves::bn256::Fr;

    let mut rng = rand::thread_rng();

    run::<Fr>(
        LOG_TOTAL_NUM_ROWS,
        PrecompileEcParams {
            ec_add: 1,
            ec_mul: 0,
            ec_pairing: 0,
        },
        // using empty vec will populate the default ops.
        gen(&mut rng, 1),
        // gen(&mut rng, 9),
        vec![],
        vec![],
    )
}
