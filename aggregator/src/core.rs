use ark_std::{end_timer, start_timer};
use eth_types::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::bn256::{Bn256, G1Affine},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use rand::Rng;
use snark_verifier::{
    loader::native::NativeLoader,
    pcs::{
        kzg::{Bdfg21, Kzg, KzgAccumulator, KzgAs},
        AccumulationSchemeProver,
    },
    verifier::PlonkVerifier,
    Error,
};
use snark_verifier_sdk::{
    types::{PoseidonTranscript, Shplonk, POSEIDON_SPEC},
    Snark,
};
use zkevm_circuits::{
    keccak_circuit::{keccak_packed_multi::multi_keccak, KeccakCircuitConfig},
    table::LookupTable,
    util::Challenges,
};

use crate::{
    constants::{CHAIN_ID_LEN, LOG_DEGREE},
    util::{assert_equal, capacity, get_indices},
    CHUNK_DATA_HASH_INDEX, POST_STATE_ROOT_INDEX, PREV_STATE_ROOT_INDEX, WITHDRAW_ROOT_INDEX,
};

/// Input the hash input bytes,
/// assign the circuit for the hash function,
/// return cells of the hash inputs and digests.
#[allow(clippy::type_complexity)]
pub(crate) fn assign_batch_hashes<F: Field>(
    config: &KeccakCircuitConfig<F>,
    layouter: &mut impl Layouter<F>,
    challenges: Challenges<Value<F>>,
    preimages: &[Vec<u8>],
) -> Result<
    (
        Vec<Vec<AssignedCell<F, F>>>, // input cells
        Vec<Vec<AssignedCell<F, F>>>, // digest cells
    ),
    Error,
> {
    let mut is_first_time = true;
    let num_rows = 1 << LOG_DEGREE;

    let timer = start_timer!(|| ("multi keccak").to_string());
    // preimages consists of the following parts
    // (1) batchPiHash preimage =
    //      (chain_id ||
    //      chunk[0].prev_state_root ||
    //      chunk[k-1].post_state_root ||
    //      chunk[k-1].withdraw_root ||
    //      batch_data_hash)
    // (2) batchDataHash preimage =
    //      (chunk[0].dataHash || ... || chunk[k-1].dataHash)
    // (3) chunk[i].piHash preimage =
    //      (chain id ||
    //      chunk[i].prevStateRoot || chunk[i].postStateRoot ||
    //      chunk[i].withdrawRoot || chunk[i].datahash)
    // each part of the preimage is mapped to image by Keccak256
    let witness = multi_keccak(preimages, challenges, capacity(num_rows)).unwrap();
    end_timer!(timer);

    // extract the indices of the rows for which the preimage and the digest cells lie in
    let (preimage_indices, digest_indices) = get_indices(preimages);
    let mut preimage_indices_iter = preimage_indices.iter();
    let mut digest_indices_iter = digest_indices.iter();

    let mut hash_input_cells = vec![];
    let mut hash_output_cells = vec![];

    let mut cur_preimage_index = preimage_indices_iter.next();
    let mut cur_digest_index = digest_indices_iter.next();

    layouter.assign_region(
        || "assign keccak rows",
        |mut region| {
            if is_first_time {
                is_first_time = false;
                let offset = witness.len() - 1;
                config.set_row(&mut region, offset, &witness[offset])?;
                return Ok(());
            }
            // ====================================================
            // Step 1. Extract the hash cells
            // ====================================================
            let mut current_hash_input_cells = vec![];
            let mut current_hash_output_cells = vec![];

            let timer = start_timer!(|| "assign row");
            for (offset, keccak_row) in witness.iter().enumerate() {
                let row = config.set_row(&mut region, offset, keccak_row)?;

                if cur_preimage_index.is_some() && *cur_preimage_index.unwrap() == offset {
                    // 7-th column is Keccak input in Keccak circuit
                    current_hash_input_cells.push(row[6].clone());
                    cur_preimage_index = preimage_indices_iter.next();
                }
                if cur_digest_index.is_some() && *cur_digest_index.unwrap() == offset {
                    // last column is Keccak output in Keccak circuit
                    current_hash_output_cells.push(row.last().unwrap().clone());
                    cur_digest_index = digest_indices_iter.next();
                }

                // we reset the current hash when it is finalized
                // note that length == 0 indicate that the hash is a padding
                // so we simply skip it
                if keccak_row.is_final && keccak_row.length != 0 {
                    hash_input_cells.push(current_hash_input_cells);
                    hash_output_cells.push(current_hash_output_cells);
                    current_hash_input_cells = vec![];
                    current_hash_output_cells = vec![];
                }
            }
            end_timer!(timer);

            // sanity: we have same number of hash input and output
            let hash_num = hash_input_cells.len();
            let num_chunks = hash_num - 2;
            assert_eq!(hash_num, preimages.len());
            assert_eq!(hash_num, hash_output_cells.len());

            // ====================================================
            // Step 2. Constraint the relations between hash preimages and digests
            // ====================================================
            //
            // 2.1 batch_data_hash digest is reused for public input hash
            //
            // public input hash is build as
            //  keccak(
            //      chain_id ||
            //      chunk[0].prev_state_root ||
            //      chunk[k-1].post_state_root ||
            //      chunk[k-1].withdraw_root ||
            //      batch_data_hash )
            for i in 0..4 {
                for j in 0..8 {
                    // sanity check
                    // CHUNK_DATA_HASH_INDEX is the byte position for batch_data_hash
                    assert_equal(
                        &hash_input_cells[0][i * 8 + j + CHUNK_DATA_HASH_INDEX],
                        &hash_output_cells[1][(3 - i) * 8 + j],
                    );
                    region.constrain_equal(
                        // preimage and digest has different endianness
                        hash_input_cells[0][i * 8 + j + CHUNK_DATA_HASH_INDEX].cell(),
                        hash_output_cells[1][(3 - i) * 8 + j].cell(),
                    )?;
                }
            }

            // 2.2 batch_pi_hash used same roots as chunk_pi_hash
            //
            // batch_pi_hash =
            //   keccak(
            //      chain_id ||
            //      chunk[0].prev_state_root ||
            //      chunk[k-1].post_state_root ||
            //      chunk[k-1].withdraw_root ||
            //      batchData_hash )
            //
            // chunk[i].piHash =
            //   keccak(
            //        chain id ||
            //        chunk[i].prevStateRoot ||
            //        chunk[i].postStateRoot ||
            //        chunk[i].withdrawRoot  ||
            //        chunk[i].datahash)
            //
            // PREV_STATE_ROOT_INDEX, POST_STATE_ROOT_INDEX, WITHDRAW_ROOT_INDEX
            // used below are byte positions for
            // prev_state_root, post_state_root, withdraw_root
            for i in 0..32 {
                // 2.2.1 chunk[0].prev_state_root
                // sanity check
                assert_equal(
                    &hash_input_cells[0][i + PREV_STATE_ROOT_INDEX],
                    &hash_input_cells[2][i + PREV_STATE_ROOT_INDEX],
                );
                region.constrain_equal(
                    hash_input_cells[0][i + PREV_STATE_ROOT_INDEX].cell(),
                    hash_input_cells[2][i + PREV_STATE_ROOT_INDEX].cell(),
                )?;
                // 2.2.2 chunk[k-1].post_state_root
                // sanity check
                assert_equal(
                    &hash_input_cells[0][i + POST_STATE_ROOT_INDEX],
                    &hash_input_cells[hash_num - 1][i + POST_STATE_ROOT_INDEX],
                );
                region.constrain_equal(
                    hash_input_cells[0][i + POST_STATE_ROOT_INDEX].cell(),
                    hash_input_cells[hash_num - 1][i + POST_STATE_ROOT_INDEX].cell(),
                )?;
                // 2.2.3 chunk[k-1].withdraw_root
                assert_equal(
                    &hash_input_cells[0][i + WITHDRAW_ROOT_INDEX],
                    &hash_input_cells[hash_num - 1][i + WITHDRAW_ROOT_INDEX],
                );
                region.constrain_equal(
                    hash_input_cells[0][i + WITHDRAW_ROOT_INDEX].cell(),
                    hash_input_cells[hash_num - 1][i + WITHDRAW_ROOT_INDEX].cell(),
                )?;
            }

            // 2.3 same dataHash is used for batchDataHash and chunk[i].piHash
            //
            // batchDataHash = keccak(chunk[0].dataHash || ... || chunk[k-1].dataHash)
            //
            // chunk[i].piHash =
            //     keccak(
            //        &chain id ||
            //        chunk[i].prevStateRoot ||
            //        chunk[i].postStateRoot ||
            //        chunk[i].withdrawRoot  ||
            //        chunk[i].datahash)
            for (i, chunk) in hash_input_cells[1].chunks(32).enumerate().take(num_chunks) {
                for (j, cell) in chunk.iter().enumerate() {
                    // sanity check
                    assert_equal(cell, &hash_input_cells[2 + i][j + CHUNK_DATA_HASH_INDEX]);
                    region.constrain_equal(
                        cell.cell(),
                        hash_input_cells[2 + i][j + CHUNK_DATA_HASH_INDEX].cell(),
                    )?;
                }
            }

            // 2.4  chunks are continuous: they are linked via the state roots
            for i in 0..num_chunks - 1 {
                for j in 0..32 {
                    // sanity check
                    assert_equal(
                        &hash_input_cells[i + 3][PREV_STATE_ROOT_INDEX + j],
                        &hash_input_cells[i + 2][POST_STATE_ROOT_INDEX + j],
                    );
                    region.constrain_equal(
                        // chunk[i+1].prevStateRoot
                        hash_input_cells[i + 3][PREV_STATE_ROOT_INDEX + j].cell(),
                        // chunk[i].postStateRoot
                        hash_input_cells[i + 2][POST_STATE_ROOT_INDEX + j].cell(),
                    )?;
                }
            }

            // 2.5 assert hashes use a same chain id
            for i in 0..num_chunks {
                for j in 0..CHAIN_ID_LEN {
                    // sanity check
                    assert_equal(&hash_input_cells[0][j], &hash_input_cells[i + 2][j]);
                    region.constrain_equal(
                        // chunk[i+1].prevStateRoot
                        hash_input_cells[0][j].cell(),
                        // chunk[i].postStateRoot
                        hash_input_cells[i + 2][j].cell(),
                    )?;
                }
            }

            config.keccak_table.annotate_columns_in_region(&mut region);
            config.annotate_circuit(&mut region);
            Ok(())
        },
    ).unwrap();

    Ok((hash_input_cells, hash_output_cells))
}

/// Subroutine for the witness generations.
/// Extract the accumulator and proof that from previous snarks.
/// Uses SHPlonk for accumulation.
pub(crate) fn extract_accumulators_and_proof(
    params: &ParamsKZG<Bn256>,
    snarks: &[Snark],
    rng: impl Rng + Send,
) -> Result<(KzgAccumulator<G1Affine, NativeLoader>, Vec<u8>), Error> {
    let svk = params.get_g()[0].into();

    let mut transcript_read =
        PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(&[], POSEIDON_SPEC.clone());
    let accumulators = snarks
        .iter()
        .flat_map(|snark| {
            transcript_read.new_stream(snark.proof.as_slice());
            let proof = Shplonk::read_proof(
                &svk,
                &snark.protocol,
                &snark.instances,
                &mut transcript_read,
            );
            // each accumulator has (lhs, rhs) based on Shplonk
            // lhs and rhs are EC points
            Shplonk::succinct_verify(&svk, &snark.protocol, &snark.instances, &proof)
        })
        .collect::<Vec<_>>();

    let mut transcript_write =
        PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(vec![], POSEIDON_SPEC.clone());
    // We always use SHPLONK for accumulation scheme when aggregating proofs
    let accumulator =
        // core step
        // KzgAs does KZG accumulation scheme based on given accumulators and random number (for adding blinding)
        // accumulated ec_pt = ec_pt_1 * 1 + ec_pt_2 * r + ... + ec_pt_n * r^{n-1}
        // ec_pt can be lhs and rhs
        // r is the challenge squeezed from proof
        KzgAs::<Kzg<Bn256, Bdfg21>>::create_proof::<PoseidonTranscript<NativeLoader, Vec<u8>>, _>(
            &Default::default(),
            &accumulators,
            &mut transcript_write,
            rng,
        )?;
    Ok((accumulator, transcript_write.finalize()))
}
