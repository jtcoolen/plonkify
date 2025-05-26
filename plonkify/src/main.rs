use ark_bn254::Fr;
use ark_ff::{BigInteger, Field};
use circom_compat::{read_witness, R1CSFile};
use clap::Parser;
use core::num;
use hyperplonk::{prelude::SelectorColumn, witness};
use plonkify::{
    general::{
        ExpandedCircuit, ExpansionConfig, LinearOnlyGeneralPlonkifier,
        NaiveLinearOnlyGeneralPlonkifier, SimpleGeneralPlonkifier,
    },
    vanilla::{GreedyBruteForcePlonkifier, OptimizedPlonkifier, SimplePlonkifer},
    CustomizedGates, GeneralPlonkifer, Plonkifier,
};
use std::io::BufReader;
use std::{fs::File, time::Instant};
use ark_ff::PrimeField;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Optimization level
    #[arg(short = 'O', default_value_t = 1, value_parser = clap::value_parser!(u8).range(..3))]
    optimize: u8,

    /// Whether to use jellyfish turboplonk gates
    #[arg(long)]
    general: bool,

    /// R1CS circuit file (e.g. circuit.r1cs)
    circuit: String,

    /// JSON witness file (e.g. witness.json)
    witness: String,
}


pub fn pad_permutation_field<F: PrimeField>(
    mut permutation: Vec<F>,
    num_rows: usize,
    padding: usize,
    expected_length: usize,
) -> Vec<F> {
    let mut new_permutation = permutation;
    let mut current_offset = 0;

    let mut chunk_start = 0;
    while chunk_start + num_rows <= new_permutation.len() {
        let insert_at = chunk_start + num_rows + current_offset;

        // Insert padding block
        for i in 0..padding {
            new_permutation.insert(insert_at + i, F::zero()); // placeholder
        }

        // Shift all values >= insert_at by `padding`
        for val in new_permutation.iter_mut() {
            let v = val.into_bigint().as_ref()[0] as usize;
            if v >= insert_at {
                *val = F::from((v + padding) as u64);
            }
        }

        // Fix the inserted padding block into a cycle
        for i in 0..padding {
            let idx = insert_at + i;
            let next = insert_at + ((i + 1) % padding);
            new_permutation[idx] = F::from(next as u64);
        }

        current_offset += padding;
        chunk_start += num_rows;
    }

    // Final padding if needed
    let final_pad_start = new_permutation.len();
    while new_permutation.len() < expected_length {
        new_permutation.push(F::zero());
    }
    let final_pad_indices: Vec<usize> = (final_pad_start..expected_length).collect();
    for (i, &idx) in final_pad_indices.iter().enumerate() {
        let next = final_pad_indices[(i + 1) % final_pad_indices.len()];
        new_permutation[idx] = F::from(next as u64);
    }

    new_permutation
}


/// Checks that the permutation is a valid reordering of the witnesses with correct cycles.
///
/// A correct permutation must:
/// - Be the same length as `witnesses`
/// - Only include valid indices (i.e., < witnesses.len())
/// - Consist of disjoint cycles that map every index in the witness array
pub fn check_permutation<F: PrimeField>(
    witnesses: &[F],
    permutation: &[F],
    num_rows: usize,
) -> bool {
    let len = witnesses.len();
    if permutation.len() != len {
        println!("Permutation length mismatch: expected {}, got {}", len, permutation.len());
        return false;
    
    }

    let zero = F::zero();
    let zero_indices: Vec<usize> = permutation.iter()
        .enumerate()
        .filter_map(|(i, &val)| if val == zero { Some(i) } else { None })
        .collect();

    // Step 1: Check that all permutation values are valid indices
    let mut seen = vec![false; len];
    for &perm in permutation {
        let idx = perm.into_bigint().as_ref()[0] as usize;
        if idx >= len {
            println!("Expected index < {}, got {}", len, idx);
            return false;
        }
    }

    // Step 2: Follow each unvisited cycle and mark entries
    for start in 0..len {
        if seen[start] {
            continue;
        }

        let mut i = start;
        let mut cycle_len = 0;
        let next = 0;
        loop {
            if seen[i] {
                // Cycle looped to an already seen value before completing — error
                println!("cycle looped to an already seen value before completing, index {}, len {}, value {}", i, cycle_len, next);
                //continue;
                return false;
            }
            seen[i] = true;
            let next = permutation[i].into_bigint().as_ref()[0] as usize;
            cycle_len += 1;
            if start == next {
                break;
            }
            i = next;
        }

        if cycle_len == 0 {
            println!("cycle of len 0");
            return false;
        }
    }

    // Step 3: All entries must be seen
    seen.into_iter().all(|v| v)
}


fn convert_selectors(
    selectors: Vec<plonkify::selectors::SelectorColumn<Fr>>,
) -> Vec<hyperplonk::selectors::SelectorColumn<Fr>> {
    use ark_std::Zero;
    selectors
        .into_iter()
        .map(|mut s| {
            // Calculate the next power of two
            let next_power_of_two = s.0.len().next_power_of_two();

            // Pad with zeros if necessary
            if s.0.len() < next_power_of_two {
                s.0.resize(next_power_of_two, Fr::zero());
            }

            hyperplonk::selectors::SelectorColumn(s.0)
        })
        .collect()
}

fn convert_gates(
    gates: plonkify::custom_gate::CustomizedGates,
) -> hyperplonk::custom_gate::CustomizedGates {
    hyperplonk::custom_gate::CustomizedGates { gates: gates.gates }
}

fn convert_params(
    params: plonkify::circuit::PlonkishCircuitParams,
) -> hyperplonk::structs::HyperPlonkParams {
    hyperplonk::structs::HyperPlonkParams {
        num_constraints: params.num_constraints,
        num_pub_input: params.num_pub_input,
        gate_func: convert_gates(params.gate_func),
    }
}

fn split_flat_witness<F: Clone + ark_std::Zero>(
    flat_witness: &[F],
    num_columns: usize,
    num_rows: usize,
    num_pub_inputs: usize,
) -> Vec<Vec<F>> {
    let padding = num_pub_inputs.next_power_of_two() - num_pub_inputs;
    let padded_num_rows = (num_rows + padding).next_power_of_two();

    let mut columns = vec![Vec::with_capacity(padded_num_rows); num_columns];

    for wire in 0..num_columns {
        // 1. Public inputs
        for row in 0..num_pub_inputs {
            columns[wire].push(flat_witness[wire * num_rows + row].clone());
        }

        // 2. Padding
        for _ in 0..padding {
            columns[wire].push(F::zero());
        }

        // 3. Private inputs
        for row in num_pub_inputs..num_rows {
            columns[wire].push(flat_witness[wire * num_rows + row].clone());
        }

        // 4. Padding to the next power of two
        while columns[wire].len() < padded_num_rows {
            columns[wire].push(F::zero());
        }
        // Sanity check
        assert_eq!(columns[wire].len(), padded_num_rows);
    }

    columns
}


pub fn flatten_witness_matrix_preserve_padding<F: Clone>(
    columns: &[Vec<F>],
) -> Vec<F> {
    let num_columns = columns.len();
    let padded_num_rows = columns
        .first()
        .map(|col| col.len())
        .expect("Empty columns vector");

    // Sanity check: all columns should have the same length
    for col in columns {
        assert_eq!(col.len(), padded_num_rows, "Column length mismatch");
    }

    let mut flat = Vec::with_capacity(num_columns * padded_num_rows);

    for col in columns {
        for row in col {
            flat.push(row.clone());
        }
    }

    flat
}

fn main() {
    let cli = Cli::parse();

    let reader = BufReader::new(File::open(cli.circuit).unwrap());
    let mut file = R1CSFile::<Fr>::new(reader).unwrap();

    let witness_reader = BufReader::new(File::open(cli.witness).unwrap());
    file.witness = read_witness::<Fr>(witness_reader);

    println!("R1CS num constraints: {}", file.header.n_constraints);
    println!("R1CS num public inputs: {}", file.header.n_pub_in);
    println!("R1CS num private inputs: {}", file.header.n_prv_in);
    println!("R1CS witness len: {}", file.witness.len());

    let start = Instant::now();

    if cli.general {
        let (plonkish_circuit, plonkish_witness) = match cli.optimize {
            0 => NaiveLinearOnlyGeneralPlonkifier::<Fr>::plonkify(
                &file,
                &CustomizedGates::jellyfish_turbo_plonk_gate(),
            ),
            1 => LinearOnlyGeneralPlonkifier::<Fr>::plonkify(
                &file,
                &CustomizedGates::jellyfish_turbo_plonk_gate(),
            ),
            2 => SimpleGeneralPlonkifier::<Fr>::plonkify(
                &file,
                &CustomizedGates::jellyfish_turbo_plonk_gate(),
            ),
            _ => panic!("Unexpected optimizization level"),
        };
        println!(
            "Plonk num constraints: {}",
            plonkish_circuit.params.num_constraints
        );
        assert!(plonkish_circuit.is_satisfied(&plonkish_witness));
    } else {
        let (mut plonkish_circuit, plonkish_witness) = match cli.optimize {
            0 => SimplePlonkifer::<Fr>::plonkify(&file),
            1 => OptimizedPlonkifier::<Fr>::plonkify(&file),
            2 => GreedyBruteForcePlonkifier::<Fr>::plonkify(&file),
            _ => panic!("Unexpected optimizization level"),
        };
        println!(
            "Plonk num constraints: {}",
            plonkish_circuit.params.num_constraints
        );

        assert!(plonkish_circuit.is_satisfied(&plonkish_witness));


        let num_rows: usize = plonkish_circuit.params.num_constraints; //num_constraints
        let num_columns = plonkish_circuit.params.gate_func.num_witness_columns();
        let num_pub_inputs = plonkish_circuit.params.num_pub_input;

        let witnesses: Vec<hyperplonk::witness::WitnessColumn<_>> =
            split_flat_witness(&plonkish_witness, num_columns, num_rows, num_pub_inputs)
                .into_iter()
                .map(hyperplonk::witness::WitnessColumn::new)
                .collect();

        let witnesses_vec: Vec<Vec<_>> = witnesses
                .iter()
                .map(|w| w.coeff_ref().to_vec())  // Convert each slice into an owned Vec
                .collect();
            
        let witnesses_flattened = flatten_witness_matrix_preserve_padding(&witnesses_vec);


        use ark_std::log2;

        use ark_std::Zero;


        let selectors = plonkish_circuit.selectors.clone();

        plonkish_circuit.params.num_constraints =
            plonkish_circuit.params.num_constraints.next_power_of_two();
        plonkish_circuit.params.num_pub_input = plonkish_circuit.params.num_pub_input.next_power_of_two();

        let padding = num_pub_inputs.next_power_of_two() - num_pub_inputs;

        
        let num_priv_inputs = num_rows - num_pub_inputs;
        let pub_padding = num_pub_inputs.next_power_of_two() - num_pub_inputs;
        let total_len = num_pub_inputs + pub_padding + num_priv_inputs;

        let mut padded_selectors: Vec<Vec<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>>> = vec![vec![Fr::zero(); total_len]; selectors.len()];

        for (i, sel_column) in selectors.iter().enumerate() {
            // Copy public inputs
            for j in 0..num_pub_inputs {
                padded_selectors[i][j] = sel_column.0[j].clone();
            }
            // Padding remains zero (implicitly)

            // Copy private inputs after padding
            for j in 0..num_priv_inputs {
                padded_selectors[i][num_pub_inputs + pub_padding + j] =
                    sel_column.0[num_pub_inputs + j].clone();
            }
        }
        

        let padded_selectors: Vec<plonkify::selectors::SelectorColumn<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>>> = padded_selectors
                .into_iter()
                .map(|col| plonkify::selectors::SelectorColumn(col))
                .collect()
        ;
 
        let new_num_rows = num_rows + padding;
        let padded_num_rows = num_rows.next_power_of_two();
        let pad = padded_num_rows - num_rows;

        let chunk_size = 1 << log2(plonkish_circuit.params.num_constraints) as usize;
        assert_eq!(chunk_size, padded_num_rows);
        let expected_length = chunk_size * num_columns;
        let mut permutation = plonkish_circuit.permutation.clone();


        let mut new_permutation = pad_permutation_field(
            permutation.clone(),
            num_rows,
            padding,
            expected_length,
        );
    

        assert_eq!(plonkish_circuit.params.num_constraints , witnesses[0].coeff_ref().len());
        
        
        assert!(
            check_permutation(&plonkish_witness, &permutation, num_rows),
            "Permutation check failed"
        );
        assert!(
            check_permutation(&witnesses_flattened, &new_permutation, num_rows.next_power_of_two()),
            "Permutation check failed"
        );


        let circuit: HyperPlonkIndex<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>> =
            HyperPlonkIndex {
                params: convert_params(plonkish_circuit.params.clone()),
                permutation: new_permutation,
                selectors: convert_selectors(padded_selectors),
            };
        assert_eq!(plonkish_circuit.params.num_constraints , circuit.selectors[0].0.len());

        println!("Num gates: {}", num_columns);
        println!("Num constraints (after padding): {}", circuit.params.num_constraints);
        println!("Num public inputs (after padding): {}", circuit.params.num_pub_input);

        use ark_bn254::Bn254;
        use ark_bn254::Fr;
        use ark_ff::PrimeField;
        use std::str::FromStr;

        use hyperplonk::structs::{HyperPlonkIndex, HyperPlonkParams};
        use hyperplonk::HyperPlonkSNARK;

        use ark_std::test_rng;
        use subroutines::{
            pcs::{
                prelude::{MultilinearKzgPCS, MultilinearUniversalParams},
                PolynomialCommitmentScheme,
            },
            poly_iop::PolyIOP,
        };

        const SUPPORTED_SIZE: usize = 20;

        let mut rng = test_rng();
        let pcs_srs = {
            let srs =
                MultilinearKzgPCS::<Bn254>::gen_srs_for_testing(&mut rng, SUPPORTED_SIZE).unwrap();
            //write_srs(&srs);
            srs
        };
        use ark_ff::BigInt;
        
        let mut public_inputs = plonkish_witness[..num_pub_inputs].to_vec();
        public_inputs.resize(num_pub_inputs.next_power_of_two(), Fr::zero());
        
       

        let start = Instant::now();

        let (pk, vk) =
            <PolyIOP<Fr> as HyperPlonkSNARK<Bn254, MultilinearKzgPCS<Bn254>>>::preprocess(
                &circuit, &pcs_srs,
            )
            .unwrap();

        println!("key extraction: {:?}", start.elapsed());


        //==========================================================
        // generate a proof
        let start = Instant::now();

        let _proof = <PolyIOP<Fr> as HyperPlonkSNARK<Bn254, MultilinearKzgPCS<Bn254>>>::prove(
            &pk,
            &public_inputs,
            &witnesses,
        )
        .unwrap();

        println!("proving: {:?}", start.elapsed());

        let proof = <PolyIOP<Fr> as HyperPlonkSNARK<Bn254, MultilinearKzgPCS<Bn254>>>::prove(
            &pk,
            &public_inputs,
            &witnesses,
        )
        .unwrap();
        //==========================================================
        // verify a proof
        let start = Instant::now();
        //println!("proof : {:?}", proof.perm_check_proof.zero_check_proof);

        let verify = <PolyIOP<Fr> as HyperPlonkSNARK<Bn254, MultilinearKzgPCS<Bn254>>>::verify(
            &vk,
            &public_inputs,
            &proof,
        )
        .unwrap();
        assert!(verify);

        println!("verifying: {:?}", start.elapsed());
    }

    let end = Instant::now();
    //println!("Time: {}", (end - start).as_micros());
}
