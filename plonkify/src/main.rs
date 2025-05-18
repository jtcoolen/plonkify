use ark_bn254::Fr;
use circom_compat::{read_witness, R1CSFile};
use clap::Parser;
use core::num;
use hyperplonk::witness;
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
) -> Vec<Vec<F>> {
    println!("num_columns: {}", num_columns);
    println!("num_rows: {}", num_rows);
    // Calculate the next power of two for num_rows
    let padded_num_rows = num_rows.next_power_of_two();
    println!("padded_num_rows: {}", padded_num_rows);
    let mut columns = vec![Vec::with_capacity(num_rows); num_columns];

    for col in 0..num_columns {
        for row in 0..num_rows {
            columns[col].push(flat_witness[col * num_rows + row].clone());
        }
        // Pad the column with zeros if necessary
        while columns[col].len() < padded_num_rows {
            columns[col].push(F::zero());
        }
    }

    columns
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
    // let witnesses = file.witness.clone();

    // indexes in witness of public values 1, 2, 4, 8, 44, 46, 85
    // 0, 0, 10421825637439628824081370409036765017174374174061117515899412920044738899655,
    // 0, 10612347151689404540561019678397472246525777872901669450210397933867489294116,
    // 13586366247509677337685352076333204587518780062832582595806876819740439599275, 9702677999813389814729049215331589824309244590168229392617691640937402679279

    // let (plonkish_circuit, plonkish_witness) = SimpleGeneralPlonkifier::<Fr>::plonkify(
    //     &file,
    //     &CustomizedGates::jellyfish_turbo_plonk_gate(),
    // );
    // return;

    // let (plonkish_circuit, plonkish_witness) = LinearOnlyGeneralPlonkifier::<Fr>::plonkify(
    //     &file,
    //     &CustomizedGates::jellyfish_turbo_plonk_gate(),
    // );
    // // return;

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

        let witnesses: Vec<hyperplonk::witness::WitnessColumn<_>> =
            split_flat_witness(&plonkish_witness, num_columns, num_rows)
                .into_iter()
                .map(hyperplonk::witness::WitnessColumn::new)
                .collect();

        use ark_std::log2;

        let chunk_size = 1 << log2(plonkish_circuit.params.num_constraints) as usize;
        let expected_length = chunk_size * num_columns;
        let mut permutation = plonkish_circuit.permutation.clone();

        use ark_std::Zero;

        // Pad with zeros if the vector is too short
        if permutation.len() < expected_length {
            println!("permutation too short");
            permutation.resize(expected_length, Fr::zero());
        }

        // Truncate if the vector is too long
        if permutation.len() > expected_length {
            println!("permutation too long");
            permutation.truncate(expected_length);
        }

        let selectors = plonkish_circuit.selectors.clone();

        plonkish_circuit.params.num_constraints =
            plonkish_circuit.params.num_constraints.next_power_of_two();
        // fork hyperplonk, then export hyperplonk index, do the proper conversions
        let circuit: HyperPlonkIndex<ark_ff::Fp<ark_ff::MontBackend<ark_bn254::FrConfig, 4>, 4>> =
            HyperPlonkIndex {
                params: convert_params(plonkish_circuit.params),
                permutation: permutation,
                selectors: convert_selectors(selectors),
            };
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
        let public_inputs: [Fr; 8] = [
            Fr::from_str("1").expect("failed to parse"), // but from my understanding should be 0
            Fr::from_str("1").expect("failed to parse"), // 0?
            Fr::from(BigInt([0, 0, 0, 0])), // 10421825637439628824081370409036765017174374174061117515899412920044738899655?
            Fr::from(BigInt([0, 0, 0, 0])), // 0?
            Fr::from(BigInt([
                2540811791615192775,
                2915835453654324972,
                12845048901031846702,
                1660292612223788596,
            ])), // 10612347151689404540561019678397472246525777872901669450210397933867489294116?
            Fr::from(BigInt([0, 0, 0, 0])), //13586366247509677337685352076333204587518780062832582595806876819740439599275
            Fr::from(BigInt([
                1318003681124415268,
                8744354528158778391,
                5232689545760966842,
                1690644440548590990,
            ])), // 9702677999813389814729049215331589824309244590168229392617691640937402679279?
            Fr::from(BigInt([
                7510843847969855659,
                16363481456411911964,
                12760593984962864632,
                2164433017059063600,
            ])), // 0? not sure about this one (if padding is sufficient)
        ];

        let start = Instant::now();

        let (pk, vk) =
            <PolyIOP<Fr> as HyperPlonkSNARK<Bn254, MultilinearKzgPCS<Bn254>>>::preprocess(
                &circuit, &pcs_srs,
            )
            .unwrap();

        println!("key extraction: {:?}", start.elapsed());

        println!("public inputs: {:?}", public_inputs);
        println!("public inputs len: {:?}", public_inputs.len());

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
    println!("Time: {}", (end - start).as_micros());
}
