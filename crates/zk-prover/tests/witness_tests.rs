// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod common;

use acir::{
    circuit::{Circuit, Opcode, Program, PublicInputs},
    native_types::{Expression, Witness},
    AcirField, FieldElement,
};
use base64::engine::{general_purpose, Engine};
use e3_zk_prover::{input_map, CompiledCircuit, WitnessGenerator};
use noirc_abi::{Abi, AbiParameter, AbiType, AbiVisibility};
use std::collections::BTreeSet;

fn dummy_circuit() -> CompiledCircuit {
    let x = Witness(0);
    let y = Witness(1);
    let sum = Witness(2);

    let expr = Expression {
        mul_terms: Vec::new(),
        linear_combinations: vec![
            (FieldElement::one(), x),
            (FieldElement::one(), y),
            (-FieldElement::one(), sum),
        ],
        q_c: FieldElement::zero(),
    };

    let circuit = Circuit {
        function_name: "main".to_string(),
        current_witness_index: 2,
        opcodes: vec![Opcode::AssertZero(expr)],
        private_parameters: BTreeSet::from([x, y, sum]),
        public_parameters: PublicInputs(BTreeSet::new()),
        return_values: PublicInputs(BTreeSet::new()),
        assert_messages: Vec::new(),
        num_phases: 0,
    };

    let program = Program { functions: vec![circuit], unconstrained_functions: Vec::new() };
    let bytecode = general_purpose::STANDARD.encode(Program::serialize_program(&program));

    CompiledCircuit {
        bytecode,
        abi: Abi {
            parameters: vec![
                AbiParameter {
                    name: "x".to_string(),
                    typ: AbiType::Field,
                    visibility: AbiVisibility::Private,
                },
                AbiParameter {
                    name: "y".to_string(),
                    typ: AbiType::Field,
                    visibility: AbiVisibility::Private,
                },
                AbiParameter {
                    name: "_sum".to_string(),
                    typ: AbiType::Field,
                    visibility: AbiVisibility::Private,
                },
            ],
            return_type: None,
            error_types: Default::default(),
        },
    }
}

#[test]
fn test_witness_generation_from_fixture() {
    let circuit = dummy_circuit();

    let witness_gen = WitnessGenerator::new();
    let inputs = input_map([("x", "5"), ("y", "3"), ("_sum", "8")]).unwrap();
    let witness = witness_gen.generate_witness(&circuit, inputs).unwrap();

    assert!(witness.len() > 2);
    assert_eq!(witness[0], 0x1f);
    assert_eq!(witness[1], 0x8b);
}

#[test]
fn test_witness_generation_wrong_sum_fails() {
    let circuit = dummy_circuit();

    let witness_gen = WitnessGenerator::new();
    let inputs = input_map([("x", "5"), ("y", "3"), ("_sum", "10")]).unwrap();
    let result = witness_gen.generate_witness(&circuit, inputs);

    assert!(result.is_err());
}
