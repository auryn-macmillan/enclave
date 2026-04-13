// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod common;

use e3_zk_prover::{input_map, CompiledCircuit, WitnessGenerator};
use sha2::{Digest, Sha256};

const DUMMY_CIRCUIT: &str = r#"{"noir_version":"1.0.0-beta.15+83245db91dcf63420ef4bcbbd85b98f397fee663","hash":"15412581843239610929","abi":{"parameters":[{"name":"x","type":{"kind":"field"},"visibility":"private"},{"name":"y","type":{"kind":"field"},"visibility":"private"},{"name":"_sum","type":{"kind":"field"},"visibility":"public"}],"return_type":null,"error_types":{}},"bytecode":"H4sIAAAAAAAA/5WOMQ5AMBRA/y8HMbIRRxCJSYwWg8RiIGIz9gjiAk4hHKeb0WLX0KHRDu1bXvL/y89H+HCFu7rtCTeCiiPsgRFo06LUhk0+smgN9iLdKC0rPz6z6RjmhN3LxffE/O7byg+hZv7nAb2HRPkUAQAA","debug_symbols":"jZDRCoMwDEX/Jc996MbG1F8ZQ2qNUghtie1giP++KLrpw2BPaXJ7bsgdocUm97XzXRiguo/QsCNyfU3BmuSCl+k4KdjaOjGijGCnCxUNo09Q+Uyk4GkoL5+GaPxSk2FRtQL0rVQx7Bzh/JrUl9a/0Vu5ssXlA1//psvbSp90ccAf0hnr+HAuaKjO0+zGzjSEawRd9naXSHrFTdkyixwstplxtls0WfAG","file_map":{"50":{"source":"pub fn main(\n    x: Field,\n    y: Field,\n    _sum: pub Field\n) {\n    let sum = x + y;\n    assert(sum == _sum);\n}\n","path":"/Users/ctrlc03/Documents/zk/enclave/circuits/bin/dummy/src/main.nr"}},"expression_width":{"Bounded":{"width":4}}}"#;

#[test]
fn test_witness_generation_from_fixture() {
    let circuit = CompiledCircuit::from_json(DUMMY_CIRCUIT).unwrap();

    let witness_gen = WitnessGenerator::new();
    let inputs = input_map([("x", "5"), ("y", "3"), ("_sum", "8")]).unwrap();
    let witness = witness_gen.generate_witness(&circuit, inputs).unwrap();

    assert!(witness.len() > 2);
    assert_eq!(witness[0], 0x1f);
    assert_eq!(witness[1], 0x8b);
    assert_eq!(
        hex::encode(Sha256::digest(&witness)),
        "0503af42e2e2e68d96638a0917abee95ed280fcc32acfceff9d95a88abb8599a"
    );
}

#[test]
fn test_witness_generation_wrong_sum_fails() {
    let circuit = CompiledCircuit::from_json(DUMMY_CIRCUIT).unwrap();

    let witness_gen = WitnessGenerator::new();
    let inputs = input_map([("x", "5"), ("y", "3"), ("_sum", "10")]).unwrap();
    let result = witness_gen.generate_witness(&circuit, inputs);

    assert!(result.is_err());
}
