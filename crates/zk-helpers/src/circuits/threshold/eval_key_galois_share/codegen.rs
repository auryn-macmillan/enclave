// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::circuits::computation::Computation;
use crate::threshold::eval_key_galois_share::circuit::EvalKeyGaloisShareCircuit;
use crate::threshold::eval_key_galois_share::computation::{Configs, Inputs};
use crate::threshold::eval_key_galois_share::EvalKeyGaloisShareCircuitData;
use crate::{Artifacts, Circuit, CircuitCodegen, CircuitsErrors};
use e3_fhe_params::BfvPreset;

impl CircuitCodegen for EvalKeyGaloisShareCircuit {
    type Preset = BfvPreset;
    type Data = EvalKeyGaloisShareCircuitData;
    type Error = CircuitsErrors;

    fn codegen(&self, preset: Self::Preset, data: &Self::Data) -> Result<Artifacts, Self::Error> {
        let inputs = Inputs::compute(preset, data)?;
        let configs = Configs::compute(preset, &())?;
        Ok(Artifacts {
            toml: toml::to_string(&inputs).map_err(CircuitsErrors::Toml)?,
            configs: format!(
                "pub global {}_N: u32 = {};\npub global {}_L: u32 = {};\npub global {}_SK_BIT: u32 = {};\npub global {}_TRANSFORMED_SK_BIT: u32 = {};\npub global {}_C0_BIT: u32 = {};\n",
                <EvalKeyGaloisShareCircuit as Circuit>::PREFIX,
                configs.n,
                <EvalKeyGaloisShareCircuit as Circuit>::PREFIX,
                configs.l,
                <EvalKeyGaloisShareCircuit as Circuit>::PREFIX,
                configs.bits.sk_bit,
                <EvalKeyGaloisShareCircuit as Circuit>::PREFIX,
                configs.bits.transformed_sk_bit,
                <EvalKeyGaloisShareCircuit as Circuit>::PREFIX,
                configs.bits.c0_bit,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::write_artifacts;
    use crate::threshold::eval_key_galois_share::EvalKeyGaloisShareCircuitData;
    use e3_fhe_params::BfvPreset;
    use tempfile::TempDir;

    #[test]
    fn test_c8_codegen_smoke() {
        let sample =
            EvalKeyGaloisShareCircuitData::generate_sample(BfvPreset::InsecureThreshold512)
                .unwrap();
        let artifacts = EvalKeyGaloisShareCircuit
            .codegen(BfvPreset::InsecureThreshold512, &sample)
            .unwrap();

        let parsed: toml::Value = artifacts.toml.parse().unwrap();
        assert!(parsed.get("secret_key_share").is_some());
        assert!(parsed.get("substituted_secret_share").is_some());
        assert!(parsed.get("transformed_secret_share").is_some());
        assert!(parsed.get("garner_coefficient").is_some());

        let temp_dir = TempDir::new().unwrap();
        write_artifacts(
            Some(&artifacts.toml),
            &artifacts.configs,
            Some(temp_dir.path()),
        )
        .unwrap();

        assert!(temp_dir.path().join("Prover.toml").exists());
        assert!(temp_dir.path().join("configs.nr").exists());
    }
}
