// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::circuits::computation::Computation;
use crate::threshold::eval_key_relin_round2_share::circuit::EvalKeyRelinRound2ShareCircuit;
use crate::threshold::eval_key_relin_round2_share::computation::{Configs, Inputs};
use crate::threshold::eval_key_relin_round2_share::EvalKeyRelinRound2ShareCircuitData;
use crate::{Artifacts, Circuit, CircuitCodegen, CircuitsErrors};
use e3_fhe_params::BfvPreset;

impl CircuitCodegen for EvalKeyRelinRound2ShareCircuit {
    type Preset = BfvPreset;
    type Data = EvalKeyRelinRound2ShareCircuitData;
    type Error = CircuitsErrors;

    fn codegen(&self, preset: Self::Preset, data: &Self::Data) -> Result<Artifacts, Self::Error> {
        let inputs = Inputs::compute(preset, data)?;
        let configs = Configs::compute(preset, &())?;
        Ok(Artifacts {
            toml: toml::to_string(&inputs).map_err(CircuitsErrors::Toml)?,
            configs: format!(
                "pub global {}_N: u32 = {};\npub global {}_L: u32 = {};\npub global {}_BIT_SK: u32 = {};\npub global {}_BIT_U: u32 = {};\npub global {}_BIT_ERROR: u32 = {};\npub global {}_BIT_R: u32 = {};\npub global {}_ERROR_BOUND: Field = {};\n",
                <EvalKeyRelinRound2ShareCircuit as Circuit>::PREFIX,
                configs.n,
                <EvalKeyRelinRound2ShareCircuit as Circuit>::PREFIX,
                configs.l,
                <EvalKeyRelinRound2ShareCircuit as Circuit>::PREFIX,
                configs.bits.sk_bit,
                <EvalKeyRelinRound2ShareCircuit as Circuit>::PREFIX,
                configs.bits.u_bit,
                <EvalKeyRelinRound2ShareCircuit as Circuit>::PREFIX,
                configs.bits.error_bit,
                <EvalKeyRelinRound2ShareCircuit as Circuit>::PREFIX,
                configs.bits.r_bit,
                <EvalKeyRelinRound2ShareCircuit as Circuit>::PREFIX,
                configs.bounds.error_bound,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::write_artifacts;
    use tempfile::TempDir;

    #[test]
    fn test_c10_codegen_smoke() {
        let sample =
            EvalKeyRelinRound2ShareCircuitData::generate_sample(BfvPreset::InsecureThreshold512)
                .unwrap();
        let artifacts = EvalKeyRelinRound2ShareCircuit
            .codegen(BfvPreset::InsecureThreshold512, &sample)
            .unwrap();

        let parsed: toml::Value = artifacts.toml.parse().unwrap();
        assert!(parsed.get("secret_key_share").is_some());
        assert!(parsed.get("ephemeral_u_share").is_some());
        assert!(parsed.get("h0_aggregate").is_some());

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
