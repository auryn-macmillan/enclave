// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE

use crate::traits::Provable;
use e3_events::CircuitName;
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::circuits::threshold::eval_key_relin_round2_share::circuit::{
    EvalKeyRelinRound2ShareCircuit, EvalKeyRelinRound2ShareCircuitData,
};
use e3_zk_helpers::circuits::threshold::eval_key_relin_round2_share::computation::Inputs;

impl Provable for EvalKeyRelinRound2ShareCircuit {
    type Params = BfvPreset;
    type Input = EvalKeyRelinRound2ShareCircuitData;
    type Inputs = Inputs;

    fn circuit(&self) -> CircuitName {
        CircuitName::EvalKeyRelinRound2Share
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::ZkProver;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use tokio::fs;

    const REQUIRED_BB_VERSION: &str = "3.0.0-nightly.20260102";

    fn dist_circuits_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("dist")
            .join("circuits")
    }

    fn threshold_target_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("circuits")
            .join("bin")
            .join("threshold")
            .join("target")
    }

    async fn discover_compatible_bb() -> Option<PathBuf> {
        fn home_candidates() -> Vec<PathBuf> {
            std::env::var("HOME")
                .ok()
                .map(|home| {
                    vec![
                        PathBuf::from(format!("{home}/.bb/bb")),
                        PathBuf::from(format!("{home}/.nargo/bin/bb")),
                        PathBuf::from(format!("{home}/.enclave/noir/bin/bb")),
                        PathBuf::from("/usr/local/bin/bb"),
                    ]
                })
                .unwrap_or_else(|| vec![PathBuf::from("/usr/local/bin/bb")])
        }

        async fn version_of(path: &PathBuf) -> Option<String> {
            let output = tokio::process::Command::new(path)
                .arg("--version")
                .output()
                .await
                .ok()?;
            if !output.status.success() {
                return None;
            }
            Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }

        let mut candidates = Vec::<PathBuf>::new();

        if let Ok(path) = std::env::var("E3_CUSTOM_BB") {
            candidates.push(PathBuf::from(path));
        }

        if let Ok(output) = tokio::process::Command::new("which")
            .arg("-a")
            .arg("bb")
            .output()
            .await
        {
            if output.status.success() {
                candidates.extend(
                    String::from_utf8_lossy(&output.stdout)
                        .lines()
                        .map(str::trim)
                        .filter(|line| !line.is_empty())
                        .map(PathBuf::from),
                );
            }
        }

        candidates.extend(home_candidates());

        candidates.sort();
        candidates.dedup();

        let mut fallback_v3 = None;

        for candidate in candidates {
            if !candidate.exists() {
                continue;
            }

            let Some(version) = version_of(&candidate).await else {
                continue;
            };

            if version.contains(REQUIRED_BB_VERSION) {
                return Some(candidate);
            }

            if fallback_v3.is_none() && version.starts_with("3.") {
                fallback_v3 = Some(candidate);
            }
        }

        fallback_v3
    }

    #[tokio::test]
    async fn test_c10_prove_smoke() {
        let Some(bb) = discover_compatible_bb().await else {
            eprintln!(
                "skipping C10 smoke test: compatible bb binary not found (need {})",
                REQUIRED_BB_VERSION
            );
            return;
        };

        let temp = TempDir::new().unwrap();

        let noir_dir = temp.path().join("noir");
        let circuits_dir = noir_dir.join("circuits");
        let work_dir = noir_dir.join("work").join("test_node");
        let backend = crate::backend::ZkBackend::new(
            e3_config::BBPath::Custom(bb),
            circuits_dir.clone(),
            work_dir,
        );

        fs::create_dir_all(&circuits_dir).await.unwrap();
        fs::create_dir_all(backend.base_dir.join("bin")).await.unwrap();
        fs::create_dir_all(&backend.work_dir).await.unwrap();

        fs::create_dir_all(
            circuits_dir
                .join("recursive")
                .join("threshold")
                .join("eval_key_relin_round2_share"),
        )
        .await
        .unwrap();

        let dist = dist_circuits_path();
        let target = circuits_dir
            .join("recursive")
            .join("threshold")
            .join("eval_key_relin_round2_share");

        let target_build = threshold_target_path();
        let json_src = if target_build.join("eval_key_relin_round2_share.json").exists() {
            target_build.join("eval_key_relin_round2_share.json")
        } else {
            dist.join("recursive")
                .join("threshold")
                .join("eval_key_relin_round2_share")
                .join("eval_key_relin_round2_share.json")
        };
        let vk_src = if target_build
            .join("eval_key_relin_round2_share.vk_noir")
            .exists()
        {
            target_build.join("eval_key_relin_round2_share.vk_noir")
        } else if target_build
            .join("eval_key_relin_round2_share.vk_recursive")
            .exists()
        {
            target_build.join("eval_key_relin_round2_share.vk_recursive")
        } else if target_build.join("eval_key_relin_round2_share.vk").exists() {
            target_build.join("eval_key_relin_round2_share.vk")
        } else {
            dist.join("recursive")
                .join("threshold")
                .join("eval_key_relin_round2_share")
                .join("eval_key_relin_round2_share.vk")
        };

        if json_src.exists() && vk_src.exists() {
            fs::copy(
                &json_src,
                target.join("eval_key_relin_round2_share.json"),
            )
            .await
            .unwrap();
            fs::copy(&vk_src, target.join("eval_key_relin_round2_share.vk"))
                .await
                .unwrap();
        }

        let prover = ZkProver::new(&backend);
        let circuit_dir = prover
            .circuits_dir(e3_events::CircuitVariant::Recursive)
            .join(CircuitName::EvalKeyRelinRound2Share.dir_path());
        if !circuit_dir.join("eval_key_relin_round2_share.json").exists()
            || !circuit_dir.join("eval_key_relin_round2_share.vk").exists()
        {
            panic!(
                "C10 circuit not found at {} — build circuits and ensure dist/circuits includes threshold/eval_key_relin_round2_share",
                circuit_dir.display()
            );
        }

        let preset = BfvPreset::InsecureThreshold512;
        let sample = EvalKeyRelinRound2ShareCircuitData::generate_sample(preset)
            .expect("sample generation");
        let proof = EvalKeyRelinRound2ShareCircuit
            .prove(&prover, &preset, &sample, "c10-smoke")
            .expect("C10 prove should succeed");

        assert!(!proof.data.is_empty());
        assert!(!proof.public_signals.is_empty());

        let verified = EvalKeyRelinRound2ShareCircuit
            .verify(&prover, &proof, "c10-smoke", 0)
            .expect("C10 verify should succeed");
        assert!(verified, "C10 proof verification must pass");
    }
}
