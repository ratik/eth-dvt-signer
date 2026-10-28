//! `hash_tree_root` of every Ethereum container the signer hashes, against the consensus
//! specification test vectors (`ssz_static`, mainnet preset), vendored from
//! `ethereum/consensus-spec-tests` (commit in `tests/vectors/ssz_static/SOURCE_COMMIT`).

use eth_mpc_signer::eth::types::*;
use serde::de::DeserializeOwned;
use std::path::Path;
use tree_hash::TreeHash;

fn check<T: DeserializeOwned + TreeHash>(fork: &str, container: &str) -> usize {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/ssz_static")
        .join(fork)
        .join(container);
    let mut cases = 0;
    for case in std::fs::read_dir(&dir).unwrap() {
        let case = case.unwrap().path();
        let value: T =
            serde_yaml::from_str(&std::fs::read_to_string(case.join("value.yaml")).unwrap())
                .unwrap_or_else(|err| panic!("{}: {err}", case.display()));
        let roots: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(case.join("roots.yaml")).unwrap())
                .unwrap();
        let expected = roots["root"].as_str().unwrap();
        let actual = format!("0x{}", hex::encode(value.tree_hash_root()));
        assert_eq!(actual, expected, "{}", case.display());
        cases += 1;
    }
    assert!(cases > 0, "no vectors in {}", dir.display());
    cases
}

#[test]
fn hash_tree_roots_match_the_specification_vectors() {
    let cases = check::<BeaconBlockHeader>("phase0", "BeaconBlockHeader")
        + check::<AttestationData>("phase0", "AttestationData")
        + check::<Checkpoint>("phase0", "Checkpoint")
        + check::<VoluntaryExit>("phase0", "VoluntaryExit")
        + check::<AttestationPhase0>("phase0", "Attestation")
        + check::<AggregateAndProofPhase0>("phase0", "AggregateAndProof")
        + check::<ForkData>("phase0", "ForkData")
        + check::<SigningData>("phase0", "SigningData")
        + check::<SyncAggregatorSelectionData>("altair", "SyncAggregatorSelectionData")
        + check::<SyncCommitteeContribution>("altair", "SyncCommitteeContribution")
        + check::<ContributionAndProof>("altair", "ContributionAndProof")
        + check::<AttestationElectra>("electra", "Attestation")
        + check::<AggregateAndProofElectra>("electra", "AggregateAndProof");
    assert_eq!(cases, 39);
}

mod signing_roots {
    use eth_mpc_signer::eth::{duty::*, types::*};

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        hex::decode(hex.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap()
    }

    /// The `fork_info` of every example of the Web3Signer API specification
    /// (`openapi-specs/eth2/signing/paths/sign.yaml`, Consensys/web3signer master 92eed05).
    fn example_fork() -> ForkInfo {
        ForkInfo {
            fork: Fork {
                previous_version: [0, 0, 0, 1],
                current_version: [0, 0, 0, 1],
                epoch: 1,
            },
            genesis_validators_root: bytes(
                "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673",
            ),
        }
    }

    fn attestation_data(block_root: &str, slot: u64) -> AttestationData {
        AttestationData {
            slot,
            index: 0,
            beacon_block_root: bytes(block_root),
            source: Checkpoint {
                epoch: 0,
                root: [0; 32],
            },
            target: Checkpoint {
                epoch: 0,
                root: bytes(block_root),
            },
        }
    }

    /// Signing roots computed by Web3Signer (an independent implementation, on Teku) for the
    /// examples of its API specification. Its Electra aggregate example does not reproduce with
    /// the mainnet containers; their roots are covered by the specification vectors above.
    #[test]
    fn signing_roots_match_web3signer_examples() {
        let fork = example_fork();
        let selection_proof: Signature = bytes(
            "0xa63f73a03f1f42b1fd0a988b614d511eb346d0a91c809694ef76df5ae021f0f144d64e612d735bc8820950cf6f7f84cd0ae194bfe3d4242fe79688f83462e3f69d9d33de71aab0721b7dab9d6960875e5fdfd26b171a75fb51af822043820c47",
        );
        let aggregate = AttestationPhase0 {
            aggregation_bits: serde_json::from_value(serde_json::json!("0x00000101")).unwrap(),
            data: attestation_data(
                "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd",
                0,
            ),
            signature: bytes(
                "0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875",
            ),
        };
        let cases = [
            (
                Duty::BlockProposal(BeaconBlockHeader {
                    slot: 0,
                    proposer_index: 4666673844721362956,
                    parent_root: bytes(
                        "0x367cbd40ac7318427aadb97345a91fa2e965daf3158d7f1846f1306305f41bef",
                    ),
                    state_root: bytes(
                        "0xfd18cf40cc907a739be483f1ca0ee23ad65cdd3df23205eabc6d660a75d1f54e",
                    ),
                    body_root: bytes(
                        "0xa759d8029a69d4fdd8b3996086e9722983977e4efc1f12f4098ea3d93e868a6b",
                    ),
                }),
                "0xaa2e0c465c1a45d7b6637fcce4ad6ceb71fc12064b548078d619a411f0de8adc",
            ),
            (
                Duty::Attestation(attestation_data(
                    "0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89",
                    32,
                )),
                "0x548c9a015f4c96cb8b1ddbbdfca85846f85bf9f344a434c140f378cdfb5341f0",
            ),
            (
                Duty::AggregationSlot { slot: 119 },
                "0x1fb90dd6e8b2670e6949347bc4eaacd37f9b6cc6e42c559973e362c800e853b9",
            ),
            (
                Duty::RandaoReveal { epoch: 3 },
                "0x3d047c51a8b03630781dc4c5519c17f7de87174246ff2deed0f195c6c775f91e",
            ),
            (
                Duty::VoluntaryExit(VoluntaryExit {
                    epoch: 119,
                    validator_index: 0,
                }),
                "0x38e9f1cfe7926ce5366b633b7fc7113129025737394002d2637faaeefc56913d",
            ),
            (
                Duty::SyncCommitteeMessage {
                    beacon_block_root: bytes(
                        "0x235bc3400c2839fd856a524871200bd5e362db615fc4565e1870ed9a2a936464",
                    ),
                    slot: 0,
                },
                "0xa6f60df2817ea5b52eed1fefebbad746ef64c6249fc05c90c9e0f520cc75bb95",
            ),
            (
                Duty::SyncSelectionProof(SyncAggregatorSelectionData {
                    slot: 0,
                    subcommittee_index: 0,
                }),
                "0x50d85c783ab27c1eb3f3efa914b91cb93ffd677137b15c27ba5bb548306e6963",
            ),
            (
                Duty::AggregateAndProof(AggregateAndProof::Phase0(Box::new(
                    AggregateAndProofPhase0 {
                        aggregator_index: 1,
                        aggregate,
                        selection_proof,
                    },
                ))),
                "0x8d777156899cb02e0e66217afd832886239752a59a393218f6c603bcf615b4f8",
            ),
        ];
        for (duty, expected) in cases {
            assert_eq!(
                format_root(&duty.signing_root(&fork)),
                expected,
                "{:?}",
                duty.kind()
            );
        }
    }

    #[test]
    fn the_fork_version_switches_at_the_fork_epoch() {
        let mut fork = example_fork();
        fork.fork = Fork {
            previous_version: [1, 0, 0, 0],
            current_version: [2, 0, 0, 0],
            epoch: 10,
        };
        assert_eq!(fork.version_at(0), [1, 0, 0, 0]);
        assert_eq!(fork.version_at(9), [1, 0, 0, 0]);
        assert_eq!(fork.version_at(10), [2, 0, 0, 0]);
        assert_eq!(fork.version_at(u64::MAX), [2, 0, 0, 0]);
        // The block's epoch decides: slot 319 is in epoch 9, slot 320 in epoch 10.
        let block = |slot| {
            Duty::BlockProposal(BeaconBlockHeader {
                slot,
                proposer_index: 1,
                parent_root: [1; 32],
                state_root: [2; 32],
                body_root: [3; 32],
            })
        };
        let previous = ForkInfo {
            fork: Fork {
                current_version: [1, 0, 0, 0],
                ..fork.fork
            },
            ..fork
        };
        let current = ForkInfo {
            fork: Fork {
                previous_version: [2, 0, 0, 0],
                ..fork.fork
            },
            ..fork
        };
        assert_eq!(
            block(319).signing_root(&fork),
            block(319).signing_root(&previous)
        );
        assert_eq!(
            block(320).signing_root(&fork),
            block(320).signing_root(&current)
        );
        assert_ne!(
            block(320).signing_root(&fork),
            block(320).signing_root(&previous)
        );
        // Extreme slots do not overflow the epoch computation.
        assert_eq!(block(u64::MAX).epoch(), u64::MAX / SLOTS_PER_EPOCH);
    }

    #[test]
    fn roots_are_separated_by_chain_and_domain() {
        let fork = example_fork();
        let mut other_chain = fork;
        other_chain.genesis_validators_root[0] ^= 1;
        let mut other_version = fork;
        other_version.fork.current_version = [0, 0, 0, 2];
        // The same 8-byte object under different domains: RANDAO (epoch 3) and the selection proof
        // of slot 3 hash the same `uint64`.
        let randao = Duty::RandaoReveal { epoch: 3 };
        let selection = Duty::AggregationSlot { slot: 3 };
        assert_ne!(
            randao.signing_root(&fork),
            randao.signing_root(&other_chain)
        );
        assert_ne!(
            randao.signing_root(&fork),
            randao.signing_root(&other_version)
        );
        assert_ne!(
            randao.signing_root(&fork),
            Duty::RandaoReveal {
                epoch: 3 * SLOTS_PER_EPOCH
            }
            .signing_root(&fork)
        );
        assert_ne!(
            Duty::RandaoReveal { epoch: 0 }.signing_root(&fork),
            Duty::AggregationSlot { slot: 0 }.signing_root(&fork)
        );
        assert_ne!(randao.signing_root(&fork), selection.signing_root(&fork));
    }
}
