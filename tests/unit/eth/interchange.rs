//! Unit tests of `crate::eth::interchange`: a child module of it (`#[path]` in `src/eth/interchange.rs`),
//! so private items are in scope.

use super::*;
use crate::{
    eth::duty::Protection as Rule,
    slashing::{
        Activation, Decision, Floors, HistoryOutcome, HistoryRefusal, ImportedValidator,
        Protection, Refusal, Validator,
    },
};
use serde::Deserialize;
use std::collections::BTreeSet;

const KEY_A: &str = "0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c";
const KEY_B: &str = "0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b";
const GVR: &str = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

fn key(text: &str) -> ValidatorKey {
    unhex_array(text).unwrap()
}

fn root(byte: u8) -> Root {
    [byte; 32]
}

fn chain(text: &str) -> ChainIdentity {
    ChainIdentity {
        genesis_validators_root: unhex_array(text).unwrap(),
    }
}

/// A protection with `keys` as imported validators, activated for `chain` (rounds 0..).
fn protection(keys: &[ValidatorKey], chain: ChainIdentity) -> Protection {
    let mut protection = Protection::default();
    for (id, key) in keys.iter().enumerate() {
        let round = id as u64;
        protection.designate(round);
        protection.restore_validator(
            id as u64,
            Validator {
                key: *key,
                round,
                activation: Some(Activation { chain, height: 0 }),
                legacy_chain: None,
                records: 0,
            },
        );
        protection.restore_imported(
            id as u64,
            ImportedValidator {
                round,
                chain: Some(chain),
                floors: Floors::default(),
                imports: 1,
                acknowledged: Some(0),
            },
        );
    }
    protection
}

fn interchange(json: serde_json::Value) -> Result<Interchange, Error> {
    parse(&serde_json::to_vec(&json).unwrap())
}

fn document(data: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "metadata": {"interchange_format_version": "5", "genesis_validators_root": GVR},
        "data": data,
    })
}

fn import_into(
    protection: &mut Protection,
    json: serde_json::Value,
) -> Result<HistoryOutcome, String> {
    let interchange = interchange(json).map_err(|err| err.to_string())?;
    let import = interchange.import(None).map_err(|err| err.to_string())?;
    match protection.import_history(&import).0 {
        HistoryOutcome::Refused(refusal) => Err(refusal.to_string()),
        outcome => Ok(outcome),
    }
}

fn sign_block(protection: &mut Protection, id: u64, slot: u64, signing_root: Root) -> bool {
    protection
        .authorize_raw(id, Rule::Proposal { slot }, signing_root, 1)
        .is_authorized()
}

fn sign_attestation(
    protection: &mut Protection,
    id: u64,
    source: u64,
    target: u64,
    signing_root: Root,
) -> bool {
    protection
        .authorize_raw(id, Rule::Attestation { source, target }, signing_root, 1)
        .is_authorized()
}

// The EIP-3076 interchange test suite (tests/vectors/eip3076).

#[derive(Deserialize)]
struct Case {
    name: String,
    genesis_validators_root: String,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    should_succeed: bool,
    contains_slashable_data: bool,
    interchange: serde_json::Value,
    blocks: Vec<Attempt>,
    attestations: Vec<Attempt>,
}

#[derive(Deserialize)]
struct Attempt {
    pubkey: String,
    #[serde(default)]
    slot: Option<String>,
    #[serde(default)]
    source_epoch: Option<String>,
    #[serde(default)]
    target_epoch: Option<String>,
    #[serde(default)]
    signing_root: Option<String>,
    should_succeed: bool,
    should_succeed_complete: bool,
}

/// Every case of the suite. Imported history is kept in the minimal form and the network's own
/// records in full, so a signing must succeed whenever the minimal strategy succeeds
/// (`should_succeed`), and fail whenever even the complete strategy fails
/// (`should_succeed_complete`). A step whose interchange is slashable may be refused, which ends
/// the case (the suite's rule); any other step must import exactly as expected.
#[test]
fn eip3076_interchange_vectors() {
    let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/eip3076/v5.3.0");
    let mut files: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    assert_eq!(files.len(), 38, "the suite has 38 cases");
    let (mut attempts, mut refused_slashable) = (0, 0);
    for file in files {
        let case: Case = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        let mut keys: Vec<ValidatorKey> = Vec::new();
        for step in &case.steps {
            let data = step.interchange["data"].as_array().unwrap();
            let pubkeys = data
                .iter()
                .map(|entry| entry["pubkey"].as_str().unwrap().to_string())
                .chain(
                    step.blocks
                        .iter()
                        .chain(&step.attestations)
                        .map(|attempt| attempt.pubkey.clone()),
                );
            for pubkey in pubkeys {
                let key = key(&pubkey);
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        let mut protection = protection(&keys, chain(&case.genesis_validators_root));
        let id = |pubkey: &str| {
            keys.iter()
                .position(|candidate| *candidate == key(pubkey))
                .unwrap() as u64
        };
        'steps: for (index, step) in case.steps.iter().enumerate() {
            let context = format!("{} step {index}", case.name);
            let imported = import_into(&mut protection, step.interchange.clone());
            match (&imported, step.should_succeed) {
                (Ok(_), true) | (Err(_), false) => {}
                (Err(_), true) if step.contains_slashable_data => {
                    refused_slashable += 1;
                    break 'steps;
                }
                (Err(reason), true) => panic!("{context}: refused a valid interchange: {reason}"),
                (Ok(_), false) => panic!("{context}: imported an invalid interchange"),
            }
            for block in &step.blocks {
                let slot: u64 = block.slot.as_deref().unwrap().parse().unwrap();
                let signing_root = block
                    .signing_root
                    .as_deref()
                    .map(|r| unhex_array(r).unwrap())
                    .unwrap_or_default();
                let signed = sign_block(&mut protection, id(&block.pubkey), slot, signing_root);
                attempts += 1;
                if block.should_succeed {
                    assert!(
                        signed,
                        "{context}: block at slot {slot} refused (the minimal strategy signs it)"
                    );
                }
                if !block.should_succeed_complete {
                    assert!(
                        !signed,
                        "{context}: block at slot {slot} signed (even the complete strategy refuses it)"
                    );
                }
            }
            for attestation in &step.attestations {
                let source: u64 = attestation
                    .source_epoch
                    .as_deref()
                    .unwrap()
                    .parse()
                    .unwrap();
                let target: u64 = attestation
                    .target_epoch
                    .as_deref()
                    .unwrap()
                    .parse()
                    .unwrap();
                let signing_root = attestation
                    .signing_root
                    .as_deref()
                    .map(|r| unhex_array(r).unwrap())
                    .unwrap_or_default();
                let signed = sign_attestation(
                    &mut protection,
                    id(&attestation.pubkey),
                    source,
                    target,
                    signing_root,
                );
                attempts += 1;
                if attestation.should_succeed {
                    assert!(
                        signed,
                        "{context}: attestation {source}->{target} refused (the minimal strategy signs it)"
                    );
                }
                if !attestation.should_succeed_complete {
                    assert!(
                        !signed,
                        "{context}: attestation {source}->{target} signed (even the complete strategy refuses it)"
                    );
                }
            }
        }
    }
    println!(
        "eip3076: {attempts} signing attempts checked, {refused_slashable} slashable interchanges refused"
    );
}

// Parsing.

#[test]
fn malformed_interchanges_are_refused() {
    let valid = document(
        serde_json::json!([{"pubkey": KEY_A, "signed_blocks": [{"slot": "10"}], "signed_attestations": []}]),
    );
    assert!(interchange(valid.clone()).is_ok());
    type Change = fn(&mut serde_json::Value);
    let cases: &[(&str, Change)] = &[
        ("version 4", |v| {
            v["metadata"]["interchange_format_version"] = "4".into()
        }),
        ("numeric version", |v| {
            v["metadata"]["interchange_format_version"] = 5.into()
        }),
        ("short root", |v| {
            v["metadata"]["genesis_validators_root"] = "0x0470".into()
        }),
        ("no 0x", |v| v["data"][0]["pubkey"] = KEY_A[2..].into()),
        ("hex slot", |v| {
            v["data"][0]["signed_blocks"][0]["slot"] = "0x10".into()
        }),
        ("signed slot", |v| {
            v["data"][0]["signed_blocks"][0]["slot"] = "+10".into()
        }),
        ("numeric slot", |v| {
            v["data"][0]["signed_blocks"][0]["slot"] = 10.into()
        }),
        ("empty slot", |v| {
            v["data"][0]["signed_blocks"][0]["slot"] = "".into()
        }),
        ("overflowing slot", |v| {
            v["data"][0]["signed_blocks"][0]["slot"] = "18446744073709551616".into()
        }),
        ("unknown field", |v| v["data"][0]["extra"] = 1.into()),
        ("missing attestations", |v| {
            v["data"][0]
                .as_object_mut()
                .unwrap()
                .remove("signed_attestations");
        }),
        ("bad signing root", |v| {
            v["data"][0]["signed_blocks"][0]["signing_root"] = "0x00".into()
        }),
    ];
    for (name, change) in cases {
        let mut json = valid.clone();
        change(&mut json);
        assert!(interchange(json).is_err(), "{name} was accepted");
    }
}

#[test]
fn self_slashable_histories_are_refused_and_duplicates_merged() {
    let block = |slot: &str, root: Option<Root>| match root {
        Some(root) => serde_json::json!({"slot": slot, "signing_root": hex0x(&root)}),
        None => serde_json::json!({"slot": slot}),
    };
    let attestation = |source: &str, target: &str, root: Option<Root>| match root {
        Some(root) => {
            serde_json::json!({"source_epoch": source, "target_epoch": target, "signing_root": hex0x(&root)})
        }
        None => serde_json::json!({"source_epoch": source, "target_epoch": target}),
    };
    let one = |blocks: Vec<serde_json::Value>, attestations: Vec<serde_json::Value>| {
        document(
            serde_json::json!([{"pubkey": KEY_A, "signed_blocks": blocks, "signed_attestations": attestations}]),
        )
    };
    let slashable = |json| matches!(interchange(json), Err(Error::Slashable { .. }));

    // Blocks: same slot, different roots; a root and no root; vs exact duplicates.
    assert!(slashable(one(
        vec![block("10", Some(root(1))), block("10", Some(root(2)))],
        vec![]
    )));
    assert!(slashable(one(
        vec![block("10", Some(root(1))), block("10", None)],
        vec![]
    )));
    let merged = interchange(one(
        vec![
            block("10", Some(root(1))),
            block("10", Some(root(1))),
            block("9", None),
            block("9", None),
        ],
        vec![],
    ))
    .unwrap();
    assert_eq!(merged.validators[&key(KEY_A)].blocks.len(), 2);

    // Attestations: double vote, surround both ways, source after target; exact duplicates.
    assert!(slashable(one(
        vec![],
        vec![
            attestation("1", "3", Some(root(1))),
            attestation("1", "3", Some(root(2)))
        ]
    )));
    assert!(slashable(one(
        vec![],
        vec![attestation("1", "3", None), attestation("2", "3", None)]
    )));
    assert!(slashable(one(
        vec![],
        vec![attestation("2", "3", None), attestation("1", "4", None)]
    )));
    assert!(slashable(one(
        vec![],
        vec![attestation("1", "4", None), attestation("2", "3", None)]
    )));
    assert!(slashable(one(vec![], vec![attestation("5", "4", None)])));
    let merged = interchange(one(
        vec![],
        vec![
            attestation("1", "3", Some(root(1))),
            attestation("1", "3", Some(root(1))),
            attestation("3", "5", None),
        ],
    ))
    .unwrap();
    assert_eq!(merged.validators[&key(KEY_A)].attestations.len(), 2);

    // Entries of one key are merged before the checks.
    let split = document(serde_json::json!([
        {"pubkey": KEY_A, "signed_blocks": [block("10", Some(root(1)))], "signed_attestations": []},
        {"pubkey": KEY_A, "signed_blocks": [block("10", Some(root(2)))], "signed_attestations": []},
    ]));
    assert!(slashable(split));
}

#[test]
fn the_summary_is_the_latest_block_and_attestation_and_the_digest_ignores_formatting() {
    let first = document(serde_json::json!([
        {"pubkey": KEY_A, "signed_blocks": [{"slot": "7"}, {"slot": "12", "signing_root": hex0x(&root(3))}],
         "signed_attestations": [{"source_epoch": "1", "target_epoch": "2"}, {"source_epoch": "4", "target_epoch": "9", "signing_root": hex0x(&root(4))}]},
        {"pubkey": KEY_B, "signed_blocks": [], "signed_attestations": []},
    ]));
    let parsed = interchange(first).unwrap();
    let summary = parsed.validators[&key(KEY_A)].summary();
    assert_eq!(
        summary.block,
        Some(ImportedBlock {
            slot: 12,
            signing_root: Some(root(3))
        })
    );
    assert_eq!(
        summary.attestation,
        Some(ImportedAttestation {
            source: 4,
            target: 9,
            signing_root: Some(root(4))
        })
    );
    assert_eq!(
        parsed.validators[&key(KEY_B)].summary(),
        HistorySummary::default()
    );

    // The same records in another order, split over entries, with duplicates: same digest.
    let second = document(serde_json::json!([
        {"pubkey": KEY_B, "signed_blocks": [], "signed_attestations": []},
        {"pubkey": KEY_A, "signed_blocks": [{"slot": "12", "signing_root": hex0x(&root(3))}], "signed_attestations": [{"source_epoch": "4", "target_epoch": "9", "signing_root": hex0x(&root(4))}]},
        {"pubkey": KEY_A, "signed_blocks": [{"slot": "7"}, {"slot": "7"}], "signed_attestations": [{"source_epoch": "1", "target_epoch": "2"}]},
    ]));
    assert_eq!(interchange(second).unwrap().digest(), parsed.digest());
    let mut third = parsed.clone();
    third
        .validators
        .get_mut(&key(KEY_A))
        .unwrap()
        .blocks
        .insert(13, None);
    assert_ne!(third.digest(), parsed.digest());

    // Selecting validators: only those, and each must be in the interchange.
    assert_eq!(
        parsed.import(Some(&[key(KEY_B)])).unwrap().validators.len(),
        1
    );
    assert!(parsed.import(Some(&[[9; 48]])).is_err());
}

// Merging into the network's records.

#[test]
fn imports_only_raise_floors_and_never_contradict_local_records() {
    let a = key(KEY_A);
    let mut protection = protection(&[a], chain(GVR));
    let history = |slot: &str, source: &str, target: &str| {
        document(
            serde_json::json!([{"pubkey": KEY_A, "signed_blocks": [{"slot": slot}],
            "signed_attestations": [{"source_epoch": source, "target_epoch": target}]}]),
        )
    };
    assert_eq!(
        import_into(&mut protection, history("100", "10", "11")),
        Ok(HistoryOutcome::Imported)
    );
    // Identical and older histories change nothing: the floors only rise.
    assert_eq!(
        import_into(&mut protection, history("100", "10", "11")),
        Ok(HistoryOutcome::Unchanged)
    );
    assert_eq!(
        import_into(&mut protection, history("50", "3", "4")),
        Ok(HistoryOutcome::Unchanged)
    );
    let floors = protection.imported(0).unwrap().floors;
    assert_eq!(
        floors,
        Floors {
            block: Some(100),
            attestation: Some((10, 11))
        }
    );
    assert!(!sign_block(&mut protection, 0, 100, root(0)));
    assert!(!sign_block(&mut protection, 0, 60, root(0)));
    assert!(!sign_attestation(&mut protection, 0, 9, 12, root(0)));
    assert!(!sign_attestation(&mut protection, 0, 10, 11, root(0)));

    // The network signs above the floors; a later import must not contradict what it signed.
    assert!(sign_block(&mut protection, 0, 101, root(1)));
    assert!(sign_attestation(&mut protection, 0, 10, 12, root(2)));
    assert!(sign_attestation(&mut protection, 0, 12, 14, root(3)));
    let conflict = |json| matches!(import_into(&mut protection.clone(), json), Err(reason) if reason.contains("slashable with respect to this signer"));
    // Another block for slot 101; another attestation for target 14; one surrounding 12->14; one
    // surrounded by 10->12... (11->12 is a double vote for target 12).
    assert!(conflict(history("101", "10", "11")));
    assert!(conflict(document(
        serde_json::json!([{"pubkey": KEY_A, "signed_blocks": [], "signed_attestations": [{"source_epoch": "12", "target_epoch": "14"}]}])
    )));
    assert!(conflict(document(
        serde_json::json!([{"pubkey": KEY_A, "signed_blocks": [], "signed_attestations": [{"source_epoch": "11", "target_epoch": "15"}]}])
    )));
    assert!(conflict(document(
        serde_json::json!([{"pubkey": KEY_A, "signed_blocks": [], "signed_attestations": [{"source_epoch": "13", "target_epoch": "13"}]}])
    )));
    // An older history merges with the newer records: they stay, the floors stay.
    assert_eq!(
        import_into(&mut protection, history("90", "8", "9")),
        Ok(HistoryOutcome::Unchanged)
    );
    assert!(protection.proposal(0, 101).is_some() && protection.attestation(0, 14).is_some());
    // A newer one raises the floors above the network's records.
    assert_eq!(
        import_into(&mut protection, history("200", "20", "21")),
        Ok(HistoryOutcome::Imported)
    );
    assert!(!sign_block(&mut protection, 0, 150, root(9)));
    assert!(sign_block(&mut protection, 0, 201, root(9)));
}

#[test]
fn imports_are_refused_for_another_chain_unknown_or_non_imported_keys() {
    let a = key(KEY_A);
    let mut protection = protection(&[a], chain(GVR));
    let mut json = document(
        serde_json::json!([{"pubkey": KEY_A, "signed_blocks": [], "signed_attestations": []}]),
    );
    json["metadata"]["genesis_validators_root"] = hex0x(&[1; 32]).into();
    let import = interchange(json).unwrap().import(None).unwrap();
    assert!(matches!(
        protection.import_history(&import).0,
        HistoryOutcome::Refused(HistoryRefusal::OtherChain { .. })
    ));
    let unknown = document(
        serde_json::json!([{"pubkey": KEY_B, "signed_blocks": [], "signed_attestations": []}]),
    );
    let import = interchange(unknown).unwrap().import(None).unwrap();
    assert!(matches!(
        protection.import_history(&import).0,
        HistoryOutcome::Refused(HistoryRefusal::UnknownValidator { .. })
    ));
    // A DKG key (no import state) takes no history.
    let mut dkg = Protection::default();
    dkg.designate(0);
    dkg.register(0, key(KEY_B));
    assert!(matches!(
        dkg.import_history(&import).0,
        HistoryOutcome::Refused(HistoryRefusal::NotImported { .. })
    ));
    // Nothing named, or one key twice.
    let mut empty = import.clone();
    empty.validators.clear();
    assert!(matches!(
        protection.import_history(&empty).0,
        HistoryOutcome::Refused(HistoryRefusal::Validators)
    ));
}

#[test]
fn a_missing_signing_root_is_conservative() {
    let a = key(KEY_A);
    let mut protection = protection(&[a], chain(GVR));
    import_into(
        &mut protection,
        document(
            serde_json::json!([{"pubkey": KEY_A, "signed_blocks": [{"slot": "5"}],
        "signed_attestations": [{"source_epoch": "1", "target_epoch": "2"}]}]),
        ),
    )
    .unwrap();
    // Nothing at the floor is signed, whatever the root (there is no root to repeat).
    for candidate in [root(0), root(1)] {
        assert!(!sign_block(&mut protection, 0, 5, candidate));
        assert!(!sign_attestation(&mut protection, 0, 1, 2, candidate));
    }
    assert!(matches!(
        protection.authorize_raw(0, Rule::Proposal { slot: 5 }, root(0), 1),
        Decision::Refused(Refusal::BlockAtOrBelowImported { slot: 5, floor: 5 })
    ));
    assert!(sign_block(&mut protection, 0, 6, root(0)));
}

// Export.

/// Every duty in a grid of slots and epochs that `protection` refuses for `id`, the protection an
/// export of it gives a fresh signer also refuses: this network, and a signer that follows
/// EIP-3076's conditions as written ([Reference]).
fn assert_export_is_conservative(protection: &Protection, id: u64, key: ValidatorKey) {
    let exported = protection.export(id);
    let json = export(&chain(GVR), &[(key, exported)]);
    let mut receiver = self::protection(&[key], chain(GVR));
    import_into(&mut receiver, serde_json::to_value(&json).unwrap()).unwrap();
    let mut reference = Reference::default();
    reference.import(&from_json(&json).unwrap().validators[&key]);
    for slot in 0..40 {
        let mut ours = protection.clone();
        if !sign_block(&mut ours, id, slot, root(0xee)) {
            assert!(
                !sign_block(&mut receiver.clone(), 0, slot, root(0xee)),
                "block {slot}"
            );
            assert!(
                !reference.clone().sign_block(slot, root(0xee)),
                "block {slot} (reference)"
            );
        }
    }
    for source in 0..12 {
        for target in source..14 {
            let mut ours = protection.clone();
            if !sign_attestation(&mut ours, id, source, target, root(0xee)) {
                assert!(
                    !sign_attestation(&mut receiver.clone(), 0, source, target, root(0xee)),
                    "attestation {source}->{target}"
                );
                assert!(
                    !reference
                        .clone()
                        .sign_attestation(source, target, root(0xee)),
                    "attestation {source}->{target} (reference)"
                );
            }
        }
    }
}

#[test]
fn exports_round_trip_and_stay_conservative() {
    let a = key(KEY_A);
    // Imported floors, then the network's own records above them.
    let mut protection = protection(&[a], chain(GVR));
    import_into(
        &mut protection,
        document(
            serde_json::json!([{"pubkey": KEY_A, "signed_blocks": [{"slot": "10"}],
        "signed_attestations": [{"source_epoch": "3", "target_epoch": "4"}]}]),
        ),
    )
    .unwrap();
    assert!(sign_block(&mut protection, 0, 15, root(1)));
    assert!(sign_block(&mut protection, 0, 20, root(2)));
    assert!(sign_attestation(&mut protection, 0, 4, 6, root(3)));
    assert!(sign_attestation(&mut protection, 0, 6, 8, root(4)));
    let exported = protection.export(0);
    assert_eq!(
        exported.blocks,
        vec![(10, None), (15, Some(root(1))), (20, Some(root(2)))]
    );
    assert_eq!(
        exported.attestations,
        vec![(3, 4, None), (4, 6, Some(root(3))), (6, 8, Some(root(4)))]
    );
    // The export is itself a valid interchange (not slashable) and parses back to the same records.
    let json = export(&chain(GVR), &[(a, exported.clone())]);
    let parsed = from_json(&json).unwrap();
    assert_eq!(parsed.validators[&a].blocks.len(), 3);
    assert_conservative_and_repeatable(&protection, a);

    // A newer import after local signing: the export starts at the new floors.
    import_into(
        &mut protection,
        document(
            serde_json::json!([{"pubkey": KEY_A, "signed_blocks": [{"slot": "25"}],
        "signed_attestations": [{"source_epoch": "8", "target_epoch": "9"}]}]),
        ),
    )
    .unwrap();
    let exported = protection.export(0);
    assert_eq!(exported.blocks, vec![(25, None)]);
    assert_eq!(exported.attestations, vec![(8, 9, None)]);
    assert_conservative_and_repeatable(&protection, a);

    // A DKG key's export is every record.
    let mut dkg = Protection::default();
    dkg.designate(0);
    dkg.restore_validator(
        0,
        Validator {
            key: a,
            round: 0,
            activation: Some(Activation {
                chain: chain(GVR),
                height: 0,
            }),
            legacy_chain: None,
            records: 0,
        },
    );
    assert!(sign_block(&mut dkg, 0, 3, root(5)));
    assert!(sign_attestation(&mut dkg, 0, 1, 2, root(6)));
    assert_eq!(
        dkg.export(0),
        Exported {
            blocks: vec![(3, Some(root(5)))],
            attestations: vec![(1, 2, Some(root(6)))]
        }
    );
}

fn assert_conservative_and_repeatable(protection: &Protection, key: ValidatorKey) {
    assert_export_is_conservative(protection, 0, key);
    // Exporting twice gives the same document.
    assert_eq!(
        serde_json::to_string(&export(&chain(GVR), &[(key, protection.export(0))])).unwrap(),
        serde_json::to_string(&export(&chain(GVR), &[(key, protection.export(0))])).unwrap()
    );
}

// The specification as a reference.

/// A signer that follows EIP-3076's conditions as written, independently of `slashing`. After each
/// import it refuses (1) a block slashable with respect to a recorded block, (2) a block at or
/// below the import's minimum slot, (3) an attestation slashable with respect to a recorded
/// attestation, (4) an attestation with a source below the import's minimum source, (5) one with
/// a target at or below the import's minimum target; (2) and (5) except a repeat (the same
/// message, as determined by the signing root). An absent signing root matches nothing. What it
/// signs is kept in full, like the imported messages.
#[derive(Clone, Default)]
struct Reference {
    blocks: Vec<(u64, Option<Root>)>,
    attestations: Vec<(u64, u64, Option<Root>)>,
    /// The highest of the imports' minimum slots, sources and targets.
    min_slot: Option<u64>,
    min_source: Option<u64>,
    min_target: Option<u64>,
}

impl Reference {
    fn import(&mut self, history: &History) {
        self.min_slot = self.min_slot.max(history.blocks.keys().min().copied());
        self.min_source = self.min_source.max(
            history
                .attestations
                .values()
                .map(|(source, _)| *source)
                .min(),
        );
        self.min_target = self
            .min_target
            .max(history.attestations.keys().min().copied());
        self.blocks
            .extend(history.blocks.iter().map(|(&slot, &root)| (slot, root)));
        self.attestations.extend(
            history
                .attestations
                .iter()
                .map(|(&target, &(source, root))| (source, target, root)),
        );
    }

    fn sign_block(&mut self, slot: u64, root: Root) -> bool {
        if self.blocks.contains(&(slot, Some(root))) {
            return true;
        }
        if self.blocks.iter().any(|&(signed, _)| signed == slot)
            || self.min_slot.is_some_and(|min| slot <= min)
        {
            return false;
        }
        self.blocks.push((slot, Some(root)));
        true
    }

    fn sign_attestation(&mut self, source: u64, target: u64, root: Root) -> bool {
        // Condition (4) has no exception for repeats.
        if source > target || self.min_source.is_some_and(|min| source < min) {
            return false;
        }
        if self.attestations.contains(&(source, target, Some(root))) {
            return true;
        }
        let slashable = self.attestations.iter().any(|&(s, t, _)| {
            t == target || (source < s && t < target) || (s < source && target < t)
        });
        if slashable || self.min_target.is_some_and(|min| target <= min) {
            return false;
        }
        self.attestations.push((source, target, Some(root)));
        true
    }
}

/// xorshift64*, for reproducible randomized tests.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) % n
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// The signing root of one block: a message per (slot, variant).
fn block_root(slot: u64, variant: u64) -> Root {
    let mut root = [1; 32];
    root[1..9].copy_from_slice(&slot.to_be_bytes());
    root[9..17].copy_from_slice(&variant.to_be_bytes());
    root
}

/// The signing root of one attestation: a message per (source, target, variant).
fn attestation_root(source: u64, target: u64, variant: u64) -> Root {
    let mut root = [2; 32];
    root[1..9].copy_from_slice(&source.to_be_bytes());
    root[9..17].copy_from_slice(&target.to_be_bytes());
    root[17..25].copy_from_slice(&variant.to_be_bytes());
    root
}

/// A history that is not slashable in itself, over the same slots and epochs as the duties, with
/// absent signing roots.
fn random_history(rng: &mut Rng) -> serde_json::Value {
    let mut blocks = BTreeMap::new();
    for _ in 0..rng.below(4) {
        let slot = rng.below(40);
        let root = rng.chance(70).then(|| block_root(slot, rng.below(2)));
        blocks.entry(slot).or_insert(root);
    }
    let mut attestations = Vec::new();
    let mut source = rng.below(8);
    let mut target = source + rng.below(3);
    for _ in 0..rng.below(4) {
        let root = rng
            .chance(70)
            .then(|| attestation_root(source, target, rng.below(2)));
        attestations.push((source, target, root));
        source += rng.below(3);
        target = (target + 1).max(source) + rng.below(2);
    }
    let hex = |root: &Option<Root>| root.map(|root| hex0x(&root));
    serde_json::json!({
        "pubkey": KEY_A,
        "signed_blocks": blocks.iter().map(|(slot, root)| match hex(root) {
            Some(root) => serde_json::json!({"slot": slot.to_string(), "signing_root": root}),
            None => serde_json::json!({"slot": slot.to_string()}),
        }).collect::<Vec<_>>(),
        "signed_attestations": attestations.iter().map(|(source, target, root)| {
            let mut entry = serde_json::json!({
                "source_epoch": source.to_string(), "target_epoch": target.to_string()});
            if let Some(root) = hex(root) {
                entry["signing_root"] = root.into();
            }
            entry
        }).collect::<Vec<_>>(),
    })
}

/// Random imports and duties on an imported key. At every duty, this network refuses whatever the
/// specification's conditions refuse, except the exact repeat of a message the network itself
/// signed (re-signed below a later import's source minimum, which condition (4) would refuse:
/// the same message gives the same signature, so nothing new can be slashed; documented in
/// docs/slashing-protection.md). At the end, a specification signer that imports the export
/// refuses whatever this network refuses. `INTERCHANGE_SEEDS=<n>` runs more seeds.
#[test]
fn imports_and_exports_are_at_least_as_strict_as_the_specification() {
    let seeds: u64 = std::env::var("INTERCHANGE_SEEDS")
        .ok()
        .and_then(|seeds| seeds.parse().ok())
        .unwrap_or(300);
    let a = key(KEY_A);
    for seed in 0..seeds {
        let mut rng = Rng(seed * 2 + 1);
        let mut ours = protection(&[a], chain(GVR));
        let mut reference = Reference::default();
        let mut own_blocks = BTreeSet::new();
        let mut own_attestations = BTreeSet::new();
        for step in 0..12 {
            match rng.below(3) {
                0 => {
                    let json = document(serde_json::json!([random_history(&mut rng)]));
                    let history = interchange(json.clone()).unwrap().validators[&a].clone();
                    if import_into(&mut ours, json).is_ok() {
                        reference.import(&history);
                    }
                }
                1 => {
                    let slot = rng.below(44);
                    let root = block_root(slot, rng.below(2));
                    let allowed = reference.clone().sign_block(slot, root);
                    if sign_block(&mut ours, 0, slot, root) {
                        assert!(
                            allowed || own_blocks.contains(&(slot, root)),
                            "seed {seed} step {step}: block {slot} signed, the specification refuses it"
                        );
                        reference.sign_block(slot, root);
                        own_blocks.insert((slot, root));
                    }
                }
                _ => {
                    let source = rng.below(14);
                    let target = source + rng.below(4);
                    let root = attestation_root(source, target, rng.below(2));
                    let allowed = reference.clone().sign_attestation(source, target, root);
                    if sign_attestation(&mut ours, 0, source, target, root) {
                        assert!(
                            allowed || own_attestations.contains(&(source, target, root)),
                            "seed {seed} step {step}: attestation {source}->{target} signed, the \
                             specification refuses it"
                        );
                        reference.sign_attestation(source, target, root);
                        own_attestations.insert((source, target, root));
                    }
                }
            }
        }
        let json = export(&chain(GVR), &[(a, ours.export(0))]);
        let mut receiver = Reference::default();
        receiver.import(&from_json(&json).unwrap().validators[&a]);
        for slot in 0..44 {
            for variant in [0, 1, 7] {
                let root = block_root(slot, variant);
                if !sign_block(&mut ours.clone(), 0, slot, root) {
                    assert!(
                        !receiver.clone().sign_block(slot, root),
                        "seed {seed}: the export lets block {slot} be signed"
                    );
                }
            }
        }
        for source in 0..14 {
            for target in source..source + 6 {
                for variant in [0, 1, 7] {
                    let root = attestation_root(source, target, variant);
                    if !sign_attestation(&mut ours.clone(), 0, source, target, root) {
                        assert!(
                            !receiver.clone().sign_attestation(source, target, root),
                            "seed {seed}: the export lets attestation {source}->{target} be signed"
                        );
                    }
                }
            }
        }
    }
}
