//! Unit tests of `crate::types`: a child module of it (`#[path]` in `src/types.rs`),
//! so private items are in scope.

use super::*;
use commonware_codec::DecodeExt;

#[test]
fn block_roundtrip() {
    let transaction = Transaction {
        id: 1,
        command: Command::Sign(SignRequest {
            ceremony: CeremonyId::new("c").unwrap(),
            nonce: 7,
            payload_hash: [9; 32],
        }),
    };
    let block = Block::new(
        Block::genesis().digest(),
        Height::new(1),
        3,
        vec![transaction],
    );
    let decoded = Block::decode(block.encode()).unwrap();
    assert_eq!(decoded, block);
    assert_eq!(decoded.digest(), block.digest());
}

#[test]
fn digest_commits_to_contents() {
    let parent = Block::genesis().digest();
    let a = Block::new(parent, Height::new(1), 1, vec![]);
    let b = Block::new(parent, Height::new(1), 2, vec![]);
    assert_ne!(a.digest(), b.digest());
}

/// A reshare start keeps R1's encoding (tag 10) without membership; with one (R2) it is tag 13
/// and carries the generation, dealers and players. Both round trip inside a block.
#[test]
fn reshare_start_encodings() {
    use commonware_cryptography::{
        Signer as _,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_utils::{TryCollect as _, ordered::Set};
    let keys = |seeds: &[u64]| -> Set<PublicKey> {
        seeds
            .iter()
            .map(|seed| PrivateKey::from_seed(*seed).public_key())
            .try_collect()
            .unwrap()
    };
    let r1 = Command::StartResharing {
        validator: [5; 48],
        ceremony: CeremonyId::new("g1").unwrap(),
        membership: None,
    };
    let r2 = Command::StartResharing {
        validator: [5; 48],
        ceremony: CeremonyId::new("g1").unwrap(),
        membership: Some(Box::new(Membership {
            from: 3,
            dealers: keys(&[0, 1, 2]),
            players: keys(&[0, 1, 2, 4]),
        })),
    };
    assert_eq!(r1.encode()[0], 10);
    assert_eq!(r1.encode().len(), 1 + 48 + 3);
    assert_eq!(r2.encode()[0], 13);
    let transactions: Vec<Transaction> = [r1, r2]
        .into_iter()
        .enumerate()
        .map(|(id, command)| Transaction {
            id: id as u64,
            command,
        })
        .collect();
    for transaction in &transactions {
        assert_eq!(
            transaction.command.encode().len(),
            transaction.command.encode_size()
        );
    }
    let block = Block::new(Block::genesis().digest(), Height::new(1), 1, transactions);
    assert_eq!(Block::decode(block.encode()).unwrap(), block);

    // An empty dealer or player set does not decode: the API refuses one before it is submitted.
    let empty = Command::StartResharing {
        validator: [5; 48],
        ceremony: CeremonyId::new("g1").unwrap(),
        membership: Some(Box::new(Membership {
            from: 3,
            dealers: Set::default(),
            players: keys(&[0, 1, 2, 4]),
        })),
    };
    assert!(Command::decode(empty.encode()).is_err());
}

/// A reconfiguration (R3) is tag 14 and round trips inside a block.
#[test]
fn reconfigure_encoding() {
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    let command = Command::Reconfigure(Box::new(Reconfiguration {
        epoch: 1,
        remove: PrivateKey::from_seed(3).public_key(),
        add: PrivateKey::from_seed(4).public_key(),
    }));
    assert_eq!(command.encode()[0], 14);
    assert_eq!(command.encode().len(), command.encode_size());
    assert_eq!(Command::decode(command.encode()).unwrap(), command);
    let block = Block::new(
        Block::genesis().digest(),
        Height::new(1),
        1,
        vec![Transaction { id: 9, command }],
    );
    assert_eq!(Block::decode(block.encode()).unwrap(), block);
}

/// The builder registration policy command: tag 16, protected (bare it is refused in a new
/// block; with approvals it decodes inside `Admin`), and only a valid policy decodes.
#[test]
fn registration_policy_encoding() {
    let policy =
        RegistrationPolicy::new(vec![[2; 20], [1; 20]], 30_000_000, 60_000_000, 30, 3600).unwrap();
    let command = Command::SetRegistrationPolicy(Box::new(policy.clone()));
    assert!(command.is_protected());
    assert_eq!(command.registration_policy(), Some(&policy));
    assert!(!command.is_registration());
    let bytes = command.encode();
    assert_eq!(bytes[0], 16);
    assert_eq!(bytes.len(), command.encode_size());
    assert_eq!(Command::decode(bytes.clone()).unwrap(), command);
    // With approvals (an approver index and a signature: decoding checks only the shape).
    let approved = Command::Admin(Box::new(Authorized {
        nonce: 4,
        command: command.clone(),
        approvals: vec![Approval {
            approver: 0,
            signature: {
                use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
                PrivateKey::from_seed(1).sign(b"namespace", b"message")
            },
        }],
    }));
    assert_eq!(Command::decode(approved.encode()).unwrap(), approved);
    assert_eq!(approved.registration_policy(), Some(&policy));
    // A policy whose fee recipients are not sorted does not decode.
    let mut unsorted = bytes.to_vec();
    unsorted[2..22].copy_from_slice(&[2; 20]);
    unsorted[22..42].copy_from_slice(&[1; 20]);
    assert!(Command::decode(commonware_codec::Copying(unsorted.as_slice())).is_err());
}

/// Reserved ceremony ids are the protected commands' (an imported key's registration, a
/// replacement of keyholders), and theirs only: an unprotected start cannot take the id an
/// approved one names in advance (audit H-11). A command that starts no ceremony is not concerned.
#[test]
fn reserved_ceremony_ids_are_the_protected_commands_only() {
    use commonware_cryptography::{
        Signer as _,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_utils::{TryCollect as _, ordered::Set};
    let keys = |seeds: &[u64]| -> Set<PublicKey> {
        seeds
            .iter()
            .map(|seed| PrivateKey::from_seed(*seed).public_key())
            .try_collect()
            .unwrap()
    };
    let id = |name: &str| CeremonyId::new(name).unwrap();
    let dkg =
        |name: &str| Command::StartCeremony(CeremonyConfig::new(id(name), keys(&[0, 1, 2, 3])));
    let validator = |name: &str| {
        Command::StartValidatorCeremony(CeremonyConfig::new(id(name), keys(&[0, 1, 2, 3])))
    };
    let replacement = Membership {
        from: 3,
        dealers: keys(&[0, 1, 2]),
        players: keys(&[0, 1, 2, 4]),
    };
    let reshare = |name: &str, membership: Option<&Membership>| Command::StartResharing {
        validator: [5; 48],
        ceremony: id(name),
        membership: membership.cloned().map(Box::new),
    };

    for allowed in [
        dkg("key-1"),
        validator("validator-1"),
        reshare("g1", None),
        reshare("approved.g1", Some(&replacement)),
    ] {
        assert!(allowed.ceremony_id_rule().is_ok(), "{allowed:?}");
    }
    for refused in [
        dkg("approved.key-1"),
        validator("approved.validator-1"),
        reshare("approved.g1", None),
        reshare("g1", Some(&replacement)),
    ] {
        assert!(refused.ceremony_id_rule().is_err(), "{refused:?}");
    }
    let sign = Command::Sign(SignRequest {
        ceremony: id("approved.key-1"),
        nonce: 1,
        payload_hash: [0; 32],
    });
    assert!(sign.ceremony_id_rule().is_ok());
}

/// The batch activation command: tag 17, protected, round trip with and without an
/// acknowledgment; an empty batch, a repeated key, too many keys and unknown acknowledgment bits
/// do not decode; the largest batch fits a block many times over.
#[test]
fn batch_activation_encoding() {
    use crate::slashing::{Acknowledgment, ChainIdentity};
    let acknowledgment = Acknowledgment::from_bits(0b1111).unwrap();
    let batch = |validators: Vec<(ValidatorKey, Option<Acknowledgment>)>| {
        Command::ActivateValidators(Box::new(BatchActivation {
            chain: ChainIdentity {
                genesis_validators_root: [9; 32],
            },
            validators,
        }))
    };
    let command = batch(vec![([1; 48], None), ([2; 48], Some(acknowledgment))]);
    assert!(command.is_protected());
    let bytes = command.encode();
    assert_eq!(bytes[0], 17);
    assert_eq!(bytes.len(), command.encode_size());
    assert_eq!(Command::decode(bytes.clone()).unwrap(), command);

    // Encoded by hand, as a faulty leader could: refused when decoding.
    let raw = |count: u32, entries: &[(u8, Option<u8>)]| {
        let mut bytes = vec![17u8];
        bytes.extend_from_slice(&[9; 32]);
        UInt(count).write(&mut bytes);
        for (key, bits) in entries {
            bytes.extend_from_slice(&[*key; 48]);
            match bits {
                Some(bits) => bytes.extend_from_slice(&[1, *bits]),
                None => bytes.push(0),
            }
        }
        bytes
    };
    assert!(
        Command::decode(commonware_codec::Copying(
            raw(2, &[(1, None), (2, Some(0b1111))]).as_slice()
        ))
        .is_ok()
    );
    assert!(Command::decode(commonware_codec::Copying(raw(0, &[]).as_slice())).is_err());
    assert!(
        Command::decode(commonware_codec::Copying(
            raw(2, &[(1, None), (1, None)]).as_slice()
        ))
        .is_err()
    );
    assert!(
        Command::decode(commonware_codec::Copying(
            raw(1, &[(1, Some(0b10000))]).as_slice()
        ))
        .is_err()
    );
    assert!(
        Command::decode(commonware_codec::Copying(
            raw(MAX_BATCH_ACTIVATIONS as u32 + 1, &[]).as_slice()
        ))
        .is_err()
    );

    let largest = batch(
        (0..MAX_BATCH_ACTIVATIONS)
            .map(|index| {
                let mut key = [0; 48];
                key[..8].copy_from_slice(&(index as u64).to_be_bytes());
                (key, Some(acknowledgment))
            })
            .collect(),
    );
    assert!(largest.encode_size() * 8 < MAX_BLOCK_BYTES);
    assert_eq!(Command::decode(largest.encode()).unwrap(), largest);
}

/// The batch registration command: tag 18, protected, its ceremony ids reserved, round trip; an
/// empty batch, a repeated id, a repeated key and too many manifests do not decode; the largest
/// batch of a committee of 4 fits a block 4 times.
#[test]
fn batch_registration_encoding() {
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use commonware_utils::TryCollect as _;
    let committee: commonware_utils::ordered::Set<_> = (0..4u64)
        .map(|seed| PrivateKey::from_seed(seed).public_key())
        .try_collect()
        .unwrap();
    let manifest =
        |ceremony: &str, seed: u64| crate::import::manifest::for_test(ceremony, &committee, seed);
    let batch = |manifests: Vec<Manifest>| {
        Command::RegisterImportedKeys(Box::new(BatchRegistration { manifests }))
    };
    let command = batch(vec![manifest("approved.a", 1), manifest("approved.b", 2)]);
    assert!(command.is_protected());
    assert!(command.ceremony_id_rule().is_ok());
    assert!(
        batch(vec![manifest("approved.a", 1), manifest("b", 2)])
            .ceremony_id_rule()
            .is_err()
    );
    let bytes = command.encode();
    assert_eq!(bytes[0], 18);
    assert_eq!(bytes.len(), command.encode_size());
    assert_eq!(Command::decode(bytes.clone()).unwrap(), command);

    // Encoded by hand, as a faulty leader could: refused when decoding.
    let raw = |count: u32, manifests: &[Manifest]| {
        let mut bytes = vec![18u8];
        UInt(count).write(&mut bytes);
        for manifest in manifests {
            manifest.write(&mut bytes);
        }
        bytes
    };
    let decodes = |bytes: Vec<u8>| Command::decode(commonware_codec::Copying(bytes.as_slice()));
    assert!(
        decodes(raw(
            2,
            &[manifest("approved.a", 1), manifest("approved.b", 2)]
        ))
        .is_ok()
    );
    assert!(decodes(raw(0, &[])).is_err());
    assert!(
        decodes(raw(
            2,
            &[manifest("approved.a", 1), manifest("approved.a", 2)]
        ))
        .is_err()
    );
    assert!(
        decodes(raw(
            2,
            &[manifest("approved.a", 1), manifest("approved.b", 1)]
        ))
        .is_err()
    );
    assert!(decodes(raw(MAX_BATCH_REGISTRATIONS as u32 + 1, &[])).is_err());

    let one = manifest("approved.x", 1);
    let largest = batch(
        (0..MAX_BATCH_REGISTRATIONS)
            .map(|index| {
                let mut manifest = one.clone();
                manifest.ceremony =
                    CeremonyId::new(format!("approved.load-import-{index}")).unwrap();
                manifest.validator[..8].copy_from_slice(&(index as u64).to_be_bytes());
                manifest
            })
            .collect(),
    );
    assert!(largest.encode_size() * 4 < MAX_BLOCK_BYTES);
    assert_eq!(Command::decode(largest.encode()).unwrap(), largest);
}
