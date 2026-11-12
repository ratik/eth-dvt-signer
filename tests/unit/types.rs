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
