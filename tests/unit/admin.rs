//! Unit tests of `crate::admin`: a child module of it (`#[path]` in `src/admin.rs`), so private
//! items are in scope. P0 part 2, tests 1 to 8 at the level of the approvals themselves (the
//! nonce, the voters and the API are tested end to end, `tests/e2e/admin.rs`).

use super::*;
use crate::types::Transaction;

fn key(seed: u64) -> PrivateKey {
    PrivateKey::from_seed(seed)
}

fn approvers() -> Approvers {
    Approvers::new(2, (100..103).map(|seed| key(seed).public_key()).collect()).unwrap()
}

fn genesis(seeds: std::ops::Range<u64>) -> Set<PublicKey> {
    seeds
        .map(|seed| key(seed).public_key())
        .try_collect()
        .unwrap()
}

fn admin() -> Administration {
    Administration::new(approvers(), &genesis(0..4))
}

fn activation(root: u8) -> Command {
    Command::ActivateValidator {
        validator: [7; 48],
        chain: ChainIdentity {
            genesis_validators_root: [root; 32],
        },
    }
}

/// `command` with `nonce`, approved by the approvers of `seeds`.
fn authorized(admin: &Administration, nonce: u64, command: Command, seeds: &[u64]) -> Authorized {
    let mut approvals: Vec<Approval> = seeds
        .iter()
        .map(|seed| admin.approve(&key(*seed), nonce, &command).unwrap())
        .collect();
    approvals.sort_by_key(|approval| approval.approver);
    Authorized {
        nonce,
        command,
        approvals,
    }
}

#[test]
fn an_approver_set_has_a_majority_threshold() {
    let keys = |count: u64| {
        (100..100 + count)
            .map(|seed| key(seed).public_key())
            .collect()
    };
    assert!(Approvers::new(1, keys(1)).is_ok());
    assert!(Approvers::new(2, keys(3)).is_ok());
    assert!(Approvers::new(3, keys(4)).is_ok());
    // Half or less, more than the keys, none, too many, a key twice.
    assert!(Approvers::new(1, keys(2)).is_err());
    assert!(Approvers::new(2, keys(4)).is_err());
    assert!(Approvers::new(4, keys(3)).is_err());
    assert!(Approvers::new(0, keys(0)).is_err());
    assert!(Approvers::new(5, keys(9)).is_err());
    let mut twice: Vec<PublicKey> = keys(2);
    twice.push(twice[0].clone());
    assert!(Approvers::new(2, twice).is_err());

    // The file round trips; its digest binds the keys and the threshold.
    let set = approvers();
    let json = serde_json::to_string(&set.to_json()).unwrap();
    assert_eq!(Approvers::from_json(&json).unwrap(), set);
    assert_ne!(Approvers::new(3, keys(3)).unwrap().digest(), set.digest());
    assert!(Approvers::from_json(r#"{"threshold": 1, "approvers": ["0x12"]}"#).is_err());
    assert!(Approvers::from_json(r#"{"threshold": 1, "approvers": [], "extra": 1}"#).is_err());
}

/// The signed message is the documented layout, and depends on every input.
#[test]
fn the_message_layout() {
    let admin = admin();
    let command = activation(1);
    let message = admin.message(5, &command);
    let encoded = command.encode();
    assert_eq!(&message[..32], admin.cluster().as_ref());
    assert_eq!(&message[32..34], &VERSION.to_be_bytes());
    assert_eq!(message[34], encoded[0]);
    assert_eq!(&message[35..43], &5u64.to_be_bytes());
    assert_eq!(
        &message[43..47],
        &((encoded.len() - 1) as u32).to_be_bytes()
    );
    assert_eq!(&message[47..], &encoded[1..]);
    assert_eq!(message, admin.message(5, &command));
    assert_ne!(message, admin.message(6, &command));
    assert_ne!(message, admin.message(5, &activation(2)));
}

/// Tests 1 to 3: a threshold of valid approvals authorizes; none, or fewer, do not.
#[test]
fn a_threshold_of_approvals_authorizes() {
    let admin = admin();
    assert_eq!(
        admin.verify(&authorized(&admin, 1, activation(1), &[100, 102])),
        Ok(())
    );
    assert_eq!(
        admin.verify(&authorized(&admin, 1, activation(1), &[100, 101, 102])),
        Ok(())
    );
    assert_eq!(
        admin.verify(&authorized(&admin, 1, activation(1), &[])),
        Err(Unauthorized::TooFew {
            signed: 0,
            required: 2
        })
    );
    assert_eq!(
        admin.verify(&authorized(&admin, 1, activation(1), &[101])),
        Err(Unauthorized::TooFew {
            signed: 1,
            required: 2
        })
    );
    // Only protected commands take approvals.
    let sign = Command::Sign(crate::types::SignRequest {
        ceremony: crate::dkg::CeremonyId::new("c").unwrap(),
        nonce: 1,
        payload_hash: [1; 32],
    });
    let mut unprotected = authorized(&admin, 1, activation(1), &[100, 101]);
    unprotected.command = sign;
    assert_eq!(admin.verify(&unprotected), Err(Unauthorized::NotProtected));
}

/// Tests 4 to 6: an approver counted twice, a key outside the set, a signature that does not
/// verify.
#[test]
fn approvals_are_distinct_known_and_valid() {
    let admin = admin();
    let mut twice = authorized(&admin, 1, activation(1), &[100]);
    twice.approvals.push(twice.approvals[0].clone());
    assert_eq!(admin.verify(&twice), Err(Unauthorized::Unsorted));

    // A stranger's signature, given an index past the set.
    let mut unknown = authorized(&admin, 1, activation(1), &[100]);
    unknown.approvals.push(Approval {
        approver: 3,
        signature: key(999).sign(NAMESPACE, &admin.message(1, &activation(1))),
    });
    assert_eq!(
        admin.verify(&unknown),
        Err(Unauthorized::UnknownApprover(3))
    );
    assert!(admin.approve(&key(999), 1, &activation(1)).is_none());

    // A stranger's signature under an approver's index.
    let mut forged = authorized(&admin, 1, activation(1), &[100, 101]);
    let index = forged.approvals[1].approver;
    forged.approvals[1].signature = key(999).sign(NAMESPACE, &admin.message(1, &activation(1)));
    assert_eq!(
        admin.verify(&forged),
        Err(Unauthorized::BadSignature(index))
    );

    // Approvals from JSON: each approver once, known.
    let json = |seed: u64| ApprovalJson {
        approver: format_key(&key(seed).public_key()),
        signature: format!(
            "0x{}",
            hex::encode(
                key(seed)
                    .sign(NAMESPACE, &admin.message(1, &activation(1)))
                    .encode()
            )
        ),
    };
    let approvals = admin.approvals(&[json(102), json(100)]).unwrap();
    assert!(approvals[0].approver < approvals[1].approver);
    assert!(admin.approvals(&[json(100), json(100)]).is_err());
    assert!(admin.approvals(&[json(999)]).is_err());
}

/// Tests 7 and 8: approvals bind the command, the nonce and the cluster.
#[test]
fn approvals_bind_the_command_the_nonce_and_the_cluster() {
    let admin = admin();
    let mut modified = authorized(&admin, 1, activation(1), &[100, 101]);
    modified.command = activation(2);
    assert!(matches!(
        admin.verify(&modified),
        Err(Unauthorized::BadSignature(_))
    ));
    let mut renumbered = authorized(&admin, 1, activation(1), &[100, 101]);
    renumbered.nonce = 2;
    assert!(matches!(
        admin.verify(&renumbered),
        Err(Unauthorized::BadSignature(_))
    ));

    // Another network (other genesis committee), or another approver set over the same one.
    let other = Administration::new(approvers(), &genesis(10..14));
    assert_ne!(other.cluster(), admin.cluster());
    let elsewhere = authorized(&other, 1, activation(1), &[100, 101]);
    assert_eq!(other.verify(&elsewhere), Ok(()));
    assert!(matches!(
        admin.verify(&elsewhere),
        Err(Unauthorized::BadSignature(_))
    ));
    let rotated = Administration::new(
        Approvers::new(3, (100..104).map(|seed| key(seed).public_key()).collect()).unwrap(),
        &genesis(0..4),
    );
    assert_ne!(rotated.cluster(), admin.cluster());
}

/// The wire form: one level of approvals over a protected command, sorted, 1 to 8.
#[test]
fn the_admin_command_encoding() {
    let admin = admin();
    let command = Command::Admin(Box::new(authorized(&admin, 7, activation(1), &[100, 101])));
    let encoded = command.encode();
    assert_eq!(encoded[0], 15);
    assert_eq!(Command::decode(encoded.clone()).unwrap(), command);
    let transaction = Transaction { id: 3, command };
    assert_eq!(
        Transaction::decode(transaction.encode()).unwrap(),
        transaction
    );

    let reject = |authorized: Authorized| {
        Command::decode(Command::Admin(Box::new(authorized)).encode()).is_err()
    };
    // No approvals; unsorted; over an unprotected command.
    assert!(reject(authorized(&admin, 7, activation(1), &[])));
    let mut unsorted = authorized(&admin, 7, activation(1), &[100, 101]);
    unsorted.approvals.reverse();
    assert!(reject(unsorted));
    let mut unprotected = authorized(&admin, 7, activation(1), &[100]);
    unprotected.command = Command::ActivateGeneration {
        validator: [7; 48],
        round: 1,
    };
    assert!(reject(unprotected));
    // Nested approvals, however deep, are refused without recursing.
    let mut nested = vec![15u8, 1];
    for _ in 0..100_000 {
        nested.extend_from_slice(&[15, 1]);
    }
    assert!(Command::decode(commonware_codec::Copying(nested.as_slice())).is_err());
    let inner = authorized(&admin, 7, activation(1), &[100]);
    let mut twice = authorized(&admin, 7, activation(1), &[100]);
    twice.command = Command::Admin(Box::new(inner));
    assert!(reject(twice));
}

/// The document approvers sign offline: drafted, signed separately, merged, checked; an edit
/// after drafting is refused.
#[test]
fn a_signed_command_document() {
    let admin = admin();
    let request = serde_json::json!({
        "public_key": format!("0x{}", hex::encode([7u8; 48])),
        "genesis_validators_root": format!("0x{}", hex::encode([1u8; 32])),
    });
    let draft = SignedCommand::draft(admin.cluster(), "activate", 4, request).unwrap();
    assert_eq!(draft.command().unwrap(), activation(1));
    assert_eq!(draft.endpoint().unwrap(), "/validators/activate");
    assert_eq!(draft.message().unwrap(), admin.message(4, &activation(1)));
    assert!(draft.description.contains("activate validator 0x0707"));

    let mut first = draft.clone();
    first.sign(&key(100)).unwrap();
    let mut second = draft.clone();
    second.sign(&key(102)).unwrap();
    first.merge(&second).unwrap();
    assert_eq!(first.approvals.len(), 2);
    assert_eq!(first.check(&approvers()).unwrap(), vec![Ok(()), Ok(())]);
    // Signing again replaces; a stranger's approval is reported, not counted.
    first.sign(&key(100)).unwrap();
    assert_eq!(first.approvals.len(), 2);
    let mut stranger = draft.clone();
    stranger.sign(&key(999)).unwrap();
    assert!(stranger.check(&approvers()).unwrap()[0].is_err());

    // What the API receives verifies.
    let body = first.body().unwrap();
    let authorization: AuthorizationJson =
        serde_json::from_value(body["authorization"].clone()).unwrap();
    let approvals = admin.approvals(&authorization.approvals).unwrap();
    let command = command("activate", &body).unwrap();
    assert_eq!(
        admin.verify(&Authorized {
            nonce: authorization.nonce,
            command,
            approvals,
        }),
        Ok(())
    );

    // Edited after drafting: the request, the nonce, or a different command merged in.
    let mut edited = draft.clone();
    edited.request["genesis_validators_root"] =
        serde_json::json!(format!("0x{}", hex::encode([2u8; 32])));
    assert!(edited.command().is_err());
    assert!(edited.sign(&key(100)).is_err());
    let mut renumbered = draft.clone();
    renumbered.nonce = 5;
    assert!(renumbered.command().is_err());
    let other =
        SignedCommand::draft(admin.cluster(), "activate", 5, draft.request.clone()).unwrap();
    assert!(first.clone().merge(&other).is_err());
}

/// Each operation's request builds the command the node builds from it.
#[test]
fn operations_build_their_commands() {
    let identity = |seed: u64| format_key(&key(seed).public_key());
    let reconfigure = command(
        "reconfigure",
        &serde_json::json!({"epoch": 1, "remove": identity(3), "add": identity(4)}),
    )
    .unwrap();
    assert!(matches!(&reconfigure, Command::Reconfigure(change)
        if change.epoch == 1 && change.add == key(4).public_key()));
    assert!(reconfigure.is_protected());
    let reshare = command(
        "reshare",
        &serde_json::json!({
            "public_key": format!("0x{}", hex::encode([7u8; 48])),
            "ceremony_id": "r2",
            "from_round": 3,
            "dealers": [identity(0), identity(1), identity(2)],
            "players": [identity(0), identity(1), identity(2), identity(4)],
        }),
    )
    .unwrap();
    assert!(reshare.is_protected());
    assert!(describe(&reshare).contains("new keyholders"));
    assert!(command("reshare", &serde_json::json!({"public_key": "0x00"})).is_err());
    assert!(command("unknown", &serde_json::json!({})).is_err());
    assert_eq!(endpoint("register-import"), Some("/keys/import"));
}

/// One validator of a test interchange: its key byte, its blocks' slots, its attestations'
/// `(source, target)`.
type TestHistory<'a> = (u8, &'a [u64], &'a [(u64, u64)]);

/// An EIP-3076 interchange of `validators` for the chain `root`.
fn interchange(root: u8, validators: &[TestHistory]) -> serde_json::Value {
    serde_json::json!({
        "metadata": {
            "interchange_format_version": "5",
            "genesis_validators_root": format!("0x{}", hex::encode([root; 32])),
        },
        "data": validators.iter().map(|(key, blocks, attestations)| serde_json::json!({
            "pubkey": format!("0x{}", hex::encode([*key; 48])),
            "signed_blocks": blocks.iter().map(|slot| serde_json::json!({
                "slot": slot.to_string(),
            })).collect::<Vec<_>>(),
            "signed_attestations": attestations.iter().map(|(source, target)| serde_json::json!({
                "source_epoch": source.to_string(),
                "target_epoch": target.to_string(),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

/// P0.1 tests 7, 8 and 12 at the approval level: an import's approvals bind every record of its
/// interchange, the keys imported, and the operation; not the JSON's formatting.
#[test]
fn an_import_approval_binds_its_exact_history() {
    let admin = admin();
    let history = interchange(1, &[(7, &[5, 9], &[(1, 2), (2, 3)]), (8, &[4], &[])]);
    let request = |history: &serde_json::Value| serde_json::json!({ "interchange": history });
    let import = command("import-history", &request(&history)).unwrap();
    assert!(import.is_protected());
    let Command::ImportSlashingProtection(summary) = &import else {
        panic!("an import");
    };
    assert_eq!(summary.validators.len(), 2);
    let approved = authorized(&admin, 4, import.clone(), &[100, 101]);
    assert_eq!(admin.verify(&approved), Ok(()));
    let reapproved = |command: Command| Authorized {
        command,
        ..approved.clone()
    };

    // Formatting is not signed: the same history written otherwise is the same command.
    let reformatted: serde_json::Value =
        serde_json::from_str(&serde_json::to_string_pretty(&history).unwrap()).unwrap();
    assert_eq!(
        command("import-history", &request(&reformatted)).unwrap(),
        import
    );

    // Any record, even one below the floors the import sets, changes the command (7).
    for other in [
        interchange(1, &[(7, &[5, 8], &[(1, 2), (2, 3)]), (8, &[4], &[])]),
        interchange(1, &[(7, &[5, 9], &[(1, 2), (2, 3)]), (8, &[3], &[])]),
        interchange(1, &[(7, &[9], &[(1, 2), (2, 3)]), (8, &[4], &[])]),
        interchange(1, &[(7, &[5, 9], &[(2, 3)]), (8, &[4], &[])]),
        interchange(2, &[(7, &[5, 9], &[(1, 2), (2, 3)]), (8, &[4], &[])]),
    ] {
        let changed = command("import-history", &request(&other)).unwrap();
        assert_ne!(changed, import);
        assert!(matches!(
            admin.verify(&reapproved(changed)),
            Err(Unauthorized::BadSignature(_))
        ));
    }
    // The keys imported (8): another key, or only some of them.
    let renamed = interchange(1, &[(6, &[5, 9], &[(1, 2), (2, 3)]), (8, &[4], &[])]);
    let only = serde_json::json!({
        "interchange": history,
        "validators": [format!("0x{}", hex::encode([7u8; 48]))],
    });
    for other in [request(&renamed), only] {
        let changed = command("import-history", &other).unwrap();
        assert!(matches!(
            admin.verify(&reapproved(changed)),
            Err(Unauthorized::BadSignature(_))
        ));
    }
    // Another operation's approvals (12).
    let activation_approvals = authorized(&admin, 4, activation(1), &[100, 101]).approvals;
    assert!(matches!(
        admin.verify(&Authorized {
            approvals: activation_approvals,
            ..approved.clone()
        }),
        Err(Unauthorized::BadSignature(_))
    ));

    // A dry run takes no approvals; a key not in the interchange is refused.
    let mut dry = request(&history);
    dry["dry_run"] = serde_json::json!(true);
    assert!(command("import-history", &dry).is_err());
    let missing = serde_json::json!({
        "interchange": history,
        "validators": [format!("0x{}", hex::encode([9u8; 48]))],
    });
    assert!(command("import-history", &missing).is_err());
    assert_eq!(
        endpoint("import-history"),
        Some("/slashing-protection/import")
    );

    // What approvers read: the digest the command carries, every key, records and ranges.
    let description = describe(&import);
    assert!(description.contains(&hex::encode(summary.digest)));
    assert!(description.contains(&hex::encode([7u8; 48])));
    let overview = history_overview(&request(&history)).unwrap().join("\n");
    assert!(overview.contains("validators affected: 2 (of 2 in the interchange)"));
    assert!(overview.contains("total: 3 block proposals (slots 4..=9), 2 attestations"));
    assert!(overview.contains("sources 1..=2, targets 2..=3"));
    assert!(overview.contains(&hex::encode(summary.digest)));
}

/// A `sign-exit` request for the validator `[key; 48]`: `epoch`, `index`, the domain's fork
/// version `version` and the chain `root`.
fn exit_request(key: u8, epoch: u64, index: u64, version: &str, root: u8) -> serde_json::Value {
    serde_json::json!({
        "public_key": format!("0x{}", hex::encode([key; 48])),
        "type": "VOLUNTARY_EXIT",
        "fork_info": {
            "fork": {"previous_version": version, "current_version": version, "epoch": epoch.to_string()},
            "genesis_validators_root": format!("0x{}", hex::encode([root; 32])),
        },
        "voluntary_exit": {"epoch": epoch.to_string(), "validator_index": index.to_string()},
    })
}

/// A `sign-deposit` request of the validator `[key; 48]`'s own key.
fn deposit_request(key: u8, credentials: u8, amount: u64, version: &str) -> serde_json::Value {
    let pubkey = format!("0x{}", hex::encode([key; 48]));
    serde_json::json!({
        "public_key": pubkey,
        "type": "DEPOSIT",
        "deposit": {
            "pubkey": pubkey,
            "withdrawal_credentials": format!("0x{}", hex::encode([credentials; 32])),
            "amount": amount.to_string(),
            "genesis_fork_version": version,
        },
    })
}

/// P0.2 tests 5 to 10 at the level of the approvals: an exit's or a deposit's approvals bind the
/// validator, the duty type, every field of the signed object and the fork context, so the exact
/// signing root; any change, or another cluster's approvals, does not verify.
#[test]
fn an_exit_or_deposit_approval_binds_its_exact_signing_root() {
    let admin = admin();
    let exit_body = exit_request(7, 300, 12, "0x03000000", 1);
    let exit = command("sign-exit", &exit_body).unwrap();
    assert!(exit.is_protected());
    let Command::Duty(exit_duty) = &exit else {
        panic!("a duty");
    };
    assert_eq!(exit_duty.duty.kind(), DutyKind::VoluntaryExit);
    assert_eq!(exit_duty.validator, [7; 48]);
    let deposit_body = deposit_request(7, 1, 32_000_000_000, "0x00000000");
    let deposit = command("sign-deposit", &deposit_body).unwrap();
    assert!(deposit.is_protected());
    let Command::Duty(deposit_duty) = &deposit else {
        panic!("a duty");
    };

    let approved = authorized(&admin, 5, exit.clone(), &[100, 101]);
    assert_eq!(admin.verify(&approved), Ok(()));
    let reapproved = |command: Command| Authorized {
        command,
        ..approved.clone()
    };
    // Every field: another validator (7; an exit's root names the index, not the key, but the
    // approvals name both), epoch or index, fork version or chain (8, 10).
    for (other, same_root) in [
        (exit_request(8, 300, 12, "0x03000000", 1), true),
        (exit_request(7, 301, 12, "0x03000000", 1), false),
        (exit_request(7, 300, 13, "0x03000000", 1), false),
        (exit_request(7, 300, 12, "0x04000000", 1), false),
        (exit_request(7, 300, 12, "0x03000000", 2), false),
    ] {
        let changed = command("sign-exit", &other).unwrap();
        let Command::Duty(changed_duty) = &changed else {
            panic!("a duty");
        };
        assert_eq!(
            changed_duty.signing_root() == exit_duty.signing_root(),
            same_root
        );
        assert!(matches!(
            admin.verify(&reapproved(changed)),
            Err(Unauthorized::BadSignature(_))
        ));
    }
    // Another duty type's approvals (9): the deposit's, with the same nonce.
    let deposit_approvals = authorized(&admin, 5, deposit.clone(), &[100, 101]).approvals;
    assert!(matches!(
        admin.verify(&Authorized {
            approvals: deposit_approvals,
            ..approved.clone()
        }),
        Err(Unauthorized::BadSignature(_))
    ));
    // Another cluster's approvals (10), by the same approvers.
    let elsewhere = Administration::new(approvers(), &genesis(10..14));
    assert!(matches!(
        admin.verify(&authorized(&elsewhere, 5, exit.clone(), &[100, 101])),
        Err(Unauthorized::BadSignature(_))
    ));
    // A deposit's withdrawal credentials, amount and genesis fork version.
    for other in [
        deposit_request(7, 2, 32_000_000_000, "0x00000000"),
        deposit_request(7, 1, 1_000_000_000, "0x00000000"),
        deposit_request(7, 1, 32_000_000_000, "0x10000910"),
    ] {
        let changed = command("sign-deposit", &other).unwrap();
        let approved = authorized(&admin, 6, deposit.clone(), &[100, 102]);
        assert!(matches!(
            admin.verify(&Authorized {
                command: changed,
                ..approved
            }),
            Err(Unauthorized::BadSignature(_))
        ));
    }

    // The operation fixes the type, and a given signing root must be the duty's.
    assert!(command("sign-exit", &deposit_body).is_err());
    assert!(command("sign-deposit", &exit_body).is_err());
    let mut wrong_root = exit_body.clone();
    wrong_root["signingRoot"] = serde_json::json!(format!("0x{}", hex::encode([0xee; 32])));
    assert!(command("sign-exit", &wrong_root).is_err());
    let mut right_root = exit_body.clone();
    right_root["signingRoot"] =
        serde_json::json!(format!("0x{}", hex::encode(exit_duty.signing_root())));
    assert_eq!(command("sign-exit", &right_root).unwrap(), exit);

    // Submitted to the Web3Signer endpoint of the key, the key out of the body.
    let draft = SignedCommand::draft(admin.cluster(), "sign-exit", 5, exit_body.clone()).unwrap();
    assert_eq!(
        draft.endpoint().unwrap(),
        format!("/api/v1/eth2/sign/0x{}", hex::encode([7u8; 48]))
    );
    let body = draft.body().unwrap();
    assert!(body.get("public_key").is_none());
    assert_eq!(body["type"], "VOLUNTARY_EXIT");
    assert_eq!(body["authorization"]["nonce"], 5);

    // What approvers read.
    let overview = duty_overview(exit_duty).join("\n");
    assert!(
        overview.contains("VALIDATOR INDEX:        12"),
        "{overview}"
    );
    assert!(
        overview.contains("EXIT EPOCH:             300"),
        "{overview}"
    );
    assert!(overview.contains(&format_root(&exit_duty.signing_root())));
    let overview = duty_overview(deposit_duty).join("\n");
    assert!(
        overview.contains(&format!(
            "WITHDRAWAL CREDENTIALS: 0x{}",
            hex::encode([1u8; 32])
        )),
        "{overview}"
    );
    assert!(overview.contains("AMOUNT:                 32000000000 gwei (32 ETH)"));
    assert!(describe(&exit).contains("VOLUNTARY EXIT"));
    assert!(describe(&deposit).contains(&hex::encode([1u8; 32])));

    // The messages published: an exit as the beacon API takes it, a deposit with its roots.
    let signature = format!("0x{}", hex::encode([0xab; 96]));
    let message = signed_message(exit_duty, &signature).unwrap();
    assert_eq!(
        message,
        serde_json::json!({
            "message": {"epoch": "300", "validator_index": "12"},
            "signature": signature,
        })
    );
    let message = signed_message(deposit_duty, &signature).unwrap();
    assert_eq!(message["amount"], 32_000_000_000u64);
    assert_eq!(message["fork_version"], "0x00000000");
    assert_eq!(
        message["signing_root"],
        format_root(&deposit_duty.signing_root())
    );
    assert!(signed_message(exit_duty, "0x12").is_err());
}

/// An approval wraps only a protected command: an exit or a deposit, never another duty.
#[test]
fn approvals_wrap_exits_and_deposits_only() {
    let admin = admin();
    let exit = command("sign-exit", &exit_request(7, 300, 12, "0x03000000", 1)).unwrap();
    let encoded = Command::Admin(Box::new(authorized(&admin, 1, exit, &[100, 101]))).encode();
    assert!(matches!(
        Command::decode(commonware_codec::Copying(encoded.as_ref())),
        Ok(Command::Admin(_))
    ));
    let Command::Duty(mut request) =
        command("sign-exit", &exit_request(7, 300, 12, "0x03000000", 1)).unwrap()
    else {
        panic!("a duty");
    };
    request.duty = Duty::RandaoReveal { epoch: 300 };
    let attestation = Command::Duty(request);
    assert!(!attestation.is_protected());
    let encoded =
        Command::Admin(Box::new(authorized(&admin, 1, attestation, &[100, 101]))).encode();
    assert!(Command::decode(commonware_codec::Copying(encoded.as_ref())).is_err());
}

/// The builder registration policy is a protected command: approvals bind every field of it
/// (fee recipients, the gas limit range, both windows), its nonce and cluster; a request with
/// an unknown field, an invalid address or an empty range is refused before anyone signs; the
/// description names everything approvers decide.
#[test]
fn a_registration_policy_approval_binds_every_field() {
    let admin = admin();
    let body = |fee_recipients: &[&str], min: u64, max: u64, ahead: u64, behind: u64| {
        serde_json::json!({
            "fee_recipients": fee_recipients,
            "gas_limit_min": min,
            "gas_limit_max": max,
            "max_future_seconds": ahead,
            "max_age_seconds": behind,
        })
    };
    let a = "0x1111111111111111111111111111111111111111";
    let b = "0x2222222222222222222222222222222222222222";
    let policy = command(
        "set-registration-policy",
        &body(&[b, a], 30_000_000, 60_000_000, 30, 3600),
    )
    .unwrap();
    assert!(policy.is_protected());
    assert_eq!(
        endpoint("set-registration-policy"),
        Some("/eth/registration-policy")
    );
    let approved = authorized(&admin, 3, policy.clone(), &[100, 101]);
    assert_eq!(admin.verify(&approved), Ok(()));
    // The order fee recipients are given in is not a change.
    let reordered = command(
        "set-registration-policy",
        &body(&[a, b], 30_000_000, 60_000_000, 30, 3600),
    )
    .unwrap();
    assert_eq!(reordered, policy);
    for other in [
        body(&[a], 30_000_000, 60_000_000, 30, 3600),
        body(&[a, b], 30_000_001, 60_000_000, 30, 3600),
        body(&[a, b], 30_000_000, 60_000_001, 30, 3600),
        body(&[a, b], 30_000_000, 60_000_000, 31, 3600),
        body(&[a, b], 30_000_000, 60_000_000, 30, 3601),
    ] {
        let changed = command("set-registration-policy", &other).unwrap();
        assert!(matches!(
            admin.verify(&Authorized {
                command: changed,
                ..approved.clone()
            }),
            Err(Unauthorized::BadSignature(_))
        ));
    }
    // Defaults for the windows.
    let defaults = command(
        "set-registration-policy",
        &serde_json::json!({"fee_recipients": [a], "gas_limit_min": 1, "gas_limit_max": 2}),
    )
    .unwrap();
    let Command::SetRegistrationPolicy(defaults) = defaults else {
        panic!("a policy");
    };
    assert_eq!(
        (defaults.max_future_seconds, defaults.max_age_seconds),
        (30, 3600)
    );
    // Refused before anyone signs.
    for bad in [
        serde_json::json!({"fee_recipients": [a], "gas_limit_min": 1, "gas_limit_max": 2, "extra": 1}),
        serde_json::json!({"fee_recipients": ["0x1234"], "gas_limit_min": 1, "gas_limit_max": 2}),
        serde_json::json!({"fee_recipients": [a], "gas_limit_min": 3, "gas_limit_max": 2}),
        serde_json::json!({"fee_recipients": [a], "gas_limit_min": 1}),
    ] {
        assert!(command("set-registration-policy", &bad).is_err(), "{bad}");
    }
    let text = describe(&policy);
    for part in [a, b, "30000000", "60000000", "30 s ahead", "3600 s behind"] {
        assert!(text.contains(part), "{text}");
    }
    assert!(
        describe(&command("set-registration-policy", &body(&[], 1, 2, 30, 3600)).unwrap())
            .contains("none (no registration is signed)")
    );
}

/// `activate-batch`: drafted from its request, described for approvers (DKG keys, imported keys
/// by acknowledgment), submitted to its endpoint; the node builds the same command from the body
/// it receives, approvals included; an empty batch or a key named twice is refused before
/// anyone signs.
#[test]
fn a_batch_activation_document() {
    use crate::slashing::{Acknowledgment, ChainIdentity};
    let admin = admin();
    let complete = serde_json::json!({
        "previous_signer_stopped": true,
        "no_other_active_signer": true,
        "history_exported_after_stop": true,
        "automatic_restart_disabled": true,
    });
    let public = |byte: u8| format!("0x{}", hex::encode([byte; 48]));
    let request = serde_json::json!({
        "genesis_validators_root": format!("0x{}", hex::encode([1u8; 32])),
        "validators": [
            {"public_key": public(7)},
            {"public_key": public(8), "acknowledgment": complete},
        ],
    });
    let expected = Command::ActivateValidators(Box::new(BatchActivation {
        chain: ChainIdentity {
            genesis_validators_root: [1; 32],
        },
        validators: vec![
            ([7; 48], None),
            ([8; 48], Some(Acknowledgment::from_bits(0b1111).unwrap())),
        ],
    }));
    let mut draft = SignedCommand::draft(admin.cluster(), "activate-batch", 4, request).unwrap();
    assert_eq!(draft.command().unwrap(), expected);
    assert_eq!(draft.endpoint().unwrap(), "/validators/activate/batch");
    assert!(
        draft
            .description
            .starts_with("activate 2 validators, all or none")
    );
    assert!(draft.description.contains("1 DKG keys: 0x0707"));
    assert!(draft.description.contains("1 imported keys"));

    draft.sign(&key(100)).unwrap();
    draft.sign(&key(102)).unwrap();
    let body = draft.body().unwrap();
    assert_eq!(command("activate-batch", &body).unwrap(), expected);

    let refused = |validators: serde_json::Value| {
        SignedCommand::draft(
            admin.cluster(),
            "activate-batch",
            4,
            serde_json::json!({
                "genesis_validators_root": format!("0x{}", hex::encode([1u8; 32])),
                "validators": validators,
            }),
        )
        .is_err()
    };
    assert!(refused(serde_json::json!([])));
    assert!(refused(
        serde_json::json!([{"public_key": public(7)}, {"public_key": public(7)}])
    ));
    assert!(refused(
        serde_json::json!([{"public_key": public(7), "extra": 1}])
    ));
}

/// A batch registration as approvers review it: the endpoint, one line per key with its ceremony
/// and manifest digest, and the command a node builds from the request it receives, approvals
/// included; an empty list, a repeated manifest or an unknown field is refused before anyone
/// signs.
#[test]
fn a_batch_registration_document() {
    use crate::{import::manifest::for_test, types::BatchRegistration};
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use commonware_utils::{TryCollect as _, ordered::Set};
    let admin = admin();
    let committee: Set<_> = (0..4u64)
        .map(|seed| PrivateKey::from_seed(seed).public_key())
        .try_collect()
        .unwrap();
    let first = for_test("approved.first", &committee, 1);
    let second = for_test("approved.second", &committee, 2);
    let json = |manifest: &crate::import::manifest::Manifest| {
        serde_json::to_value(manifest.to_json().unwrap()).unwrap()
    };
    let request = serde_json::json!({"manifests": [json(&first), json(&second)]});
    let expected = Command::RegisterImportedKeys(Box::new(BatchRegistration {
        manifests: vec![first.clone(), second.clone()],
    }));
    let mut draft =
        SignedCommand::draft(admin.cluster(), "register-import-batch", 4, request).unwrap();
    assert_eq!(draft.command().unwrap(), expected);
    assert_eq!(draft.endpoint().unwrap(), "/keys/import/batch");
    assert!(
        draft
            .description
            .starts_with("register 2 imported keys, all or none")
    );
    assert!(draft.description.contains("as ceremony approved.second"));
    assert!(draft.description.contains(&hex::encode(second.digest())));

    draft.sign(&key(100)).unwrap();
    draft.sign(&key(102)).unwrap();
    let body = draft.body().unwrap();
    assert_eq!(command("register-import-batch", &body).unwrap(), expected);

    let refused = |request: serde_json::Value| {
        SignedCommand::draft(admin.cluster(), "register-import-batch", 4, request).is_err()
    };
    assert!(refused(serde_json::json!({"manifests": []})));
    assert!(refused(
        serde_json::json!({"manifests": [json(&first), json(&first)]})
    ));
    assert!(refused(
        serde_json::json!({"manifests": [json(&first)], "extra": 1})
    ));
}
