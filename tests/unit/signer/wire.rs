//! Unit tests of `crate::signer::wire`: a child module of it (`#[path]` in `src/signer/wire.rs`),
//! so private items are in scope.

use super::*;
use commonware_codec::DecodeExt as _;

fn id(name: &str) -> CeremonyId {
    CeremonyId::new(name).unwrap()
}

#[test]
fn request_id_binds_every_field() {
    let base = Request::new(id("a"), 1, [1; 32]);
    assert!(base.is_consistent());
    assert_ne!(base.id, Request::new(id("b"), 1, [1; 32]).id);
    assert_ne!(base.id, Request::new(id("a"), 2, [1; 32]).id);
    assert_ne!(base.id, Request::new(id("a"), 1, [2; 32]).id);
    // Length-prefixed id: "a" + nonce bytes cannot collide with a longer id.
    assert_ne!(
        Request::new(id("a1"), 1, [1; 32]).id,
        Request::new(id("a"), 1, [1; 32]).id
    );

    let mut forged = base.clone();
    forged.payload_hash = [9; 32];
    assert!(!forged.is_consistent());

    // The kind of authorization is bound: a duty request never has a development request's
    // id, even with equal bytes, and the validator key is bound too.
    let duty = Request::duty(id("a"), [1; 48], [1; 32]);
    assert!(duty.is_consistent());
    assert_ne!(duty.id, base.id);
    assert_ne!(duty.id, Request::duty(id("a"), [2; 48], [1; 32]).id);
    assert_ne!(
        Request::duty(id("a"), [0; 48], [1; 32]).id,
        Request::new(id("a"), 0, [1; 32]).id
    );
    let mut relabeled = duty.clone();
    relabeled.authorization = AuthorizationRef::Development { nonce: 0 };
    assert!(!relabeled.is_consistent());
}

#[test]
fn roundtrip() {
    let request = Message::Request(Request::new(id("a"), 7, [3; 32]));
    assert_eq!(Message::decode(request.encode()).unwrap(), request);
    let duty = Message::Request(Request::duty(id("a"), [5; 48], [3; 32]));
    assert_eq!(Message::decode(duty.encode()).unwrap(), duty);
    let refused = Message::Refused {
        request: Request::id_of(&id("a"), 7, &[3; 32]),
        reason: Refusal::Conflict,
    };
    assert_eq!(Message::decode(refused.encode()).unwrap(), refused);
    for reason in [
        Refusal::BeyondHorizon,
        Refusal::RestartFloor,
        Refusal::AnchoredMarks,
    ] {
        let refused = Message::Refused {
            request: Request::id_of(&id("a"), 7, &[3; 32]),
            reason,
        };
        assert_eq!(Message::decode(refused.encode()).unwrap(), refused);
    }
    // Unknown refusal reason (a node that does not know it takes the message for no answer).
    let mut bad = vec![2u8];
    bad.extend_from_slice(&[0; 32]);
    bad.push(11);
    assert!(Message::decode(commonware_codec::Copying(bad.as_slice())).is_err());
}

#[test]
fn only_the_floor_and_the_anchored_marks_are_protection() {
    for reason in [Refusal::RestartFloor, Refusal::AnchoredMarks] {
        assert!(reason.is_protection() && reason.is_final(), "{reason:?}");
    }
    for reason in [
        Refusal::BeyondHorizon,
        Refusal::NotAuthorized,
        Refusal::Conflict,
        Refusal::NoShare,
        Refusal::StaleGeneration,
    ] {
        assert!(!reason.is_protection(), "{reason:?}");
    }
    assert_eq!(
        serde_json::to_value(Refusal::RestartFloor).unwrap(),
        serde_json::json!("restart_floor")
    );
    assert_eq!(
        serde_json::to_value(Refusal::AnchoredMarks).unwrap(),
        serde_json::json!("anchored_marks")
    );
}

#[test]
fn protection_alone_must_leave_too_few_keyholders() {
    use crate::signer::coordinator::protection_refuses;
    use std::collections::BTreeMap;
    let refusals = |list: &[(u32, Refusal)]| list.iter().copied().collect::<BTreeMap<_, _>>();
    // Every keyholder restarted (an R3 switch): refused for good.
    let all = refusals(&[
        (1, Refusal::RestartFloor),
        (2, Refusal::RestartFloor),
        (3, Refusal::RestartFloor),
        (4, Refusal::RestartFloor),
    ]);
    assert!(protection_refuses(4, 3, &all));
    // Two of four: no three can sign, whoever else answers.
    assert!(protection_refuses(
        4,
        3,
        &refusals(&[(1, Refusal::RestartFloor), (3, Refusal::AnchoredMarks)])
    ));
    // One floor and one silent or banned node: the absent one may come back; not protection's alone.
    assert!(!protection_refuses(
        4,
        3,
        &refusals(&[(2, Refusal::RestartFloor)])
    ));
    assert!(!protection_refuses(
        4,
        3,
        &refusals(&[(2, Refusal::RestartFloor), (3, Refusal::NoShare)])
    ));
    // Other refusals only.
    assert!(!protection_refuses(
        4,
        3,
        &refusals(&[(1, Refusal::NoShare), (2, Refusal::BeyondHorizon)])
    ));
}
