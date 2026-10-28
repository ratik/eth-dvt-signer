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
    // Unknown refusal reason.
    let mut bad = vec![2u8];
    bad.extend_from_slice(&[0; 32]);
    bad.push(9);
    assert!(Message::decode(bad.as_slice()).is_err());
}
