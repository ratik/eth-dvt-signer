use super::{
    Error, Message, REQUEST_SIZE, TAG_NONC, TAG_SRV, TAG_VER, TAG_ZZZZ, VERSION_DRAFT_07,
    VERSION_DRAFT_12, VERSION_RFC, VERSIONS, request, srv, verify,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;

struct Case {
    name: String,
    public_key: [u8; 32],
    request: Vec<u8>,
    nonce: [u8; 32],
    response: Vec<u8>,
    received_at: Option<i64>,
}

fn decode(value: &Value, field: &str) -> Vec<u8> {
    BASE64.decode(value[field].as_str().unwrap()).unwrap()
}

/// The nonce of a request packet.
fn nonce_of(packet: &[u8]) -> [u8; 32] {
    Message::parse(&packet[12..])
        .unwrap()
        .get(TAG_NONC)
        .unwrap()
        .try_into()
        .unwrap()
}

fn cases(text: &str, list: &str) -> Vec<Case> {
    let json: Value = serde_json::from_str(text).unwrap();
    json[list]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let request = decode(case, "request");
            Case {
                name: case["name"]
                    .as_str()
                    .map_or_else(|| format!("{list} {index}"), str::to_string),
                public_key: decode(case, "publicKey").try_into().unwrap(),
                nonce: nonce_of(&request),
                request,
                response: decode(case, "response"),
                received_at: case["receivedAt"].as_i64(),
            }
        })
        .collect()
}

fn rfc() -> Vec<Case> {
    cases(
        include_str!("../../fixtures/roughtime/rfc10049-appendix-b.json"),
        "responses",
    )
}

fn live() -> Vec<Case> {
    cases(
        include_str!("../../fixtures/roughtime/live-2026-11-13.json"),
        "captures",
    )
}

/// RFC 10049's appendix B examples say version 1 but are signed with the drafts' contexts
/// ("RoughTime v1 …"): an error of the RFC, which a strict client refuses. Real version-1 servers
/// sign with the RFC's contexts (`real_servers_answers_verify_in_every_version`).
#[test]
fn the_rfc_examples_are_signed_with_the_drafts_contexts_and_refused() {
    let cases = rfc();
    assert_eq!(cases.len(), 3);
    for case in cases {
        assert_eq!(
            verify(&case.public_key, &case.request, &case.nonce, &case.response),
            Err(Error::Delegation),
            "{}",
            case.name
        );
    }
}

#[test]
fn real_servers_answers_verify_in_every_version() {
    let mut versions = Vec::new();
    for case in live() {
        let answer = verify(&case.public_key, &case.request, &case.nonce, &case.response)
            .unwrap_or_else(|err| panic!("{}: {err}", case.name));
        versions.push((case.name.clone(), answer.version));
        // Within a minute of the capture's local time.
        let local = case.received_at.unwrap() * 1_000_000;
        assert!(
            (answer.midpoint() - local).abs() < 60_000_000,
            "{}: {} vs {local}",
            case.name,
            answer.midpoint()
        );
        assert!(answer.radius.as_secs() <= 10, "{}", case.name);
    }
    let version = |name: &str| versions.iter().find(|(n, _)| n == name).unwrap().1;
    assert_eq!(version("time.txryan.com"), VERSION_RFC);
    assert_eq!(version("TimeNL-Roughtime"), VERSION_RFC);
    assert_eq!(version("sth1.roughtime.netnod.se"), VERSION_DRAFT_07);
    assert_eq!(version("roughtime.se"), VERSION_DRAFT_12);
    assert_eq!(version("Inutile-Roughtime-FR"), VERSION_DRAFT_12);
}

/// A changed byte is refused, or (an unsigned byte nothing depends on, such as the tag of
/// draft 07's optional nonce echo) changes nothing: never another time.
#[test]
fn a_changed_byte_of_an_answer_never_gives_another_time() {
    for case in live() {
        let original =
            verify(&case.public_key, &case.request, &case.nonce, &case.response).unwrap();
        let mut refused = 0;
        for at in 0..case.response.len() {
            let mut changed = case.response.clone();
            changed[at] ^= 0x01;
            match verify(&case.public_key, &case.request, &case.nonce, &changed) {
                Err(_) => refused += 1,
                Ok(answer) => assert_eq!(answer, original, "{}: byte {at}", case.name),
            }
        }
        assert!(
            refused + 8 >= case.response.len(),
            "{}: only {refused} of {} changes refused",
            case.name,
            case.response.len()
        );
        // Truncated or extended.
        let short = &case.response[..case.response.len() - 4];
        assert!(verify(&case.public_key, &case.request, &case.nonce, short).is_err());
        let mut long = case.response.clone();
        long.extend_from_slice(&[0; 4]);
        assert!(verify(&case.public_key, &case.request, &case.nonce, &long).is_err());
    }
}

#[test]
fn an_answer_to_another_request_or_from_another_key_is_refused() {
    let cases = live();
    for case in &cases {
        // Another key.
        let other = cases
            .iter()
            .find(|other| other.public_key != case.public_key)
            .unwrap();
        assert_eq!(
            verify(
                &other.public_key,
                &case.request,
                &case.nonce,
                &case.response
            ),
            Err(Error::Delegation),
            "{}",
            case.name
        );
        // Another request (another nonce): the echo or the Merkle proof refuses it.
        let nonce = [0x42; 32];
        let fresh = request(&case.public_key, &nonce);
        assert!(
            matches!(
                verify(&case.public_key, &fresh, &nonce, &case.response),
                Err(Error::Nonce | Error::Merkle)
            ),
            "{}",
            case.name
        );
    }
}

#[test]
fn a_request_names_the_versions_the_key_and_the_nonce() {
    let key = [7u8; 32];
    let nonce = [9u8; 32];
    let packet = request(&key, &nonce);
    assert_eq!(packet.len(), REQUEST_SIZE);
    assert_eq!(&packet[..8], b"ROUGHTIM");
    assert_eq!(
        u32::from_le_bytes(packet[8..12].try_into().unwrap()) as usize,
        packet.len() - 12
    );
    let message = Message::parse(&packet[12..]).unwrap();
    let versions: Vec<u32> = message
        .get(TAG_VER)
        .unwrap()
        .chunks(4)
        .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
        .collect();
    assert_eq!(versions, VERSIONS);
    assert!(versions.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(message.get(TAG_SRV).unwrap(), srv(&key));
    assert_eq!(message.get(TAG_NONC).unwrap(), nonce);
    assert!(message.get(TAG_ZZZZ).unwrap().iter().all(|&b| b == 0));
    // The RFC examples' requests carry the SRV of their key.
    for case in rfc() {
        let message = Message::parse(&case.request[12..]).unwrap();
        if let Some(value) = message.get(TAG_SRV) {
            assert_eq!(value, srv(&case.public_key));
        }
    }
}

#[test]
fn malformed_messages_are_refused() {
    for bytes in [
        &[][..],
        &[0, 0, 0, 0][..],
        &[1, 0, 0, 0][..],
        // Two tags out of order ("NONC" sorts above "VER\0" as little-endian u32s).
        &[
            2, 0, 0, 0, 4, 0, 0, 0, b'N', b'O', b'N', b'C', b'V', b'E', b'R', 0, 0, 0, 0, 0,
        ][..],
        // An offset past the end.
        &[
            2, 0, 0, 0, 8, 0, 0, 0, b'N', b'O', b'N', b'C', b'V', b'E', b'R', 0, 0, 0, 0, 0,
        ][..],
    ] {
        assert!(Message::parse(bytes).is_err(), "{bytes:?}");
    }
}
