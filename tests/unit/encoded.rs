//! Unit tests of `crate::encoded`.

use super::*;
use commonware_codec::{Copying, DecodeExt as _, ReadExt as _, varint::UInt};
use commonware_cryptography::bls12381::primitives::group::{G1, Scalar};
use commonware_math::algebra::{CryptoGroup as _, Random as _};
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_storage::metadata::{Config, Metadata};
use commonware_utils::sequence::U64;

fn point() -> G1 {
    G1::generator() * &Scalar::random(rand::rng())
}

#[test]
fn writes_exactly_the_value_encoding() {
    let value = (point(), UInt(300u64));
    let encoded = Encoded::new(&value);
    assert_eq!(encoded.encode(), value.encode());
    assert_eq!(encoded.encode_size(), value.encode_size());
    assert!(encoded.decoded().is_none());
}

#[test]
fn reads_back_the_value_and_its_bytes() {
    let value = point();
    // Followed by more data: only the value's bytes are taken.
    let mut bytes = value.encode().to_vec();
    bytes.extend_from_slice(&[7, 7]);
    let mut buf = Copying(bytes.as_slice());
    let encoded = Encoded::<G1>::read(&mut buf).unwrap();
    assert_eq!(encoded.decoded(), Some(&value));
    assert_eq!(encoded.bytes(), value.encode().as_ref());
    assert_eq!(buf.0, &[7, 7]);
}

#[test]
fn reads_from_a_buffer_in_pieces() {
    let value = point();
    let bytes = value.encode();
    let (first, second) = bytes.split_at(10);
    let mut buf = bytes::Buf::chain(Copying(first), Copying(second));
    let encoded = Encoded::<G1>::read(&mut buf).unwrap();
    assert_eq!(encoded.decoded(), Some(&value));
    assert_eq!(encoded.bytes(), bytes.as_ref());
}

#[test]
fn rejects_what_the_value_rejects() {
    assert!(Encoded::<G1>::decode(Copying(&[0u8; 48])).is_err());
    assert!(Encoded::<G1>::decode(Copying(&[0u8; 3])).is_err());
}

/// A store written with plain values reads back with [Encoded] values, and the reverse: the
/// format on disk does not change.
#[test]
fn the_store_format_is_unchanged() {
    deterministic::Runner::default().start(|context| async move {
        let config = || Config {
            partition: "store".into(),
            codec_config: (),
        };
        let first = point();
        let mut plain = Metadata::<_, U64, G1>::init(context.child("plain"), config())
            .await
            .unwrap();
        plain.put(U64::new(1), first);
        drop(plain.sync().await.unwrap());

        let mut encoded = Metadata::<_, U64, Encoded<G1>>::init(context.child("encoded"), config())
            .await
            .unwrap();
        assert_eq!(encoded.get(&U64::new(1)).unwrap().decoded(), Some(&first));
        let second = point();
        encoded.put(U64::new(2), Encoded::new(&second));
        drop(encoded.sync().await.unwrap());

        let plain = Metadata::<_, U64, G1>::init(context.child("again"), config())
            .await
            .unwrap();
        assert_eq!(plain.get(&U64::new(1)), Some(&first));
        assert_eq!(plain.get(&U64::new(2)), Some(&second));
    });
}

/// Encoding a BLS point that was computed (projective, Z != 1) against one that was decoded
/// (Z = 1): the first needs a field inversion in every encode.
#[test]
#[ignore = "measurement"]
fn point_encode_cost() {
    use std::time::Instant;
    let mut rng = rand::rng();
    let fresh: Vec<G1> = (0..10_000)
        .map(|_| G1::generator() * &Scalar::random(&mut rng))
        .collect();
    let decoded: Vec<G1> = fresh
        .iter()
        .map(|point| G1::decode(point.encode()).unwrap())
        .collect();
    for (name, points) in [("computed", &fresh), ("decoded", &decoded)] {
        let started = Instant::now();
        let bytes: usize = points.iter().map(|point| point.encode().len()).sum();
        println!(
            "{name}: {:?} per point ({bytes} bytes)",
            started.elapsed() / 10_000
        );
    }
}
