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
