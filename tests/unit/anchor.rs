//! Unit tests of `crate::anchor`: records, the store's create-only writes and latest-record
//! search (in memory), and the reader's rules against a faulty record.

use super::*;
use commonware_codec::{DecodeExt as _, Encode as _, EncodeSize as _};
use commonware_cryptography::{Hasher as _, Sha256, Signer as _, ed25519::PrivateKey};
use futures::executor::block_on;

fn key(seed: u64) -> PrivateKey {
    PrivateKey::from_seed(seed)
}

fn cluster() -> commonware_cryptography::sha256::Digest {
    Sha256::hash(&[b"cluster"])
}

fn digest_of(height: u64, fork: u8) -> commonware_cryptography::sha256::Digest {
    Sha256::hash(&[&height.to_be_bytes(), &[fork]])
}

fn marks(block_slot: u64, source: u64, target: u64) -> Marks {
    Marks {
        block_slot: Some(block_slot),
        source: Some(source),
        target: Some(target),
    }
}

/// `writer`'s record `sequence` after `previous`, at `height` on chain `fork`.
fn record(
    writer: &PrivateKey,
    sequence: u64,
    previous: Option<&SignedRecord>,
    height: u64,
    fork: u8,
    marks: Marks,
) -> SignedRecord {
    SignedRecord::sign(
        writer,
        Record {
            cluster: cluster(),
            node: writer.public_key(),
            generation: 0,
            sequence,
            previous: previous.map_or_else(
                || commonware_cryptography::sha256::Digest::from([0; 32]),
                SignedRecord::hash,
            ),
            height,
            digest: digest_of(height, fork),
            marks,
            written_at: 1_700_000_000_000,
        },
    )
}

#[test]
fn records_round_trip_and_bind_their_writer() {
    let writer = key(1);
    let first = record(&writer, 0, None, 10, 0, marks(5, 1, 2));
    assert!(first.verify());
    let decoded = SignedRecord::decode(first.encode()).unwrap();
    assert_eq!(decoded, first);
    assert_eq!(first.encode().len(), first.encode_size());
    // Any change breaks the signature.
    let mut changed = first.clone();
    changed.record.marks.target = Some(3);
    assert!(!changed.verify());
    let mut other_writer = first.clone();
    other_writer.record.node = key(2).public_key();
    assert!(!other_writer.verify());
    // The chain: the next record names this one.
    let second = record(&writer, 1, Some(&first), 11, 0, marks(5, 1, 2));
    assert_eq!(second.record.previous, first.hash());
    assert_ne!(first.hash(), second.hash());
}

#[test]
fn marks_cover_and_combine() {
    let have = marks(10, 4, 5);
    assert!(have.covers(&Marks::default()));
    assert!(have.covers(&marks(10, 4, 5)));
    assert!(!have.covers(&marks(11, 4, 5)));
    assert!(!have.covers(&Marks {
        target: Some(6),
        ..Marks::default()
    }));
    assert!(!Marks::default().covers(&Marks {
        source: Some(0),
        ..Marks::default()
    }));
    assert_eq!(
        marks(10, 4, 5).max(Marks {
            block_slot: None,
            source: Some(6),
            target: Some(1),
        }),
        marks(10, 6, 5)
    );
}

#[test]
fn the_store_writes_once_and_finds_the_latest_record() {
    block_on(async {
        let store = AnchorStore::in_memory(&cluster());
        let writer = key(1);
        assert_eq!(store.latest(&writer.public_key()).await.unwrap(), None);
        let mut previous: Option<SignedRecord> = None;
        for sequence in 0..37u64 {
            let next = record(
                &writer,
                sequence,
                previous.as_ref(),
                10 + sequence,
                0,
                marks(sequence, 1, 2),
            );
            store.put(&next).await.unwrap();
            // A second write at the same place fails: another process writes as this node.
            assert!(matches!(
                store.put(&next).await,
                Err(AnchorError::Exists { .. })
            ));
            assert_eq!(
                store.latest(&writer.public_key()).await.unwrap(),
                Some(next.clone())
            );
            previous = Some(next);
        }
        assert_eq!(
            store.latest_sequence(&writer.public_key()).await.unwrap(),
            Some(36)
        );
        // Another node's chain is separate.
        assert_eq!(store.latest(&key(2).public_key()).await.unwrap(), None);
    });
}

/// The search for a node's latest record ends whatever is in that node's place, a record at
/// `u64::MAX` included: doubling saturates there, so a faulty writer that fills it must not make
/// the search ask for that one place for ever. One such node would otherwise stop every honest
/// node from reading the anchor at start, and they would all run degraded, under the restart
/// floor alone.
#[test]
fn the_search_for_the_latest_record_ends_on_a_record_at_the_last_place() {
    block_on(async {
        let store = AnchorStore::in_memory(&cluster());
        let faulty = key(9).public_key();
        // What a faulty writer can put there: anything, at any place.
        store.put_raw(&faulty, 0, b"not a record".to_vec()).await;
        for power in 0..64 {
            store.put_raw(&faulty, 1u64 << power, Vec::new()).await;
        }
        store.put_raw(&faulty, u64::MAX, Vec::new()).await;
        assert_eq!(
            store.latest_sequence(&faulty).await.unwrap(),
            Some(u64::MAX),
            "the last place is the end of the search"
        );
        // Its chain is then left out: nothing there is a record of its place.
        assert!(matches!(
            store.latest(&faulty).await,
            Err(AnchorError::Malformed { .. })
        ));
    });
}

#[test]
fn the_store_refuses_a_record_out_of_its_place_or_chain() {
    block_on(async {
        let store = AnchorStore::in_memory(&cluster());
        let (writer, other) = (key(1), key(2));
        let first = record(&writer, 0, None, 10, 0, marks(1, 1, 2));
        store.put(&first).await.unwrap();
        // A record that does not name the one before it.
        let unlinked = record(&writer, 1, None, 11, 0, marks(1, 1, 2));
        store.put(&unlinked).await.unwrap();
        assert!(matches!(
            store.latest(&writer.public_key()).await,
            Err(AnchorError::Malformed { .. })
        ));
        // Another node's record written at this node's place; garbage.
        store
            .put_raw(&other.public_key(), 0, first.encode().to_vec())
            .await;
        assert!(matches!(
            store.latest(&other.public_key()).await,
            Err(AnchorError::Malformed { .. })
        ));
        let third = key(3);
        store.put_raw(&third.public_key(), 0, vec![1, 2, 3]).await;
        assert!(matches!(
            store.latest(&third.public_key()).await,
            Err(AnchorError::Malformed { .. })
        ));
    });
}

/// Four nodes' latest records: `(height, fork, marks)`; fork 0 is the signed chain.
fn view(records: &[(u64, u8, Marks)]) -> View {
    View::new(
        0,
        records
            .iter()
            .enumerate()
            .map(|(index, (height, fork, marks))| {
                record(&key(index as u64 + 1), 0, None, *height, *fork, *marks)
            })
            .collect(),
    )
}

/// A chain that holds fork `fork` up to `applied`, and another fork above `diverges`.
fn chain(
    applied: u64,
    diverges: u64,
) -> impl Fn(u64) -> Option<commonware_cryptography::sha256::Digest> {
    move |height| (height <= applied).then(|| digest_of(height, u8::from(height > diverges)))
}

#[test]
fn anchored_marks_are_the_second_highest() {
    let honest = marks(100, 30, 31);
    let views = view(&[
        (160, 0, honest),
        (155, 0, marks(99, 30, 31)),
        (100, 0, marks(50, 20, 21)),
        // A faulty node's marks far above: they do not count.
        (999, 1, marks(9_999, 9_999, 9_999)),
    ]);
    assert_eq!(views.marks(), marks(100, 30, 31));
    assert_eq!(views.gate_height(), Some(160));
    // Without the faulty node, the second-highest honest marks.
    let honest_only = view(&[
        (160, 0, honest),
        (155, 0, marks(99, 29, 31)),
        (100, 0, marks(50, 20, 21)),
    ]);
    assert_eq!(honest_only.marks(), marks(99, 29, 31));
    // Fewer than two records: no anchored marks.
    assert_eq!(view(&[(1, 0, honest)]).marks(), Marks::default());
}

#[test]
fn the_gate_needs_two_of_the_three_highest_records_on_the_chain() {
    let m = Marks::default();
    // Honest records 160, 155, 100; a faulty one at 50.
    let records = view(&[(160, 0, m), (155, 0, m), (100, 0, m), (50, 1, m)]);
    // Caught up on the signed chain: confirmed.
    assert!(records.confirmed(chain(170, u64::MAX)));
    // Behind (a lagging node): not yet.
    assert!(!records.confirmed(chain(120, u64::MAX)));
    // Rolled back and diverged at 120, now at 200: only the record at 100 matches.
    assert!(!records.confirmed(chain(200, 120)));
    assert!(records.contradicted(chain(200, 120)));
    // A faulty record high above with a forged digest blocks nothing...
    let forged_high = view(&[(160, 0, m), (155, 0, m), (100, 0, m), (9_999, 1, m)]);
    assert!(forged_high.confirmed(chain(170, u64::MAX)));
    assert!(!forged_high.contradicted(chain(170, u64::MAX)));
    // ... and a faulty record matching a diverged chain unlocks nothing.
    let colluding = view(&[(160, 0, m), (155, 0, m), (100, 0, m), (180, 1, m)]);
    assert!(!colluding.confirmed(chain(200, 120)));
    // Fewer than three nodes with records: nothing was signed under the anchor.
    assert!(view(&[(160, 0, m), (155, 0, m)]).confirmed(chain(0, u64::MAX)));
}

#[test]
fn one_contradicting_record_is_not_enough() {
    let m = Marks::default();
    let records = view(&[(160, 0, m), (155, 0, m), (100, 0, m), (90, 1, m)]);
    // Only the faulty record (90, another fork) disagrees with the chain.
    assert_eq!(records.contradictions(chain(170, u64::MAX)).len(), 1);
    assert!(!records.contradicted(chain(170, u64::MAX)));
    // Records of another generation are not compared.
    let old = View::new(1, records.records().to_vec());
    assert!(old.records().is_empty());
}

mod keeper_tests {
    use super::*;
    use crate::{
        anchor::keeper::{self, Job, Keeper, Step},
        eth::duty::DutyKind,
    };
    use std::{
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000 + seconds)
    }

    fn keeper(reading: Option<(View, Option<SignedRecord>, bool)>) -> Keeper<u32> {
        Keeper::new(
            Arc::new(AnchorStore::in_memory(&cluster())),
            key(1),
            cluster(),
            reading,
            10,
            digest_of(10, 0),
        )
    }

    #[test]
    fn what_a_duty_needs_covered() {
        assert_eq!(
            keeper::needed(DutyKind::BlockProposal, 64, None),
            Some(Marks {
                block_slot: Some(64),
                ..Marks::default()
            })
        );
        assert_eq!(
            keeper::needed(DutyKind::Attestation, 3, Some(2)),
            Some(Marks {
                source: Some(2),
                target: Some(3),
                ..Marks::default()
            })
        );
        for kind in [
            DutyKind::RandaoReveal,
            DutyKind::AggregateAndProof,
            DutyKind::PayloadAttestation,
            DutyKind::ExecutionPayloadEnvelope,
            DutyKind::VoluntaryExit,
        ] {
            assert_eq!(keeper::needed(kind, 3, None), None, "{kind:?}");
        }
    }

    #[test]
    fn the_anchored_marks_refuse_what_may_conflict() {
        let anchored = marks(100, 30, 31);
        let refused =
            |kind, period, source| keeper::anchored_refusal(&anchored, kind, period, source);
        assert!(refused(DutyKind::BlockProposal, 100, None).is_some());
        assert!(refused(DutyKind::BlockProposal, 101, None).is_none());
        assert!(refused(DutyKind::Attestation, 31, Some(30)).is_some());
        assert!(refused(DutyKind::Attestation, 32, Some(31)).is_none());
        // A source below the anchored one: it could surround a signed attestation.
        assert!(refused(DutyKind::Attestation, 40, Some(29)).is_some());
        assert!(refused(DutyKind::Attestation, 40, Some(30)).is_none());
        assert!(refused(DutyKind::RandaoReveal, 0, None).is_none());
        assert!(
            keeper::anchored_refusal(&Marks::default(), DutyKind::BlockProposal, 0, None).is_none()
        );
    }

    #[test]
    fn partials_wait_for_one_write_that_covers_them() {
        let mut anchor = keeper(Some((View::default(), None, true)));
        let block = keeper::needed(DutyKind::BlockProposal, 64, None);
        let vote = keeper::needed(DutyKind::Attestation, 3, Some(2));
        // The first starts a write; the second waits for it (one write in flight).
        let (step, given) = anchor.step(block, 1);
        let Step::Hold(Some(job)) = step else {
            panic!("a write: {step:?}")
        };
        assert_eq!(given, None);
        assert_eq!(job.marks, block.unwrap());
        assert!(!job.refresh);
        assert_eq!(anchor.step(vote, 2), (Step::Hold(None), None));
        // Nothing needed: given at once.
        assert_eq!(anchor.step(None, 3), (Step::Give, Some(3)));
        // The first record covers the block only: the vote needs a second one.
        let first = block_on(keeper::write(
            &AnchorStore::in_memory(&cluster()),
            &key(1),
            cluster(),
            0,
            job,
            at(0),
        ))
        .unwrap();
        let (given, next) = anchor.written(first.clone());
        assert_eq!(given, vec![1]);
        let next = next.expect("a second write");
        assert_eq!(next.marks, marks(64, 2, 3));
        assert_eq!(next.head, Some(first));
        // Covered from now on: given at once.
        assert_eq!(anchor.step(block, 4), (Step::Give, Some(4)));
    }

    #[test]
    fn a_failed_write_degrades_and_catches_up_later() {
        let mut anchor = keeper(Some((View::default(), None, true)));
        let vote = keeper::needed(DutyKind::Attestation, 3, Some(2));
        let (Step::Hold(Some(_)), None) = anchor.step(vote, 1) else {
            panic!("held")
        };
        assert_eq!(anchor.failed(at(0), None), vec![1]);
        assert!(anchor.degraded());
        // Degraded: given at once, what was signed is remembered.
        let later = keeper::needed(DutyKind::Attestation, 4, Some(3));
        assert_eq!(anchor.step(later, 2), (Step::Give, Some(2)));
        // A catch-up record after the retry interval, covering what was signed meanwhile.
        assert_eq!(anchor.due(at(10), Duration::from_secs(600)), None);
        let job = anchor
            .due(at(31), Duration::from_secs(600))
            .expect("a retry");
        assert_eq!(
            job.marks,
            Marks {
                block_slot: None,
                source: Some(3),
                target: Some(4),
            }
        );
        let record = block_on(keeper::write(
            &AnchorStore::in_memory(&cluster()),
            &key(1),
            cluster(),
            0,
            job,
            at(31),
        ))
        .unwrap();
        anchor.written(record);
        assert!(!anchor.degraded());
    }

    #[test]
    fn a_heartbeat_while_blocks_are_applied() {
        let mut anchor = keeper(Some((View::default(), None, true)));
        // No record yet: one is due at once.
        let job = anchor
            .due(at(0), Duration::from_secs(600))
            .expect("a first record");
        let record = block_on(keeper::write(
            &AnchorStore::in_memory(&cluster()),
            &key(1),
            cluster(),
            0,
            job,
            at(0),
        ))
        .unwrap();
        anchor.written(record);
        // Before the interval, or without a new block: none.
        anchor.applied(11, digest_of(11, 0));
        assert_eq!(anchor.due(at(100), Duration::from_secs(600)), None);
    }

    #[test]
    fn the_gate_and_the_anchored_marks_refuse_until_confirmed() {
        let mut anchor = keeper(Some((
            view(&[
                (10, 0, marks(5, 1, 2)),
                (10, 0, marks(5, 1, 2)),
                (10, 0, marks(5, 1, 2)),
            ]),
            None,
            false,
        )));
        assert!(anchor.refusal(DutyKind::BlockProposal, 99, None).is_some());
        assert!(anchor.gate_refusal().is_some());
        anchor.confirm();
        assert!(anchor.gate_refusal().is_none());
        assert!(anchor.refusal(DutyKind::BlockProposal, 5, None).is_some());
        assert!(anchor.refusal(DutyKind::BlockProposal, 6, None).is_none());
        // Without a reading (unreachable at start): degraded, the gate open.
        let degraded = keeper(None);
        assert!(degraded.degraded());
        assert!(degraded.confirmed());
    }

    #[test]
    fn a_write_continues_the_chain_and_refreshes_an_unknown_head() {
        block_on(async {
            let store = AnchorStore::in_memory(&cluster());
            let job = |head, refresh| Job {
                marks: marks(1, 1, 2),
                height: 10,
                digest: digest_of(10, 0),
                head,
                refresh,
                attempt: None,
            };
            let first = keeper::write(&store, &key(1), cluster(), 0, job(None, false), at(0))
                .await
                .unwrap();
            assert_eq!(first.record.sequence, 0);
            // A keyholder that does not know its head (unreachable at start) reads it first.
            let second = keeper::write(&store, &key(1), cluster(), 0, job(None, true), at(1))
                .await
                .unwrap();
            assert_eq!(second.record.sequence, 1);
            assert_eq!(second.record.previous, first.hash());
            // One that believes in a stale head finds its place taken.
            assert!(matches!(
                keeper::write(
                    &store,
                    &key(1),
                    cluster(),
                    0,
                    job(Some(first), false),
                    at(2)
                )
                .await,
                Err(AnchorError::Exists { .. })
            ));
        });
    }
}

mod lost_write_tests {
    use super::*;
    use crate::anchor::keeper::{self, Job, Keeper, Step};
    use crate::eth::duty::DutyKind;
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000 + seconds)
    }

    fn job(head: Option<SignedRecord>, refresh: bool, attempt: Option<SignedRecord>) -> Job {
        Job {
            marks: marks(1, 1, 2),
            height: 10,
            digest: digest_of(10, 0),
            head,
            refresh,
            attempt,
        }
    }

    #[test]
    fn a_write_that_landed_without_an_answer_is_the_nodes_own() {
        block_on(async {
            let store = Arc::new(AnchorStore::in_memory(&cluster()));
            let mut anchor: Keeper<u32> = Keeper::new(
                store.clone(),
                key(1),
                cluster(),
                Some((View::default(), None, true)),
                10,
                digest_of(10, 0),
            );
            let vote = keeper::needed(DutyKind::Attestation, 3, Some(2));
            let (Step::Hold(Some(first)), None) = anchor.step(vote, 1) else {
                panic!("held")
            };
            // The record lands, but its answer is lost (a timeout): degraded.
            let attempted = Mutex::new(None);
            let landed =
                keeper::write_noting(&store, &key(1), cluster(), 0, first, at(0), &attempted)
                    .await
                    .unwrap();
            let attempt = attempted.lock().unwrap().take();
            assert_eq!(attempt.as_ref(), Some(&landed));
            assert_eq!(anchor.failed(at(0), attempt), vec![1]);
            assert!(anchor.degraded());

            // The catch-up reads the head back, finds its own record there, and writes after it:
            // no clone, no stop.
            let catch_up = anchor
                .due(at(31), Duration::from_secs(600))
                .expect("a retry");
            assert!(catch_up.refresh);
            assert_eq!(catch_up.attempt.as_ref(), Some(&landed));
            let next = keeper::write(&store, &key(1), cluster(), 0, catch_up, at(31))
                .await
                .unwrap();
            assert_eq!(next.record.sequence, 1);
            assert_eq!(next.record.previous, landed.hash());
            anchor.written(next);
            assert!(!anchor.degraded());
        });
    }

    #[test]
    fn an_attempt_that_lands_after_the_head_was_read_back_is_taken_as_its_own() {
        block_on(async {
            // The attempt (sequence 0), made against a store it never reached.
            let attempted = Mutex::new(None);
            let attempt = keeper::write_noting(
                &AnchorStore::in_memory(&cluster()),
                &key(1),
                cluster(),
                0,
                job(None, false, None),
                at(0),
                &attempted,
            )
            .await
            .unwrap();
            // It lands between the read-back (nothing yet) and the next write.
            let store = AnchorStore::in_memory(&cluster());
            store.put(&attempt).await.unwrap();
            let next = keeper::write(
                &store,
                &key(1),
                cluster(),
                0,
                job(None, false, Some(attempt.clone())),
                at(31),
            )
            .await
            .unwrap();
            assert_eq!(next.record.sequence, 1);
            assert_eq!(next.record.previous, attempt.hash());

            // Another record at that place is a clone's.
            let other = AnchorStore::in_memory(&cluster());
            let clone = record(&key(1), 0, None, 11, 0, marks(9, 9, 9));
            other.put(&clone).await.unwrap();
            assert!(matches!(
                keeper::write(
                    &other,
                    &key(1),
                    cluster(),
                    0,
                    job(None, false, Some(attempt)),
                    at(31)
                )
                .await,
                Err(AnchorError::Exists { .. })
            ));
        });
    }

    #[test]
    fn a_clone_is_still_found_after_a_lost_write() {
        block_on(async {
            let store = AnchorStore::in_memory(&cluster());
            let first = keeper::write(&store, &key(1), cluster(), 0, job(None, false, None), at(0))
                .await
                .unwrap();
            // This node's attempt at sequence 1 did not land; a clone wrote there instead.
            let attempt = record(&key(1), 1, Some(&first), 12, 0, marks(2, 2, 3));
            let clone = record(&key(1), 1, Some(&first), 13, 0, marks(5, 5, 6));
            store.put(&clone).await.unwrap();
            let read_back =
                |attempt: &SignedRecord| job(Some(first.clone()), true, Some(attempt.clone()));
            assert!(matches!(
                keeper::write(&store, &key(1), cluster(), 0, read_back(&attempt), at(31)).await,
                Err(AnchorError::Exists { .. })
            ));
            // Or wrote beyond it.
            let beyond = record(&key(1), 2, Some(&clone), 14, 0, marks(6, 6, 7));
            store.put(&beyond).await.unwrap();
            assert!(matches!(
                keeper::write(&store, &key(1), cluster(), 0, read_back(&clone), at(31)).await,
                Err(AnchorError::Exists { .. })
            ));
            // Nothing landed at all: the head read back is the last record, and the write goes on.
            let quiet = AnchorStore::in_memory(&cluster());
            let first = keeper::write(&quiet, &key(1), cluster(), 0, job(None, false, None), at(0))
                .await
                .unwrap();
            let lost = record(&key(1), 1, Some(&first), 12, 0, marks(2, 2, 3));
            let next = keeper::write(
                &quiet,
                &key(1),
                cluster(),
                0,
                job(Some(first.clone()), true, Some(lost)),
                at(31),
            )
            .await
            .unwrap();
            assert_eq!(next.record.sequence, 1);
            assert_eq!(next.record.previous, first.hash());
        });
    }
}

mod watch_tests {
    use super::*;
    use crate::anchor::watch::{TIP_GRACE_BLOCKS, Verdict, Watch};
    use std::collections::BTreeMap;

    #[test]
    fn a_restart_on_the_signed_chain_is_confirmed_at_once() {
        let m = Marks::default();
        let records = view(&[(160, 0, m), (155, 0, m), (100, 0, m)]);
        let observed: BTreeMap<u64, _> = [160, 155, 100]
            .into_iter()
            .map(|height| (height, digest_of(height, 0)))
            .collect();
        assert_eq!(Watch::new(records, observed).start(), Verdict::Confirmed);
    }

    #[test]
    fn a_lagging_node_is_confirmed_once_it_catches_up() {
        let m = Marks::default();
        let mut watch = Watch::new(
            view(&[(160, 0, m), (155, 0, m), (100, 0, m)]),
            BTreeMap::new(),
        );
        assert_eq!(watch.start(), Verdict::Pending);
        // The network's tip is above the gate: it catches up, never stops.
        for height in 90..=160 {
            let verdict = watch.applied(height, digest_of(height, 0), 400);
            if height < 155 {
                assert_eq!(verdict, Verdict::Pending, "{height}");
            } else {
                assert_eq!(verdict, Verdict::Confirmed, "{height}");
            }
        }
    }

    #[test]
    fn a_rolled_back_network_stops() {
        let m = Marks::default();
        let records = || view(&[(160, 0, m), (155, 0, m), (100, 0, m)]);
        // Contradicted at start: two records name other blocks at heights applied here.
        let observed: BTreeMap<u64, _> = [(155, digest_of(155, 1)), (100, digest_of(100, 1))]
            .into_iter()
            .collect();
        assert!(matches!(
            Watch::new(records(), observed).start(),
            Verdict::RolledBack(_)
        ));
        // Behind, and the network finalizes below the gate: after the grace, rolled back.
        let mut watch = Watch::new(records(), BTreeMap::new());
        let mut verdict = Verdict::Pending;
        for height in 0..TIP_GRACE_BLOCKS {
            verdict = watch.applied(20 + height, digest_of(20 + height, 1), 20 + height);
        }
        assert!(matches!(verdict, Verdict::RolledBack(_)), "{verdict:?}");
    }
}

mod acknowledgment_tests {
    use super::*;
    use crate::admin::Approvers;

    fn approver(index: u64) -> PrivateKey {
        key(1_000 + index)
    }

    /// Two of three approvers.
    fn approvers() -> Approvers {
        Approvers::new(
            2,
            (0..3).map(|index| approver(index).public_key()).collect(),
        )
        .unwrap()
    }

    fn acknowledged(generation: u64) -> Acknowledgment {
        Acknowledgment {
            cluster: cluster(),
            generation,
            height: 120,
            digest: digest_of(120, 0),
            marks: marks(900, 27, 28),
        }
    }

    fn signed(generation: u64, by: &[u64]) -> AcknowledgmentDocument {
        let mut document = AcknowledgmentDocument::draft(&acknowledged(generation));
        for index in by {
            document.sign(&approver(*index)).unwrap();
        }
        document
    }

    #[test]
    fn a_threshold_of_approvers_acknowledges_a_rollback() {
        let document = signed(1, &[0, 2]);
        assert_eq!(
            document.verify(&approvers(), &cluster()),
            Ok(acknowledged(1))
        );
        // Through JSON, as approvers exchange it.
        let parsed = AcknowledgmentDocument::from_json(&document.to_json()).unwrap();
        assert_eq!(parsed, document);
        // One approval, the same twice, or another cluster: not enough.
        assert!(signed(1, &[1]).verify(&approvers(), &cluster()).is_err());
        assert!(signed(1, &[1, 1]).verify(&approvers(), &cluster()).is_err());
        let other = Sha256::hash(&[b"another cluster"]);
        assert!(document.verify(&approvers(), &other).is_err());
        // A non-approver's signature does not count.
        let mut stranger = signed(1, &[0]);
        stranger.sign(&key(77)).unwrap();
        assert!(stranger.verify(&approvers(), &cluster()).is_err());
        // Generation 0 is the anchor's first: nothing to acknowledge.
        let mut zero = AcknowledgmentDocument::draft(&acknowledged(1));
        zero.generation = 0;
        assert!(zero.acknowledgment().is_err());
    }

    #[test]
    fn an_edited_acknowledgment_is_refused() {
        // Lower marks after signing: the message no longer matches the fields.
        let mut edited = signed(1, &[0, 1]);
        edited.marks.source = Some(1);
        assert!(edited.verify(&approvers(), &cluster()).is_err());
        // Fields and message changed together: the approvals no longer verify.
        let mut forged = signed(1, &[0, 1]);
        let lowered = Acknowledgment {
            marks: marks(900, 1, 28),
            ..acknowledged(1)
        };
        let redrafted = AcknowledgmentDocument::draft(&lowered);
        forged.marks = redrafted.marks;
        forged.description = redrafted.description;
        forged.message = redrafted.message;
        assert!(forged.verify(&approvers(), &cluster()).is_err());
    }

    #[test]
    fn copies_merge_and_conflicts_are_refused() {
        let mut first = signed(1, &[0]);
        first.merge(&signed(1, &[2])).unwrap();
        assert_eq!(first.approvals.len(), 2);
        assert!(first.verify(&approvers(), &cluster()).is_ok());
        assert!(first.merge(&signed(2, &[1])).is_err());
    }

    #[test]
    fn the_acknowledged_marks_are_floors() {
        let view = View::new(1, Vec::new()).with_floor(marks(900, 27, 28));
        assert_eq!(view.marks(), marks(900, 27, 28));
        // Records of the new generation above the floor raise it; their second-highest only.
        let records: Vec<_> = (1..=4)
            .map(|seed| {
                let mut signed =
                    record(&key(seed), 0, None, 10, 0, marks(900 + seed, 27, 28 + seed));
                signed.record.generation = 1;
                SignedRecord::sign(&key(seed), signed.record)
            })
            .collect();
        let view = View::new(1, records).with_floor(marks(900, 27, 28));
        assert_eq!(view.marks(), marks(903, 27, 31));
        // Records of the previous generation are not compared.
        let old = vec![record(&key(1), 0, None, 10, 1, marks(1, 1, 1))];
        assert!(View::new(1, old).records().is_empty());
    }

    /// Anyone who writes to the anchor can file objects under `acknowledgments/`: one too large,
    /// or not named `<generation>-<hash>`, is never downloaded, and the real one is still read.
    #[test]
    fn junk_under_acknowledgments_is_left_out() {
        let store = AnchorStore::in_memory(&cluster());
        block_on(async {
            let document = signed(1, &[0, 1]);
            store.put_acknowledgment(&document).await.unwrap();
            let large = format!("{:020}-{}", 2, "a".repeat(64));
            let json = document.to_json();
            let padded = format!(
                "{json}{}",
                " ".repeat(store::MAX_ACKNOWLEDGMENT_BYTES as usize)
            );
            store
                .put_raw_acknowledgment(&large, padded.into_bytes())
                .await;
            store
                .put_raw_acknowledgment("not-a-name", json.clone().into_bytes())
                .await;
            store
                .put_raw_acknowledgment(&format!("{:020}-{}", 3, "b".repeat(64)), b"{".to_vec())
                .await;
            assert_eq!(store.acknowledgments().await.unwrap(), vec![document]);
        });
    }

    #[test]
    fn the_store_writes_an_acknowledgment_once() {
        let store = AnchorStore::in_memory(&cluster());
        block_on(async {
            let document = signed(1, &[0, 1]);
            assert_eq!(store.put_acknowledgment(&document).await.unwrap(), None);
            // Again, with other approvals of the same acknowledgment: what is there comes back,
            // for the caller to check. Its approvals are nobody's guarantee: anyone who can
            // write to the anchor could have put it there, so a node goes by the document it
            // verified itself and not by this one.
            assert_eq!(
                store.put_acknowledgment(&signed(1, &[1, 2])).await.unwrap(),
                Some(document.clone())
            );
            // The same acknowledgment with no valid approval at all is still only what is
            // there: the write reports it rather than failing, so squatting the place cannot
            // keep a network stopped.
            assert_eq!(
                store
                    .put_acknowledgment(&AcknowledgmentDocument::draft(&acknowledged(1)))
                    .await
                    .unwrap(),
                Some(document.clone())
            );
            // Another of the same generation is filed apart (its own hash).
            let mut other = AcknowledgmentDocument::draft(&Acknowledgment {
                height: 121,
                ..acknowledged(1)
            });
            other.sign(&approver(0)).unwrap();
            assert_eq!(store.put_acknowledgment(&other).await.unwrap(), None);
            let listed = store.acknowledgments().await.unwrap();
            assert_eq!(listed.len(), 2);
            assert!(listed.contains(&document));
            // The nodes with records, whoever they are.
            let first = record(&key(5), 0, None, 10, 0, marks(1, 1, 1));
            store.put(&first).await.unwrap();
            assert_eq!(store.nodes().await.unwrap(), vec![key(5).public_key()]);
        });
    }
}
