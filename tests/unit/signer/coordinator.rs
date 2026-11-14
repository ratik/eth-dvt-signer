//! Unit tests of `crate::signer::coordinator`: what the coordinator does with the answer the
//! replicated state machine sends back for a duty.

use super::*;
use crate::{
    eth::{network::Network, web3signer::duty_request},
    executor::{Status, ValidatorEntry},
    readiness::Progress,
};
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::{
        group::{Private, Scalar},
        ops,
    },
    ed25519::PrivateKey,
};
use commonware_p2p::{CheckedSender, LimitedSender};
use commonware_runtime::{Runner as _, deterministic};

/// A sender the collection of partials would use (`Sender` is implemented for every
/// `LimitedSender`). These tests never reach it: the coordinator refuses before it asks any
/// keyholder.
#[derive(Clone)]
struct NoSender;

struct NoRecipients;

impl CheckedSender for NoRecipients {
    type PublicKey = PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        unreachable!("no partial is requested")
    }

    fn send(
        self,
        _message: impl Into<commonware_runtime::IoBufs> + Send,
        _priority: bool,
    ) -> commonware_actor::Unreliable<commonware_actor::Feedback> {
        unreachable!("no partial is requested")
    }
}

impl LimitedSender for NoSender {
    type PublicKey = PublicKey;
    type Checked<'a> = NoRecipients;

    fn check(
        &mut self,
        _recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, std::time::SystemTime> {
        unreachable!("no partial is requested")
    }
}

/// The attestation Lighthouse sends, as a typed duty of a validator key.
fn attestation() -> DutyRequest {
    let body = bytes::Bytes::from(include_str!("../../fixtures/web3signer/attestation.json"));
    let private = Private::new(Scalar::from_u64(31337));
    let validator = hex::encode(ops::compute_public::<Variant>(&private).encode());
    let (request, _) = duty_request(&format!("0x{validator}"), &body, Some(&Network::MAINNET))
        .expect("the fixture parses");
    request
}

/// A duty whose authorization has not been decided yet: the coordinator submits it.
fn undecided(request: &DutyRequest) -> DutyCheck {
    DutyCheck {
        validator: Some(ValidatorEntry {
            key: request.validator,
            ceremony: CeremonyId::new("validator-eth").unwrap(),
            round: 0,
            activation: None,
            imported: false,
            generation: 0,
        }),
        signing_root: request.signing_root(),
        decision: Decision::Accepted,
        height: None,
        approved: false,
        policy: None,
    }
}

/// A coordinator waits for its duty's authorization through a waiter keyed by the transaction id
/// its submitter chose, and that id travels in gossip: another transaction in the block that
/// carried this one can take its place, so the answer can be an authorization of another duty of
/// the same validator. Signing it would return a valid signature of a duty nobody asked for, and
/// the validator client would publish it and miss the duty it did ask for. The coordinator
/// computes the duty's root itself, so it compares the two and refuses.
///
/// Without that comparison the coordinator goes on to collect partials for the other root, which
/// this test's sender refuses to do: it then fails with a stalled runtime.
#[test]
fn an_authorization_of_another_duty_is_never_signed() {
    deterministic::Runner::default().start(|context| async move {
        let request = attestation();
        let (executor, mut messages) = mpsc::unbounded_channel();
        let (keyholder, _keyholder) = mpsc::unbounded_channel();
        let deps = Deps {
            me: PrivateKey::from_seed(1).public_key(),
            config: Config::default(),
            horizon: Horizon::unbounded(),
            executor,
            keyholder,
            sender: NoSender,
            pending: Pending::default(),
        };
        // Another duty of the same validator, already authorized: its root is a root this
        // validator's keyholders would give partials for.
        let other = Root::from([0x11; 32]);
        assert_ne!(other, request.signing_root());

        let now = context.current();
        let answering = async {
            while let Some(message) = messages.recv().await {
                match message {
                    executor::Message::CheckDuty {
                        request, response, ..
                    } => {
                        let _ = response.send(undecided(&request));
                    }
                    executor::Message::Status { response } => {
                        let _ = response.send(Status {
                            height: 10,
                            authorizations: 0,
                            mempool: 0,
                            admin_nonce: 0,
                            progress: Progress {
                                applied: 10,
                                known_finalized: 10,
                                last_applied: Some(now),
                            },
                            anchor_behind: false,
                        });
                    }
                    executor::Message::SubmitDuty { response, .. } => {
                        let _ = response.send(Ok(DutyReceipt {
                            decision: Decision::Accepted,
                            signing_root: other,
                            height: 11,
                            authorized_at: Some(11),
                            finalized_at: now,
                            applied_at: now,
                        }));
                        return;
                    }
                    _ => {}
                }
            }
        };
        let signing = sign_duty(&context, &deps, request.clone(), None, None);
        let (result, ()) = futures::future::join(signing, answering).await;
        match result {
            Err(SignError::WrongAuthorization { duty, authorized }) => {
                assert_eq!(duty, request.signing_root());
                assert_eq!(authorized, other);
            }
            other => panic!("the authorization of another duty was taken: {other:?}"),
        }
    });
}
