//! Builder registrations (`VALIDATOR_REGISTRATION`, builder-specs `ValidatorRegistrationV1`) and
//! the policy every one of them must meet.
//!
//! A registration tells relays where to pay for the validator's blocks that a builder builds:
//! whoever gets one signed with their own fee recipient, and a later timestamp, diverts those
//! payments. It is not slashable, and a validator client signs a new one whenever it restarts or
//! changes its fee recipient or gas limit (Lighthouse caches the signed one in memory), so the
//! approvers approve a [Policy], a protected command (`admin`), not each registration:
//!
//! | Field | Rule |
//! | --- | --- |
//! | `fee_recipients` | the registration's fee recipient is one of them (at most [MAX_FEE_RECIPIENTS]; none: no registration is signed) |
//! | `gas_limit_min`, `gas_limit_max` | its gas limit is in this inclusive range |
//! | `max_future_seconds` | its timestamp is at most this far ahead of the clock |
//! | `max_age_seconds` | and at most this far behind it |
//!
//! Without a policy no registration is signed (fail closed). The policy is replicated state: it
//! applies to every transaction after the one that set it, in block order.
//!
//! Where each rule is checked:
//!
//! | Rule | API (and retries) | Leader | Voter | Block application | Keyholder |
//! | --- | --- | --- | --- | --- | --- |
//! | fee recipient, gas limit | yes, the committed policy | yes | yes, the policy in force at the transaction | yes, deterministic | yes |
//! | timestamp window | yes, [`Horizon::ADMISSION`](super::horizon::Horizon::ADMISSION) leeway | yes | yes, [`Horizon::VOTE`](super::horizon::Horizon::VOTE) leeway | no: the state machine reads no clock | yes |
//! | at most [MAX_REGISTRATIONS_PER_BLOCK] per block, after every other transaction | — | yes | the count | — | — |
//!
//! A retry of a registration authorized earlier is checked against the policy in force now, so a
//! fee recipient removed from the policy gets no signature again from an honest node (one already
//! returned stays valid: a signature cannot be withdrawn). The window and the per-block limit are
//! not slashing rules: they bound what a faulty node or a client can add to the replicated history
//! and how much registrations can delay other duties.
//!
//! From Gloas on the same policy binds the two other duties that name a fee recipient
//! ([`Duty::terms`], `DutyKind::is_policy_bound`), in the same places and with the same in-block
//! order:
//!
//! | Duty | Rule |
//! | --- | --- |
//! | `PROPOSER_PREFERENCES` | its fee recipient is one of the policy's, its target gas limit in the range |
//! | `EXECUTION_PAYLOAD_ENVELOPE` (a self-built payload) | its payload's fee recipient is one of the policy's (the gas limit is not checked: the execution layer moves it towards the target block by block) |
//!
//! Neither has a timestamp window or a per-block limit (both have deadlines in their slot, and
//! slashing protection bounds them per slot). Without a policy neither is signed: a self-built
//! Gloas block's payload is then never revealed. Before Gloas the signer sees only a block's
//! header, never its payload's fee recipient (audit L-27).

use super::{
    duty::Duty,
    types::{Address, ValidatorRegistration, hex_bytes},
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize as _, Read, ReadExt as _, Write, varint::UInt,
};
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Most fee recipients a policy allows.
pub const MAX_FEE_RECIPIENTS: usize = 64;

/// Most registrations in one block. A leader puts them after every other transaction, so a burst
/// of registrations (a validator client restarting with many keys) never takes the place of an
/// attestation or a proposal; a voter refuses a block with more.
pub const MAX_REGISTRATIONS_PER_BLOCK: usize = 16;

/// Most registrations waiting in a node's mempool. Beyond it, a new one is refused with a
/// retryable error (`503`): validator clients sign again at the next slot.
pub const MAX_PENDING_REGISTRATIONS: usize = 1024;

/// `max_future_seconds` when the approvers give none.
pub const DEFAULT_MAX_FUTURE_SECONDS: u64 = 30;

/// `max_age_seconds` when the approvers give none.
pub const DEFAULT_MAX_AGE_SECONDS: u64 = 3600;

/// What every registration must meet (module docs). Fee recipients are sorted and distinct, so
/// one policy has one encoding and one [digest](Self::digest).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Policy {
    pub fee_recipients: Vec<Address>,
    pub gas_limit_min: u64,
    pub gas_limit_max: u64,
    pub max_future_seconds: u64,
    pub max_age_seconds: u64,
}

/// What the policy decides on for a policy-bound duty (`DutyKind::is_policy_bound`), and what a
/// keyholder knows of one beyond its signing root: the fee recipient, and the gas limit where the
/// duty names one the validator chooses (a registration's gas limit, the target gas limit of
/// Gloas proposer preferences; not an envelope's payload, whose gas limit moves towards the
/// target block by block).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Terms {
    pub fee_recipient: Address,
    pub gas_limit: Option<u64>,
}

impl From<&ValidatorRegistration> for Terms {
    fn from(registration: &ValidatorRegistration) -> Self {
        Self {
            fee_recipient: registration.fee_recipient,
            gas_limit: Some(registration.gas_limit),
        }
    }
}

impl Write for Terms {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.fee_recipient);
        self.gas_limit.is_some().write(buf);
        if let Some(gas_limit) = self.gas_limit {
            gas_limit.write(buf);
        }
    }
}

impl Read for Terms {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        if buf.remaining() < 20 {
            return Err(CodecError::EndOfBuffer);
        }
        let mut fee_recipient = [0; 20];
        buf.copy_to_slice(&mut fee_recipient);
        let gas_limit = if bool::read(buf)? {
            Some(u64::read(buf)?)
        } else {
            None
        };
        Ok(Self {
            fee_recipient,
            gas_limit,
        })
    }
}

impl EncodeSize for Terms {
    fn encode_size(&self) -> usize {
        20 + 1 + self.gas_limit.map_or(0, |_| u64::SIZE)
    }
}

/// Why a registration is not signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum Refusal {
    #[error(
        "no registration policy is set (mpc-admin draft set-registration-policy; \
         docs/administration.md): no registration, proposer preferences or payload envelope is \
         signed"
    )]
    NoPolicy,
    #[error(
        "fee recipient 0x{} is not one the registration policy allows",
        hex::encode(fee_recipient)
    )]
    FeeRecipient {
        #[serde(with = "hex_bytes")]
        fee_recipient: Address,
    },
    #[error("gas limit {gas_limit} is outside the registration policy's range [{min}, {max}]")]
    GasLimit { gas_limit: u64, min: u64, max: u64 },
    #[error(
        "timestamp {timestamp} is more than {max_future_seconds} s ahead of this node's clock \
         ({now})"
    )]
    TooNew {
        timestamp: u64,
        now: u64,
        max_future_seconds: u64,
    },
    #[error(
        "timestamp {timestamp} is more than {max_age_seconds} s old by this node's clock ({now})"
    )]
    TooOld {
        timestamp: u64,
        now: u64,
        max_age_seconds: u64,
    },
}

/// Seconds since the Unix epoch at `now` (0 before it).
fn seconds(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

impl Policy {
    /// A policy from its fields, the fee recipients sorted and deduplicated, if valid.
    pub fn new(
        mut fee_recipients: Vec<Address>,
        gas_limit_min: u64,
        gas_limit_max: u64,
        max_future_seconds: u64,
        max_age_seconds: u64,
    ) -> Result<Self, String> {
        fee_recipients.sort_unstable();
        fee_recipients.dedup();
        let policy = Self {
            fee_recipients,
            gas_limit_min,
            gas_limit_max,
            max_future_seconds,
            max_age_seconds,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Whether the fields are consistent: at most [MAX_FEE_RECIPIENTS] fee recipients, sorted
    /// and distinct, and a gas limit range that is not empty.
    pub fn validate(&self) -> Result<(), String> {
        if self.fee_recipients.len() > MAX_FEE_RECIPIENTS {
            return Err(format!(
                "{} fee recipients; at most {MAX_FEE_RECIPIENTS}",
                self.fee_recipients.len()
            ));
        }
        if self
            .fee_recipients
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err("fee recipients must be sorted and distinct".into());
        }
        if self.gas_limit_min > self.gas_limit_max {
            return Err(format!(
                "gas_limit_min {} is above gas_limit_max {}",
                self.gas_limit_min, self.gas_limit_max
            ));
        }
        Ok(())
    }

    /// The rules that do not depend on time: the fee recipient and the gas limit.
    pub fn allows(&self, terms: &Terms) -> Result<(), Refusal> {
        if self
            .fee_recipients
            .binary_search(&terms.fee_recipient)
            .is_err()
        {
            return Err(Refusal::FeeRecipient {
                fee_recipient: terms.fee_recipient,
            });
        }
        if let Some(gas_limit) = terms.gas_limit
            && !(self.gas_limit_min..=self.gas_limit_max).contains(&gas_limit)
        {
            return Err(Refusal::GasLimit {
                gas_limit,
                min: self.gas_limit_min,
                max: self.gas_limit_max,
            });
        }
        Ok(())
    }

    /// The timestamp window at `now`, widened by `leeway` on both sides (for clock error between
    /// nodes, as the time horizon is).
    pub fn window(&self, timestamp: u64, now: SystemTime, leeway: Duration) -> Result<(), Refusal> {
        let now = seconds(now);
        let leeway = leeway.as_secs();
        if timestamp
            > now
                .saturating_add(leeway)
                .saturating_add(self.max_future_seconds)
        {
            return Err(Refusal::TooNew {
                timestamp,
                now,
                max_future_seconds: self.max_future_seconds,
            });
        }
        if timestamp
            .saturating_add(self.max_age_seconds)
            .saturating_add(leeway)
            < now
        {
            return Err(Refusal::TooOld {
                timestamp,
                now,
                max_age_seconds: self.max_age_seconds,
            });
        }
        Ok(())
    }

    /// SHA-256 of the encoding: what `mpc-admin status` compares across nodes.
    pub fn digest(&self) -> Digest {
        let mut bytes = Vec::with_capacity(self.encode_size());
        self.write(&mut bytes);
        Sha256::hash(&[&bytes])
    }

    pub fn to_json(&self) -> PolicyJson {
        PolicyJson {
            fee_recipients: self
                .fee_recipients
                .iter()
                .map(|address| format!("0x{}", hex::encode(address)))
                .collect(),
            gas_limit_min: self.gas_limit_min,
            gas_limit_max: self.gas_limit_max,
            max_future_seconds: Some(self.max_future_seconds),
            max_age_seconds: Some(self.max_age_seconds),
        }
    }

    pub fn from_json(json: &PolicyJson) -> Result<Self, String> {
        let fee_recipients = json
            .fee_recipients
            .iter()
            .map(|address| {
                address
                    .strip_prefix("0x")
                    .and_then(|digits| hex::decode(digits).ok())
                    .and_then(|bytes| Address::try_from(bytes).ok())
                    .ok_or_else(|| format!("fee recipient {address}: 20 bytes of 0x-hex required"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            fee_recipients,
            json.gas_limit_min,
            json.gas_limit_max,
            json.max_future_seconds
                .unwrap_or(DEFAULT_MAX_FUTURE_SECONDS),
            json.max_age_seconds.unwrap_or(DEFAULT_MAX_AGE_SECONDS),
        )
    }
}

/// Check `registration` against `policy` (none: refused) at `now`, with `leeway`.
pub fn check(
    policy: Option<&Policy>,
    registration: &ValidatorRegistration,
    now: SystemTime,
    leeway: Duration,
) -> Result<(), Refusal> {
    let policy = policy.ok_or(Refusal::NoPolicy)?;
    policy.allows(&Terms::from(registration))?;
    policy.window(registration.timestamp, now, leeway)
}

/// Whether the policy in force allows `duty`: nothing to decide for a kind it does not bind;
/// for one it does, its terms, and a registration's timestamp window at `now`.
pub fn check_duty(
    policy: Option<&Policy>,
    duty: &Duty,
    now: SystemTime,
    leeway: Duration,
) -> Result<(), Refusal> {
    if let Some(registration) = duty.registration() {
        return check(policy, registration, now, leeway);
    }
    match duty.terms() {
        Some(terms) => policy.ok_or(Refusal::NoPolicy)?.allows(&terms),
        None => Ok(()),
    }
}

/// A policy as the API and `mpc-admin` write it (`POST /eth/registration-policy`). The windows
/// default to [DEFAULT_MAX_FUTURE_SECONDS] and [DEFAULT_MAX_AGE_SECONDS].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyJson {
    pub fee_recipients: Vec<String>,
    pub gas_limit_min: u64,
    pub gas_limit_max: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_future_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<u64>,
}

impl Write for Policy {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.fee_recipients.len() as u32).write(buf);
        for address in &self.fee_recipients {
            buf.put_slice(address);
        }
        self.gas_limit_min.write(buf);
        self.gas_limit_max.write(buf);
        self.max_future_seconds.write(buf);
        self.max_age_seconds.write(buf);
    }
}

impl Read for Policy {
    type Cfg = ();

    /// Only a valid policy decodes ([Policy::validate]): a block carrying another is refused
    /// by the codec on every node.
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let count = u32::from(UInt::<u32>::read(buf)?) as usize;
        if count > MAX_FEE_RECIPIENTS {
            return Err(CodecError::Invalid("Policy", "too many fee recipients"));
        }
        let fee_recipients = (0..count)
            .map(|_| Address::read(buf))
            .collect::<Result<Vec<_>, _>>()?;
        let policy = Self {
            fee_recipients,
            gas_limit_min: u64::read(buf)?,
            gas_limit_max: u64::read(buf)?,
            max_future_seconds: u64::read(buf)?,
            max_age_seconds: u64::read(buf)?,
        };
        policy
            .validate()
            .map_err(|_| CodecError::Invalid("Policy", "invalid registration policy"))?;
        Ok(policy)
    }
}

impl EncodeSize for Policy {
    fn encode_size(&self) -> usize {
        UInt(self.fee_recipients.len() as u32).encode_size() + 20 * self.fee_recipients.len() + 32
    }
}

#[cfg(test)]
#[path = "../../tests/unit/eth/registration.rs"]
mod tests;
