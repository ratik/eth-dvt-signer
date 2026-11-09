//! The Ethereum network a node signs for (P0.3): its clock, its identity and its fork schedule,
//! pinned per node (`--eth-network`, or the `--eth-genesis-*` values and `--eth-fork-schedule` of
//! another network).
//!
//! A validator client's `fork_info` decides the domain of what is signed, so a signer that takes
//! it on trust signs under whatever domain the client names. Every duty is therefore checked
//! against the pinned schedule ([`Network::check`]) where a node decides what enters consensus,
//! as the time horizon is (`eth::horizon`): the API, a leader building a block, a voter. A duty
//! whose `fork_info` is not this network's is refused, never corrected: the request is wrong.
//!
//! | Duty | `fork_info` accepted |
//! | --- | --- |
//! | Deposit | the genesis fork version as both versions, epoch 0, a zero genesis validators root (`compute_domain(DOMAIN_DEPOSIT)`) |
//! | Builder registration | the same (`compute_domain(DOMAIN_APPLICATION_BUILDER)`): the request carries none, the API puts this one in |
//! | Voluntary exit of an epoch at or after Deneb | Capella's version as both versions, the exit's epoch (EIP-7044, as Lighthouse sends it) |
//! | Any other | the network's genesis validators root, and a fork of the schedule: its version, the version before it and its epoch (as `fork_at_epoch` computes it), or its version twice with an epoch at which it is in effect (the beacon state's form on a network that started at a later fork, and after a blob-parameter-only fork); and the version it gives at the duty's domain epoch (`Duty::epoch`) is the schedule's |
//!
//! A version the schedule does not have (a fork this build does not know, another network's) is
//! refused: a fork is signed for only once a release adds it to the schedule.

use super::{
    duty::{Duty, DutyRequest, Fork, ForkInfo, SLOTS_PER_EPOCH},
    types::{Root, Version},
};
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// The forks this signer knows, in the order they activate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForkName {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
    Fulu,
}

impl ForkName {
    pub const ALL: [Self; 7] = [
        Self::Phase0,
        Self::Altair,
        Self::Bellatrix,
        Self::Capella,
        Self::Deneb,
        Self::Electra,
        Self::Fulu,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Phase0 => "phase0",
            Self::Altair => "altair",
            Self::Bellatrix => "bellatrix",
            Self::Capella => "capella",
            Self::Deneb => "deneb",
            Self::Electra => "electra",
            Self::Fulu => "fulu",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|fork| fork.name() == name)
    }
}

/// A fork of the schedule: its version, from its epoch on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledFork {
    pub name: ForkName,
    #[serde(with = "super::types::hex_bytes")]
    pub version: Version,
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: u64,
}

const fn fork(name: ForkName, version: u32, epoch: u64) -> ScheduledFork {
    ScheduledFork {
        name,
        version: version.to_be_bytes(),
        epoch,
    }
}

/// Mainnet's schedule (`consensus-specs`, `configs/mainnet.yaml`). Gloas is not scheduled.
const MAINNET_FORKS: [ScheduledFork; 7] = [
    fork(ForkName::Phase0, 0x0000_0000, 0),
    fork(ForkName::Altair, 0x0100_0000, 74_240),
    fork(ForkName::Bellatrix, 0x0200_0000, 144_896),
    fork(ForkName::Capella, 0x0300_0000, 194_048),
    fork(ForkName::Deneb, 0x0400_0000, 269_568),
    fork(ForkName::Electra, 0x0500_0000, 364_032),
    fork(ForkName::Fulu, 0x0600_0000, 411_392),
];

/// Hoodi's schedule (`eth-clients/hoodi`, `metadata/config.yaml`).
const HOODI_FORKS: [ScheduledFork; 7] = [
    fork(ForkName::Phase0, 0x1000_0910, 0),
    fork(ForkName::Altair, 0x2000_0910, 0),
    fork(ForkName::Bellatrix, 0x3000_0910, 0),
    fork(ForkName::Capella, 0x4000_0910, 0),
    fork(ForkName::Deneb, 0x5000_0910, 0),
    fork(ForkName::Electra, 0x6000_0910, 2_048),
    fork(ForkName::Fulu, 0x7000_0910, 50_688),
];

/// An Ethereum network: its clock (when slot 0 started, slot length, slots per epoch), its
/// identity (genesis validators root) and its fork schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    /// Unix seconds at the start of slot 0.
    pub genesis_time: u64,
    pub seconds_per_slot: u64,
    /// Always [`SLOTS_PER_EPOCH`]: duties are decoded with the mainnet preset.
    pub slots_per_epoch: u64,
    pub genesis_validators_root: Root,
    /// The genesis fork (Phase 0, epoch 0), then each later fork in order; a schedule may end
    /// before the last fork this signer knows.
    pub forks: &'static [ScheduledFork],
}

/// Why a duty's `fork_info` is not this network's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum WrongFork {
    #[error("this node has no Ethereum network configured (--eth-network): it signs no duty")]
    NotConfigured,
    #[error("the duty is for another chain than this node's (genesis validators root)")]
    OtherChain,
    #[error("fork version {version} is not in this network's fork schedule")]
    UnknownVersion { version: String },
    #[error(
        "fork_info names version {version} with previous version {previous} at epoch {epoch}; \
         this network's fork of that version is {expected}"
    )]
    NotAFork {
        version: String,
        previous: String,
        epoch: u64,
        expected: String,
    },
    #[error(
        "the duty's domain at epoch {epoch} would use fork version {used}; this network's is \
         {expected}"
    )]
    WrongVersion {
        epoch: u64,
        used: String,
        expected: String,
    },
    #[error(
        "a voluntary exit of epoch {epoch} is signed with Capella's version (EIP-7044): \
         fork_info must be {expected}"
    )]
    Exit { epoch: u64, expected: String },
    #[error(
        "a deposit is signed with the genesis fork version {expected} and no genesis validators \
         root"
    )]
    Deposit { expected: String },
    #[error(
        "a builder registration is signed with the genesis fork version {expected} and no \
         genesis validators root"
    )]
    Registration { expected: String },
}

fn hex_version(version: &Version) -> String {
    format!("0x{}", hex::encode(version))
}

fn describe_fork(fork: &Fork) -> String {
    format!(
        "{{previous {}, current {}, epoch {}}}",
        hex_version(&fork.previous_version),
        hex_version(&fork.current_version),
        fork.epoch
    )
}

impl Network {
    /// Ethereum mainnet (genesis state of the consensus specifications' launch).
    pub const MAINNET: Self = Self {
        genesis_time: 1_606_824_023,
        seconds_per_slot: 12,
        slots_per_epoch: SLOTS_PER_EPOCH,
        genesis_validators_root: hex32(
            "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
        ),
        forks: &MAINNET_FORKS,
    };

    /// The Hoodi testnet.
    pub const HOODI: Self = Self {
        genesis_time: 1_742_213_400,
        seconds_per_slot: 12,
        slots_per_epoch: SLOTS_PER_EPOCH,
        genesis_validators_root: hex32(
            "212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f",
        ),
        forks: &HOODI_FORKS,
    };

    /// A network by name (`mainnet`, `hoodi`).
    pub fn named(name: &str) -> Option<Self> {
        match name {
            "mainnet" => Some(Self::MAINNET),
            "hoodi" => Some(Self::HOODI),
            _ => None,
        }
    }

    /// A fork schedule given as `name=0x<version>@<epoch>,...` (`--eth-fork-schedule`), checked
    /// as [`Network::validate`] checks it.
    pub fn parse_schedule(text: &str) -> Result<Vec<ScheduledFork>, String> {
        text.split(',')
            .map(|entry| {
                let entry = entry.trim();
                let (name, rest) = entry
                    .split_once('=')
                    .ok_or_else(|| format!("{entry}: name=0x<version>@<epoch>"))?;
                let (version, epoch) = rest
                    .split_once('@')
                    .ok_or_else(|| format!("{entry}: name=0x<version>@<epoch>"))?;
                let name = ForkName::parse(name)
                    .ok_or_else(|| format!("{name}: unknown fork (phase0 to fulu)"))?;
                let version = hex::decode(version.strip_prefix("0x").unwrap_or(version))
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| format!("{version}: a fork version is 4 bytes of hex"))?;
                let epoch = epoch
                    .parse()
                    .map_err(|_| format!("{epoch}: an epoch is a number"))?;
                Ok(ScheduledFork {
                    name,
                    version,
                    epoch,
                })
            })
            .collect()
    }

    /// Whether this is a network this signer can sign for: mainnet-preset epochs, slots of some
    /// length, and a complete schedule: Phase 0 at epoch 0, then the next forks in order, each
    /// once, with distinct versions and epochs that never decrease.
    pub fn validate(&self) -> Result<(), String> {
        if self.slots_per_epoch != SLOTS_PER_EPOCH {
            return Err(format!(
                "{} slots per epoch: only the mainnet preset ({SLOTS_PER_EPOCH}) is supported",
                self.slots_per_epoch
            ));
        }
        if self.seconds_per_slot == 0 {
            return Err("seconds per slot must be above 0".into());
        }
        let Some(genesis) = self.forks.first() else {
            return Err("the fork schedule is empty".into());
        };
        if genesis.name != ForkName::Phase0 || genesis.epoch != 0 {
            return Err("the fork schedule starts with phase0 at epoch 0".into());
        }
        for (index, fork) in self.forks.iter().enumerate() {
            if fork.name != ForkName::ALL[index] {
                return Err(format!(
                    "fork {} is out of order: the schedule lists {} in order, none skipped",
                    fork.name.name(),
                    ForkName::ALL
                        .iter()
                        .map(|fork| fork.name())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if index > 0 && fork.epoch < self.forks[index - 1].epoch {
                return Err(format!(
                    "fork {} activates before the fork before it",
                    fork.name.name()
                ));
            }
            if self.forks[..index]
                .iter()
                .any(|earlier| earlier.version == fork.version)
            {
                return Err(format!(
                    "fork {} repeats version {}",
                    fork.name.name(),
                    hex_version(&fork.version)
                ));
            }
        }
        Ok(())
    }

    /// The latest slot that has started at `time`, if slot 0 has.
    pub fn slot_at(&self, time: SystemTime) -> Option<u64> {
        let since_genesis = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()?
            .as_secs()
            .checked_sub(self.genesis_time)?;
        Some(since_genesis / self.seconds_per_slot.max(1))
    }

    /// The fork in effect at `epoch`: the last one whose epoch is at or before it.
    fn index_at(&self, epoch: u64) -> usize {
        self.forks
            .iter()
            .rposition(|fork| fork.epoch <= epoch)
            .unwrap_or_default()
    }

    /// The fork version in effect at `epoch`.
    pub fn version_at(&self, epoch: u64) -> Version {
        self.forks[self.index_at(epoch)].version
    }

    /// The schedule's fork `index` as a `Fork` (the version before it, Phase 0's own for Phase
    /// 0), as a validator client names it.
    fn fork_of(&self, index: usize) -> Fork {
        Fork {
            previous_version: self.forks[index.saturating_sub(1)].version,
            current_version: self.forks[index].version,
            epoch: self.forks[index].epoch,
        }
    }

    /// The fork in effect at `epoch`, as a validator client names it.
    pub fn fork_at(&self, epoch: u64) -> Fork {
        self.fork_of(self.index_at(epoch))
    }

    /// The genesis fork version (Phase 0's).
    pub fn genesis_fork_version(&self) -> Version {
        self.forks[0].version
    }

    /// Capella's version, if a voluntary exit of `epoch` is signed with it (EIP-7044: the
    /// network has Deneb and the exit's epoch is at or after it).
    fn exit_version(&self, epoch: u64) -> Option<Version> {
        let deneb = self
            .forks
            .iter()
            .find(|fork| fork.name == ForkName::Deneb)?;
        let capella = self
            .forks
            .iter()
            .find(|fork| fork.name == ForkName::Capella)?;
        (epoch >= deneb.epoch).then_some(capella.version)
    }

    /// The `fork_info` a validator client sends for `duty` on this network (Lighthouse's).
    pub fn fork_info(&self, duty: &Duty) -> ForkInfo {
        let genesis = self.genesis_fork_version();
        match duty {
            Duty::Deposit(_) | Duty::ValidatorRegistration(_) => ForkInfo {
                fork: Fork {
                    previous_version: genesis,
                    current_version: genesis,
                    epoch: 0,
                },
                genesis_validators_root: [0; 32],
            },
            Duty::VoluntaryExit(exit) if self.exit_version(exit.epoch).is_some() => {
                let capella = self.exit_version(exit.epoch).expect("checked");
                ForkInfo {
                    fork: Fork {
                        previous_version: capella,
                        current_version: capella,
                        epoch: exit.epoch,
                    },
                    genesis_validators_root: self.genesis_validators_root,
                }
            }
            other => ForkInfo {
                fork: self.fork_at(other.epoch()),
                genesis_validators_root: self.genesis_validators_root,
            },
        }
    }

    /// Whether `request`'s `fork_info` is this network's for its duty (module docs). Nothing
    /// is corrected: a request with another `fork_info` is refused.
    pub fn check(&self, request: &DutyRequest) -> Result<(), WrongFork> {
        let fork = &request.fork;
        match &request.duty {
            Duty::Deposit(_) => {
                let expected = self.fork_info(&request.duty);
                return if *fork == expected {
                    Ok(())
                } else {
                    Err(WrongFork::Deposit {
                        expected: hex_version(&self.genesis_fork_version()),
                    })
                };
            }
            Duty::ValidatorRegistration(_) => {
                return if *fork == self.fork_info(&request.duty) {
                    Ok(())
                } else {
                    Err(WrongFork::Registration {
                        expected: hex_version(&self.genesis_fork_version()),
                    })
                };
            }
            _ if fork.genesis_validators_root != self.genesis_validators_root => {
                return Err(WrongFork::OtherChain);
            }
            Duty::VoluntaryExit(exit) if self.exit_version(exit.epoch).is_some() => {
                let expected = self.fork_info(&request.duty).fork;
                return if fork.fork == expected {
                    Ok(())
                } else {
                    Err(WrongFork::Exit {
                        epoch: exit.epoch,
                        expected: describe_fork(&expected),
                    })
                };
            }
            _ => {}
        }
        // A fork of this schedule, exactly as the schedule has it...
        let index = self
            .forks
            .iter()
            .position(|scheduled| scheduled.version == fork.fork.current_version)
            .ok_or_else(|| WrongFork::UnknownVersion {
                version: hex_version(&fork.fork.current_version),
            })?;
        let expected = self.fork_of(index);
        // The beacon state's own form on a network whose genesis is at a later fork (and after a
        // blob-parameter-only fork): the version twice, at an epoch where it is in effect.
        // Lighthouse sends the state's fork.
        let state_form = fork.fork.previous_version == fork.fork.current_version
            && self.index_at(fork.fork.epoch) == index;
        if fork.fork != expected && !state_form {
            return Err(WrongFork::NotAFork {
                version: hex_version(&fork.fork.current_version),
                previous: hex_version(&fork.fork.previous_version),
                epoch: fork.fork.epoch,
                expected: describe_fork(&expected),
            });
        }
        // ... whose version at the duty's domain epoch is the schedule's.
        let epoch = request.duty.epoch();
        let (used, scheduled) = (fork.version_at(epoch), self.version_at(epoch));
        if used != scheduled {
            return Err(WrongFork::WrongVersion {
                epoch,
                used: hex_version(&used),
                expected: hex_version(&scheduled),
            });
        }
        Ok(())
    }

    /// What identifies the network: its genesis validators root, clock and genesis fork version.
    /// Approvals are bound to it (`admin`), and the replicated state records it.
    pub fn identity(&self) -> Digest {
        let mut hasher = Sha256::default();
        hasher.update(b"eth-mpc-signer/network/v1");
        hasher.update(&self.genesis_validators_root);
        hasher.update(&self.genesis_time.to_be_bytes());
        hasher.update(&self.seconds_per_slot.to_be_bytes());
        hasher.update(&self.slots_per_epoch.to_be_bytes());
        hasher.update(&self.genesis_fork_version());
        hasher.finalize().1
    }

    /// A digest of the fork schedule, to compare nodes' configurations (`GET /eth/network`). It
    /// is not recorded: a release that adds a fork changes it.
    pub fn schedule_digest(&self) -> Digest {
        let mut hasher = Sha256::default();
        hasher.update(b"eth-mpc-signer/fork-schedule/v1");
        for fork in self.forks {
            hasher.update(&[fork.name as u8]);
            hasher.update(&fork.version);
            hasher.update(&fork.epoch.to_be_bytes());
        }
        hasher.finalize().1
    }
}

/// A network as `GET /eth/network` describes it (and `mpc-admin` reads it back).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkJson {
    #[serde(with = "serde_utils::quoted_u64")]
    pub genesis_time: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub seconds_per_slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub slots_per_epoch: u64,
    #[serde(with = "super::types::hex_bytes")]
    pub genesis_validators_root: Root,
    pub forks: Vec<ScheduledFork>,
    /// [`Network::identity`], `0x`-hex (derived: ignored when read back).
    #[serde(default)]
    pub identity: String,
    /// [`Network::schedule_digest`], `0x`-hex (derived: ignored when read back).
    #[serde(default)]
    pub schedule_digest: String,
}

impl Network {
    pub fn to_json(&self) -> NetworkJson {
        NetworkJson {
            genesis_time: self.genesis_time,
            seconds_per_slot: self.seconds_per_slot,
            slots_per_epoch: self.slots_per_epoch,
            genesis_validators_root: self.genesis_validators_root,
            forks: self.forks.to_vec(),
            identity: format!("0x{}", hex::encode(self.identity())),
            schedule_digest: format!("0x{}", hex::encode(self.schedule_digest())),
        }
    }

    /// The network `json` describes, checked; its schedule lives as long as the process (it is
    /// read once, at start).
    pub fn from_json(json: &NetworkJson) -> Result<Self, String> {
        let network = Self {
            genesis_time: json.genesis_time,
            seconds_per_slot: json.seconds_per_slot,
            slots_per_epoch: json.slots_per_epoch,
            genesis_validators_root: json.genesis_validators_root,
            forks: Vec::leak(json.forks.clone()),
        };
        network.validate()?;
        Ok(network)
    }
}

const fn hex32(hex: &str) -> Root {
    let bytes = hex.as_bytes();
    assert!(bytes.len() == 64, "32 bytes of hex");
    let mut root = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        root[i] = (digit(bytes[2 * i]) << 4) | digit(bytes[2 * i + 1]);
        i += 1;
    }
    root
}

const fn digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("lowercase hex"),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/eth/network.rs"]
mod tests;
