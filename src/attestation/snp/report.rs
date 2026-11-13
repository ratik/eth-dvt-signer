//! The SEV-SNP attestation report (AMD SEV-SNP ABI specification, `ATTESTATION_REPORT`): its
//! fields at their offsets, and the ECDSA P-384 signature over its first 0x2A0 bytes.

/// The size of a report.
pub const SIZE: usize = 0x4A0;
/// The signed part: everything before the signature.
pub const SIGNED: usize = 0x2A0;
/// ECDSA P-384 with SHA-384, the only signature algorithm of a report.
pub const ECDSA_P384_SHA384: u32 = 1;

/// `POLICY` bit: the guest may be debugged (the hypervisor reads and writes its memory).
pub const POLICY_DEBUG: u64 = 1 << 19;
/// `POLICY` bit: a migration agent may be associated with the guest.
pub const POLICY_MIGRATE_MA: u64 = 1 << 18;
/// `POLICY` bit: reserved, must be one.
pub const POLICY_RESERVED: u64 = 1 << 17;

/// A TCB version: the security patch levels of the firmware components and the microcode. Its
/// 64-bit encoding differs between Milan/Genoa and Turin ([Tcb::from_raw]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tcb {
    pub boot_loader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
    /// Turin and later only (0 before).
    #[serde(default)]
    pub fmc: u8,
}

impl Tcb {
    /// Decode a `TCB_VERSION`: Milan and Genoa `bl, tee, 0, 0, 0, 0, snp, ucode`; Turin
    /// `fmc, bl, tee, snp, 0, 0, 0, ucode` (little-endian bytes).
    pub const fn from_raw(raw: u64, turin: bool) -> Self {
        let b = raw.to_le_bytes();
        if turin {
            Self {
                fmc: b[0],
                boot_loader: b[1],
                tee: b[2],
                snp: b[3],
                microcode: b[7],
            }
        } else {
            Self {
                boot_loader: b[0],
                tee: b[1],
                snp: b[6],
                microcode: b[7],
                fmc: 0,
            }
        }
    }

    /// The encoding [Tcb::from_raw] decodes.
    pub const fn to_raw(self, turin: bool) -> u64 {
        let mut b = [0u8; 8];
        if turin {
            b[0] = self.fmc;
            b[1] = self.boot_loader;
            b[2] = self.tee;
            b[3] = self.snp;
        } else {
            b[0] = self.boot_loader;
            b[1] = self.tee;
            b[6] = self.snp;
        }
        b[7] = self.microcode;
        u64::from_le_bytes(b)
    }

    /// Whether every component is at least `minimum`'s.
    pub const fn at_least(&self, minimum: &Self) -> bool {
        self.boot_loader >= minimum.boot_loader
            && self.tee >= minimum.tee
            && self.snp >= minimum.snp
            && self.microcode >= minimum.microcode
            && self.fmc >= minimum.fmc
    }
}

/// A parsed report. The raw bytes stay with it: the signature covers them, not the fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    raw: Vec<u8>,
}

impl Report {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != SIZE {
            return Err(format!(
                "an SEV-SNP report is {SIZE} bytes, not {}",
                bytes.len()
            ));
        }
        let report = Self {
            raw: bytes.to_vec(),
        };
        if report.version() < 2 {
            return Err(format!(
                "SEV-SNP report version {} (at least 2)",
                report.version()
            ));
        }
        Ok(report)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn u32_at(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.raw[offset..offset + 4].try_into().expect("4 bytes"))
    }

    fn u64_at(&self, offset: usize) -> u64 {
        u64::from_le_bytes(self.raw[offset..offset + 8].try_into().expect("8 bytes"))
    }

    pub fn version(&self) -> u32 {
        self.u32_at(0x00)
    }

    pub fn guest_svn(&self) -> u32 {
        self.u32_at(0x04)
    }

    /// The guest policy the hypervisor launched it with (`POLICY_*`).
    pub fn policy(&self) -> u64 {
        self.u64_at(0x08)
    }

    pub fn family_id(&self) -> &[u8] {
        &self.raw[0x10..0x20]
    }

    pub fn image_id(&self) -> &[u8] {
        &self.raw[0x20..0x30]
    }

    /// The privilege level that requested the report (0 is the most privileged).
    pub fn vmpl(&self) -> u32 {
        self.u32_at(0x30)
    }

    pub fn signature_algorithm(&self) -> u32 {
        self.u32_at(0x34)
    }

    pub fn current_tcb_raw(&self) -> u64 {
        self.u64_at(0x38)
    }

    pub fn platform_info(&self) -> u64 {
        self.u64_at(0x40)
    }

    /// Bit 1 of the key-info word: the chip ID is masked (all zero).
    pub fn mask_chip_id(&self) -> bool {
        self.u32_at(0x48) & 0b10 != 0
    }

    /// Bits 2..=4 of the key-info word: 0 when the VCEK signed the report, 1 for a VLEK.
    pub fn signing_key(&self) -> u32 {
        (self.u32_at(0x48) >> 2) & 0b111
    }

    /// The 64 bytes the guest put in its request.
    pub fn report_data(&self) -> &[u8] {
        &self.raw[0x50..0x90]
    }

    /// The launch measurement (SHA-384).
    pub fn measurement(&self) -> &[u8] {
        &self.raw[0x90..0xC0]
    }

    /// The 32 bytes the hypervisor gave at launch.
    pub fn host_data(&self) -> &[u8] {
        &self.raw[0xC0..0xE0]
    }

    pub fn id_key_digest(&self) -> &[u8] {
        &self.raw[0xE0..0x110]
    }

    pub fn reported_tcb_raw(&self) -> u64 {
        self.u64_at(0x180)
    }

    /// Family and model of the CPU (version 3 and later; zero before).
    pub fn cpuid(&self) -> (u8, u8) {
        if self.version() >= 3 {
            (self.raw[0x188], self.raw[0x189])
        } else {
            (0, 0)
        }
    }

    pub fn chip_id(&self) -> &[u8] {
        &self.raw[0x1A0..0x1E0]
    }

    pub fn committed_tcb_raw(&self) -> u64 {
        self.u64_at(0x1E0)
    }

    pub fn launch_tcb_raw(&self) -> u64 {
        self.u64_at(0x1F0)
    }

    /// The signed bytes.
    pub fn signed(&self) -> &[u8] {
        &self.raw[..SIGNED]
    }

    /// The signature as `r ‖ s`, each 48 bytes big-endian (the report holds each in 72 bytes,
    /// little-endian); `None` if either does not fit in 48 bytes.
    pub fn signature_fixed(&self) -> Option<[u8; 96]> {
        let mut fixed = [0u8; 96];
        for (index, offset) in [SIGNED, SIGNED + 72].into_iter().enumerate() {
            let little = &self.raw[offset..offset + 72];
            if little[48..].iter().any(|&byte| byte != 0) {
                return None;
            }
            for (i, &byte) in little[..48].iter().enumerate() {
                fixed[index * 48 + 47 - i] = byte;
            }
        }
        Some(fixed)
    }
}
