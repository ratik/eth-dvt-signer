//! A fake SEV-SNP chip and guest device for tests: reports in AMD's format, signed by a VCEK of
//! its own (not AMD's: [super::certs::verify_vcek] refuses it), and keys derived from a secret of
//! its own over the same guest fields as the real device.

use super::{
    Product, Tcb, Vcek,
    device::{Device, KeyRequest, field},
    report,
};
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _},
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// A guest on a fake chip: what its reports say, and its chip's keys.
pub struct Chip {
    vcek: EcdsaKeyPair,
    secret: [u8; 32],
    pub product: Product,
    pub chip_id: [u8; 64],
    pub tcb: Tcb,
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub policy: u64,
    pub vmpl: u32,
}

impl Chip {
    /// A Milan chip `id` running a guest with `measurement`, no debugging, VMPL 0.
    pub fn new(id: u8, measurement: [u8; 48]) -> Self {
        Self {
            vcek: EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).expect("a P-384 key"),
            secret: [id; 32],
            product: Product::Milan,
            chip_id: [id; 64],
            tcb: Tcb {
                boot_loader: 4,
                tee: 0,
                snp: 22,
                microcode: 213,
                fmc: 0,
            },
            measurement,
            host_data: [0; 32],
            policy: report::POLICY_RESERVED | (1 << 16),
            vmpl: 0,
        }
    }

    /// The VCEK, as [super::certs::verify_vcek] would read AMD's.
    pub fn vcek(&self) -> Vcek {
        Vcek {
            product: self.product,
            hwid: self.chip_id.to_vec(),
            tcb: self.tcb,
            public_key: self.vcek.public_key().as_ref().to_vec(),
        }
    }

    /// The unsigned report with `report_data`.
    pub fn unsigned(&self, report_data: &[u8; 64]) -> Vec<u8> {
        let turin = self.product.turin_tcb();
        let tcb = self.tcb.to_raw(turin);
        let mut raw = vec![0u8; report::SIZE];
        let mut put = |offset: usize, bytes: &[u8]| {
            raw[offset..offset + bytes.len()].copy_from_slice(bytes);
        };
        put(0x00, &3u32.to_le_bytes());
        put(0x08, &self.policy.to_le_bytes());
        put(0x30, &self.vmpl.to_le_bytes());
        put(0x34, &report::ECDSA_P384_SHA384.to_le_bytes());
        put(0x38, &tcb.to_le_bytes());
        put(0x50, report_data);
        put(0x90, &self.measurement);
        put(0xC0, &self.host_data);
        put(0x180, &tcb.to_le_bytes());
        let (family, model) = match self.product {
            Product::Milan => (0x19, 0x01),
            Product::Genoa => (0x19, 0x11),
            Product::Turin => (0x1A, 0x02),
        };
        put(0x188, &[family, model, 1]);
        put(0x1A0, &self.chip_id);
        put(0x1E0, &tcb.to_le_bytes());
        put(0x1F0, &tcb.to_le_bytes());
        raw
    }

    /// Sign `raw` (a report) with this chip's VCEK, in place.
    pub fn sign(&self, raw: &mut [u8]) {
        let signature = self
            .vcek
            .sign(&SystemRandom::new(), &raw[..report::SIGNED])
            .expect("signing");
        let fixed = signature.as_ref();
        for (index, offset) in [report::SIGNED, report::SIGNED + 72]
            .into_iter()
            .enumerate()
        {
            let field = &mut raw[offset..offset + 72];
            field.fill(0);
            for i in 0..48 {
                field[i] = fixed[index * 48 + 47 - i];
            }
        }
    }
}

impl Device for Chip {
    fn report(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, String> {
        let mut raw = self.unsigned(report_data);
        self.sign(&mut raw);
        Ok(raw)
    }

    fn derived_key(&self, request: &KeyRequest) -> Result<Zeroizing<[u8; 32]>, String> {
        let committed = self.tcb.to_raw(self.product.turin_tcb());
        if request.fields & field::TCB_VERSION != 0
            && !Tcb::from_raw(committed, self.product.turin_tcb()).at_least(&Tcb::from_raw(
                request.tcb_version,
                self.product.turin_tcb(),
            ))
        {
            return Err("SNP_GET_DERIVED_KEY: the TCB version exceeds the committed one".into());
        }
        let mut hasher = Sha256::new();
        hasher.update(b"fake-sev-snp/derived-key");
        hasher.update(self.secret);
        hasher.update(request.fields.to_le_bytes());
        let select = |bit: u64, bytes: &[u8], hasher: &mut Sha256| {
            if request.fields & bit != 0 {
                hasher.update(bytes);
            }
        };
        select(field::POLICY, &self.policy.to_le_bytes(), &mut hasher);
        select(field::MEASUREMENT, &self.measurement, &mut hasher);
        select(
            field::TCB_VERSION,
            &request.tcb_version.to_le_bytes(),
            &mut hasher,
        );
        Ok(Zeroizing::new(hasher.finalize().into()))
    }
}
