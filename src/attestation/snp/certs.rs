//! AMD's certificates: the root key (ARK) and the SEV key (ASK) of each product, pinned in the
//! source, and a chip's VCEK, which signs its reports.
//!
//! - **ARK and ASK.** From AMD's Key Distribution Service (`kdsintf.amd.com/vcek/v1/<product>/
//!   cert_chain`), the ARK checked against a second source (virtee/sev's built-in copies). The ARK
//!   signs itself and the ASK (RSA-PSS, SHA-384).
//! - **VCEK.** One per chip and TCB version. The ASK signs it. Its extensions name the chip
//!   (`hwID`) and the TCB version it is for: a report it signs must name the same.

use super::report::Tcb;
use aws_lc_rs::signature::{RSA_PSS_2048_8192_SHA384, UnparsedPublicKey};
use x509_parser::{certificate::X509Certificate, prelude::FromDer as _};

/// The EPYC generations with SEV-SNP.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Product {
    Milan,
    Genoa,
    Turin,
}

impl Product {
    pub const ALL: [Self; 3] = [Self::Milan, Self::Genoa, Self::Turin];

    /// AMD's name, as KDS URLs and policies use it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Milan => "Milan",
            Self::Genoa => "Genoa",
            Self::Turin => "Turin",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|product| product.name().eq_ignore_ascii_case(name))
    }

    /// The product a version-3 report's CPUID names (family, model); `None` for others.
    pub const fn from_cpuid(family: u8, model: u8) -> Option<Self> {
        match (family, model) {
            (0x19, 0x00..=0x0F) => Some(Self::Milan),
            (0x19, 0x10..=0x1F | 0xA0..=0xAF) => Some(Self::Genoa),
            (0x1A, 0x00..=0x11) => Some(Self::Turin),
            _ => None,
        }
    }

    /// Whether the TCB encoding is Turin's ([Tcb::from_raw]).
    pub const fn turin_tcb(self) -> bool {
        matches!(self, Self::Turin)
    }

    /// The ARK and ASK (PEM).
    const fn chain(self) -> (&'static str, &'static str) {
        match self {
            Self::Milan => (
                include_str!("amd/milan-ark.pem"),
                include_str!("amd/milan-ask.pem"),
            ),
            Self::Genoa => (
                include_str!("amd/genoa-ark.pem"),
                include_str!("amd/genoa-ask.pem"),
            ),
            Self::Turin => (
                include_str!("amd/turin-ark.pem"),
                include_str!("amd/turin-ask.pem"),
            ),
        }
    }

    /// The ARK's common name.
    const fn ark_name(self) -> &'static str {
        match self {
            Self::Milan => "ARK-Milan",
            Self::Genoa => "ARK-Genoa",
            Self::Turin => "ARK-Turin",
        }
    }
}

const OID_PRODUCT_NAME: &str = "1.3.6.1.4.1.3704.1.2";
const OID_BOOT_LOADER: &str = "1.3.6.1.4.1.3704.1.3.1";
const OID_TEE: &str = "1.3.6.1.4.1.3704.1.3.2";
const OID_SNP: &str = "1.3.6.1.4.1.3704.1.3.3";
const OID_MICROCODE: &str = "1.3.6.1.4.1.3704.1.3.8";
const OID_FMC: &str = "1.3.6.1.4.1.3704.1.3.9";
const OID_HWID: &str = "1.3.6.1.4.1.3704.1.4";
const OID_RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

/// A VCEK whose chain to AMD's root checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vcek {
    pub product: Product,
    /// The chip it belongs to (64 bytes; 8 for Turin).
    pub hwid: Vec<u8>,
    /// The TCB version it is for.
    pub tcb: Tcb,
    /// Its P-384 public key, uncompressed (`04 ‖ x ‖ y`).
    pub public_key: Vec<u8>,
}

fn parse(der: &[u8]) -> Result<X509Certificate<'_>, String> {
    match X509Certificate::from_der(der) {
        Ok(([], certificate)) => Ok(certificate),
        Ok(_) => Err("trailing bytes after the certificate".into()),
        Err(err) => Err(format!("certificate: {err}")),
    }
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("a pinned PEM");
    pem.contents
}

/// Whether `issuer` signed `certificate` with RSA-PSS (SHA-384), the only scheme of AMD's chain.
fn signed_by(
    certificate: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<(), String> {
    if certificate.signature_algorithm.algorithm.to_id_string() != OID_RSASSA_PSS {
        return Err("the certificate is not signed with RSA-PSS".into());
    }
    if certificate.issuer() != issuer.subject() {
        return Err("the certificate's issuer is not the expected key".into());
    }
    UnparsedPublicKey::new(
        &RSA_PSS_2048_8192_SHA384,
        issuer.public_key().subject_public_key.data.as_ref(),
    )
    .verify(
        certificate.tbs_certificate.as_ref(),
        certificate.signature_value.data.as_ref(),
    )
    .map_err(|_| "the certificate's signature does not verify".to_string())
}

fn valid_at(certificate: &X509Certificate<'_>, now: u64) -> Result<(), String> {
    let now = i64::try_from(now).unwrap_or(i64::MAX);
    let validity = certificate.validity();
    if now < validity.not_before.timestamp() || now > validity.not_after.timestamp() {
        return Err("the certificate is not valid now".into());
    }
    Ok(())
}

/// Check the pinned chain of `product`: the ARK signs itself and the ASK.
pub fn check_pinned(product: Product) -> Result<(), String> {
    let (ark, ask) = product.chain();
    let (ark, ask) = (pem_to_der(ark), pem_to_der(ask));
    let (ark, ask) = (parse(&ark)?, parse(&ask)?);
    let name = ark
        .subject()
        .iter_common_name()
        .next()
        .and_then(|name| name.as_str().ok());
    if name != Some(product.ark_name()) {
        return Err(format!("the pinned ARK of {} is {name:?}", product.name()));
    }
    signed_by(&ark, &ark)?;
    signed_by(&ask, &ark)
}

/// An extension's value: the content of a DER INTEGER (a patch level), as one byte.
fn spl(value: &[u8]) -> Option<u8> {
    match value {
        [0x02, 1, level] => Some(*level),
        [0x02, 2, 0, level] => Some(*level),
        _ => None,
    }
}

/// The `hwID` extension: a DER OCTET STRING, or the raw bytes.
fn hwid(value: &[u8]) -> Vec<u8> {
    match value {
        [0x04, length, rest @ ..] if usize::from(*length) == rest.len() => rest.to_vec(),
        _ => value.to_vec(),
    }
}

/// Check that a VCEK (DER) chains to the pinned ASK and ARK of one of `products`, at `now` (unix
/// seconds), and read what it is for.
pub fn verify_vcek(der: &[u8], products: &[Product], now: u64) -> Result<Vcek, String> {
    let vcek = parse(der)?;
    let mut last = String::from("no product allowed");
    for &product in products {
        let (_, ask) = product.chain();
        let ask = pem_to_der(ask);
        let ask = parse(&ask)?;
        if let Err(err) = signed_by(&vcek, &ask) {
            last = format!("{}: {err}", product.name());
            continue;
        }
        valid_at(&vcek, now)?;
        return read_vcek(&vcek, product);
    }
    Err(format!("the VCEK does not chain to AMD's root ({last})"))
}

fn read_vcek(vcek: &X509Certificate<'_>, product: Product) -> Result<Vcek, String> {
    let spki = vcek.public_key();
    if spki.algorithm.algorithm.to_id_string() != OID_EC_PUBLIC_KEY {
        return Err("the VCEK's key is not an EC key".into());
    }
    let public_key = spki.subject_public_key.data.to_vec();
    if public_key.len() != 97 || public_key[0] != 0x04 {
        return Err("the VCEK's key is not an uncompressed P-384 point".into());
    }
    let extension = |oid: &str| {
        vcek.extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == oid)
            .map(|extension| extension.value)
    };
    let level = |oid: &str, name: &str| -> Result<u8, String> {
        extension(oid)
            .and_then(spl)
            .ok_or_else(|| format!("the VCEK has no {name} patch level"))
    };
    if let Some(name) = extension(OID_PRODUCT_NAME) {
        let text = String::from_utf8_lossy(name);
        if !text.contains(product.name()) {
            return Err(format!("the VCEK is for {text}, not {}", product.name()));
        }
    }
    let tcb = Tcb {
        boot_loader: level(OID_BOOT_LOADER, "boot loader")?,
        tee: level(OID_TEE, "TEE")?,
        snp: level(OID_SNP, "SNP")?,
        microcode: level(OID_MICROCODE, "microcode")?,
        fmc: if product.turin_tcb() {
            level(OID_FMC, "FMC")?
        } else {
            0
        },
    };
    let hwid = extension(OID_HWID)
        .map(hwid)
        .ok_or("the VCEK names no chip (hwID)")?;
    Ok(Vcek {
        product,
        hwid,
        tcb,
        public_key,
    })
}

/// The KDS URL of the VCEK for `chip_id` at `tcb`.
pub fn kds_url(product: Product, chip_id: &[u8], tcb: &Tcb) -> String {
    let chip = if product.turin_tcb() {
        &chip_id[..8.min(chip_id.len())]
    } else {
        chip_id
    };
    let mut url = format!(
        "https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        product.name(),
        hex::encode(chip),
        tcb.boot_loader,
        tcb.tee,
        tcb.snp,
        tcb.microcode
    );
    if product.turin_tcb() {
        url.push_str(&format!("&fmcSPL={}", tcb.fmc));
    }
    url
}

/// How often [fetch_vcek] asks KDS when it answers 429 or 503 (it rate-limits clients).
const KDS_ATTEMPTS: u32 = 5;
/// The longest wait between two attempts (a longer `Retry-After` is cut to it).
const KDS_MAX_WAIT_SECS: u64 = 30;

/// Fetch a VCEK (DER) from AMD's Key Distribution Service. It is checked by [verify_vcek] like
/// any other: KDS is not trusted. KDS rate-limits its clients: on 429 or 503 the request is
/// repeated after `Retry-After` (or 2, 4, 8, 16 s), at most [KDS_ATTEMPTS] times.
pub async fn fetch_vcek(product: Product, chip_id: &[u8], tcb: &Tcb) -> Result<Vec<u8>, String> {
    let url = kds_url(product, chip_id, tcb);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|err| err.to_string())?;
    let mut attempt = 0;
    let response = loop {
        attempt += 1;
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|err| format!("{url}: {err}"))?;
        let status = response.status();
        if status.is_success() {
            break response;
        }
        let throttled = status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status == reqwest::StatusCode::SERVICE_UNAVAILABLE;
        if !throttled || attempt >= KDS_ATTEMPTS {
            return Err(format!("{url}: {status} (attempt {attempt})"));
        }
        let wait = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()?.trim().parse::<u64>().ok())
            .unwrap_or(1 << attempt)
            .min(KDS_MAX_WAIT_SECS);
        tracing::warn!(%url, %status, wait, attempt, "AMD KDS is throttling: retrying");
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
    };
    response
        .bytes()
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|err| format!("{url}: {err}"))
}
