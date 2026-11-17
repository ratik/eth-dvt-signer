//! The Roughtime protocol, client side: a request, and the checks of an answer (RFC 10049, and the
//! two draft versions public servers still answer with).
//!
//! A request carries a fresh 32-byte nonce. An answer is accepted only if:
//! - the server's long-term key signed the delegation (`CERT`: `DELE` with `PUBK`, `MINT`, `MAXT`);
//! - the delegated key signed the response (`SREP`: `MIDP`, `RADI`, `ROOT`);
//! - the Merkle path (`INDX`, `PATH`) proves that `ROOT` covers this request;
//! - `MIDP` lies within the delegation's validity, and `RADI` is not zero.
//!
//! The server then vouches that the true time was within `MIDP ± RADI` when it processed the
//! request: after the request was sent, since the request holds the nonce. Nothing else in an
//! answer is trusted.
//!
//! **Versions.** The request offers all three; the server picks one:
//!
//! | Version | Servers | Signature contexts | Merkle leaf, hash | Timestamps |
//! | --- | --- | --- | --- | --- |
//! | 1 (RFC 10049) | time.txryan.com, rough.time.nl | `Roughtime v1 …` | the request packet, SHA-512/32; hash first | seconds |
//! | `0x8000000c` (drafts 12–19) | most | `RoughTime v1 …` | the request packet, SHA-512/32; either order (drafts 14–15 and 16–19 differ) | seconds |
//! | `0x80000007` (draft 07) | Netnod | `RoughTime v1 …` | the nonce, SHA-512/256; node first | MJD and microseconds |

use aws_lc_rs::{
    digest::{SHA512, SHA512_256, digest},
    signature::{ED25519, UnparsedPublicKey},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// RFC 10049.
pub const VERSION_RFC: u32 = 1;
/// Draft 07 (Netnod's servers).
pub const VERSION_DRAFT_07: u32 = 0x8000_0007;
/// Drafts 12 to 19 (one wire version).
pub const VERSION_DRAFT_12: u32 = 0x8000_000C;
/// The versions a request offers, ascending.
pub const VERSIONS: [u32; 3] = [VERSION_RFC, VERSION_DRAFT_07, VERSION_DRAFT_12];

/// The size of a request packet (header and message).
pub const REQUEST_SIZE: usize = 12 + 1024;
/// The largest answer accepted (a server never answers with more than the request's size).
pub const MAX_RESPONSE: usize = REQUEST_SIZE;
const MAGIC: &[u8; 8] = b"ROUGHTIM";
/// Nested messages accepted in an answer (the response, `SREP`, `CERT`, `DELE`).
const MAX_TAGS: usize = 32;
const MAX_PATH: usize = 32;

const TAG_VER: [u8; 4] = *b"VER\0";
const TAG_SRV: [u8; 4] = *b"SRV\0";
const TAG_NONC: [u8; 4] = *b"NONC";
const TAG_TYPE: [u8; 4] = *b"TYPE";
const TAG_ZZZZ: [u8; 4] = *b"ZZZZ";
const TAG_SIG: [u8; 4] = *b"SIG\0";
const TAG_SREP: [u8; 4] = *b"SREP";
const TAG_CERT: [u8; 4] = *b"CERT";
const TAG_DELE: [u8; 4] = *b"DELE";
const TAG_PUBK: [u8; 4] = *b"PUBK";
const TAG_MINT: [u8; 4] = *b"MINT";
const TAG_MAXT: [u8; 4] = *b"MAXT";
const TAG_INDX: [u8; 4] = *b"INDX";
const TAG_PATH: [u8; 4] = *b"PATH";
const TAG_RADI: [u8; 4] = *b"RADI";
const TAG_MIDP: [u8; 4] = *b"MIDP";
const TAG_ROOT: [u8; 4] = *b"ROOT";

/// Why an answer is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("malformed answer: {0}")]
    Malformed(&'static str),
    #[error("unsupported version {0:#x}")]
    Version(u32),
    #[error("the server's key did not sign the delegation")]
    Delegation,
    #[error("the delegated key did not sign the response")]
    Response,
    #[error("the response does not answer this request (Merkle proof)")]
    Merkle,
    #[error("the answer echoes another nonce")]
    Nonce,
    #[error("the response's time lies outside its delegation's validity")]
    Validity,
    #[error("the response has a zero radius")]
    Radius,
}

/// A server's guarantee: the true time was within `[earliest, latest]` when it processed the
/// request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    pub version: u32,
    /// `MIDP - RADI`, microseconds since the Unix epoch.
    pub earliest: i64,
    /// `MIDP + RADI`, microseconds since the Unix epoch.
    pub latest: i64,
    pub radius: Duration,
}

impl Answer {
    /// The midpoint.
    pub const fn midpoint(&self) -> i64 {
        self.earliest + (self.latest - self.earliest) / 2
    }

    pub fn earliest_time(&self) -> SystemTime {
        micros_to_time(self.earliest)
    }
}

/// Microseconds since the Unix epoch as a time (clamped at the epoch).
pub fn micros_to_time(micros: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(u64::try_from(micros).unwrap_or(0))
}

/// `SHA-512(0xff ‖ key)[..32]`: the `SRV` tag naming the key a client expects.
pub fn srv(public_key: &[u8; 32]) -> [u8; 32] {
    truncated(&[&[0xff], public_key.as_slice()], false)
}

fn truncated(parts: &[&[u8]], sha512_256: bool) -> [u8; 32] {
    let data: Vec<u8> = parts.concat();
    let hash = digest(if sha512_256 { &SHA512_256 } else { &SHA512 }, &data);
    hash.as_ref()[..32].try_into().expect("at least 32 bytes")
}

/// A message: tags ascending (as little-endian `u32`), each value a multiple of 4 bytes long.
fn encode(mut pairs: Vec<([u8; 4], Vec<u8>)>) -> Vec<u8> {
    pairs.sort_by_key(|(tag, _)| u32::from_le_bytes(*tag));
    let mut out = Vec::new();
    out.extend_from_slice(&(pairs.len() as u32).to_le_bytes());
    let mut offset = 0u32;
    for (index, (_, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.extend_from_slice(&offset.to_le_bytes());
        }
        offset += value.len() as u32;
    }
    for (tag, _) in &pairs {
        out.extend_from_slice(tag);
    }
    for (_, value) in &pairs {
        out.extend_from_slice(value);
    }
    out
}

/// A request packet for `nonce`, to the server with `public_key`: `VER` (every version this
/// client checks), `SRV`, `NONC`, `TYPE` 0, padded with `ZZZZ` to 1024 bytes.
pub fn request(public_key: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
    let versions: Vec<u8> = VERSIONS.iter().flat_map(|v| v.to_le_bytes()).collect();
    let pairs = |padding: usize| {
        vec![
            (TAG_VER, versions.clone()),
            (TAG_SRV, srv(public_key).to_vec()),
            (TAG_NONC, nonce.to_vec()),
            (TAG_TYPE, 0u32.to_le_bytes().to_vec()),
            (TAG_ZZZZ, vec![0; padding]),
        ]
    };
    let unpadded = encode(pairs(0)).len();
    let message = encode(pairs(1024 - unpadded));
    let mut packet = Vec::with_capacity(REQUEST_SIZE);
    packet.extend_from_slice(MAGIC);
    packet.extend_from_slice(&(message.len() as u32).to_le_bytes());
    packet.extend_from_slice(&message);
    debug_assert_eq!(packet.len(), REQUEST_SIZE);
    packet
}

/// A parsed message: its tags and values, in order.
struct Message<'a> {
    pairs: Vec<([u8; 4], &'a [u8])>,
}

impl<'a> Message<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let word = |at: usize| -> Result<u32, Error> {
            bytes
                .get(at..at + 4)
                .map(|w| u32::from_le_bytes(w.try_into().expect("4 bytes")))
                .ok_or(Error::Malformed("truncated header"))
        };
        let count = word(0)? as usize;
        if count == 0 || count > MAX_TAGS {
            return Err(Error::Malformed("tag count"));
        }
        let header = 8 * count;
        if bytes.len() < header {
            return Err(Error::Malformed("truncated header"));
        }
        let values = &bytes[header..];
        let mut offsets = vec![0usize];
        for i in 1..count {
            offsets.push(word(4 * i)? as usize);
        }
        offsets.push(values.len());
        let mut pairs = Vec::with_capacity(count);
        let mut previous: Option<u32> = None;
        for i in 0..count {
            let tag: [u8; 4] = bytes[4 * count + 4 * i..4 * count + 4 * i + 4]
                .try_into()
                .expect("4 bytes");
            let key = u32::from_le_bytes(tag);
            if previous.is_some_and(|previous| key <= previous) {
                return Err(Error::Malformed("tags not ascending"));
            }
            previous = Some(key);
            let (start, end) = (offsets[i], offsets[i + 1]);
            if start % 4 != 0 || end % 4 != 0 || start > end || end > values.len() {
                return Err(Error::Malformed("offsets"));
            }
            pairs.push((tag, &values[start..end]));
        }
        Ok(Self { pairs })
    }

    fn get(&self, tag: [u8; 4]) -> Option<&'a [u8]> {
        self.pairs
            .iter()
            .find(|(candidate, _)| *candidate == tag)
            .map(|(_, value)| *value)
    }

    fn require(&self, tag: [u8; 4], what: &'static str) -> Result<&'a [u8], Error> {
        self.get(tag).ok_or(Error::Malformed(what))
    }

    fn fixed<const N: usize>(&self, tag: [u8; 4], what: &'static str) -> Result<[u8; N], Error> {
        self.require(tag, what)?
            .try_into()
            .map_err(|_| Error::Malformed(what))
    }
}

fn u32_of(bytes: [u8; 4]) -> u32 {
    u32::from_le_bytes(bytes)
}

fn u64_of(bytes: [u8; 8]) -> u64 {
    u64::from_le_bytes(bytes)
}

/// How a version encodes what this client checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wire {
    Rfc,
    Draft12,
    Draft07,
}

impl Wire {
    const fn of(version: u32) -> Option<Self> {
        match version {
            VERSION_RFC => Some(Self::Rfc),
            VERSION_DRAFT_12 => Some(Self::Draft12),
            VERSION_DRAFT_07 => Some(Self::Draft07),
            _ => None,
        }
    }

    const fn delegation_context(self) -> &'static [u8] {
        match self {
            Self::Rfc => b"Roughtime v1 delegation signature\0",
            Self::Draft12 | Self::Draft07 => b"RoughTime v1 delegation signature\0",
        }
    }

    const fn response_context(self) -> &'static [u8] {
        match self {
            Self::Rfc => b"Roughtime v1 response signature\0",
            Self::Draft12 | Self::Draft07 => b"RoughTime v1 response signature\0",
        }
    }

    /// A timestamp, as microseconds since the Unix epoch.
    fn timestamp(self, raw: u64) -> Result<i64, Error> {
        match self {
            Self::Rfc | Self::Draft12 => i64::try_from(raw)
                .ok()
                .and_then(|seconds| seconds.checked_mul(1_000_000))
                .ok_or(Error::Malformed("timestamp")),
            Self::Draft07 => {
                // Modified Julian Date (upper 24 bits) and microseconds of the day (lower 40).
                let day = (raw >> 40) as i64;
                let micros = (raw & 0xFF_FFFF_FFFF) as i64;
                if micros >= 86_401 * 1_000_000 {
                    return Err(Error::Malformed("timestamp"));
                }
                Ok((day - 40_587) * 86_400 * 1_000_000 + micros)
            }
        }
    }

    fn radius(self, raw: u32) -> Duration {
        match self {
            Self::Rfc | Self::Draft12 => Duration::from_secs(u64::from(raw)),
            Self::Draft07 => Duration::from_micros(u64::from(raw)),
        }
    }
}

fn verify_ed25519(key: &[u8], context: &[u8], message: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&[context, message].concat(), signature)
        .is_ok()
}

/// Whether `path` from `leaf` at `index` leads to `root` (`node_first`: the sibling precedes the
/// running hash when the index bit is 0).
fn merkle(
    leaf: &[u8],
    index: u32,
    path: &[u8],
    root: &[u8; 32],
    sha512_256: bool,
    node_first: bool,
) -> bool {
    let mut hash = truncated(&[&[0x00], leaf], sha512_256);
    let mut index = index;
    for sibling in path.as_chunks::<32>().0 {
        let (left, right): (&[u8], &[u8]) = if (index & 1 == 0) != node_first {
            (&hash, sibling)
        } else {
            (sibling, &hash)
        };
        hash = truncated(&[&[0x01], left, right], sha512_256);
        index >>= 1;
    }
    index == 0 && hash == *root
}

/// Check `response`, the answer of the server with `public_key` to `request` (the packet this
/// client sent, with `nonce`).
pub fn verify(
    public_key: &[u8; 32],
    request: &[u8],
    nonce: &[u8; 32],
    response: &[u8],
) -> Result<Answer, Error> {
    if response.len() > MAX_RESPONSE {
        return Err(Error::Malformed("larger than the request"));
    }
    let rest = response
        .strip_prefix(MAGIC.as_slice())
        .ok_or(Error::Malformed("no ROUGHTIM header"))?;
    let (length, message) = rest
        .split_first_chunk::<4>()
        .ok_or(Error::Malformed("no length"))?;
    if u32_of(*length) as usize != message.len() {
        return Err(Error::Malformed("length"));
    }
    let top = Message::parse(message)?;
    let srep_bytes = top.require(TAG_SREP, "no SREP")?;
    let srep = Message::parse(srep_bytes)?;
    let cert = Message::parse(top.require(TAG_CERT, "no CERT")?)?;
    let dele_bytes = cert.require(TAG_DELE, "no DELE")?;
    let dele = Message::parse(dele_bytes)?;

    // The version: in SREP (RFC, drafts 12+), or at the top (draft 07). One this client offered.
    let version = match srep.get(TAG_VER).or_else(|| top.get(TAG_VER)) {
        Some(bytes) => u32_of(bytes.try_into().map_err(|_| Error::Malformed("VER"))?),
        None => return Err(Error::Malformed("no VER")),
    };
    let wire = Wire::of(version).ok_or(Error::Version(version))?;

    // An echoed nonce must be ours; RFC answers must echo it, and say TYPE 1.
    match top.get(TAG_NONC) {
        Some(echoed) if echoed != nonce.as_slice() => return Err(Error::Nonce),
        None if wire == Wire::Rfc => return Err(Error::Malformed("no NONC")),
        _ => {}
    }
    match top.get(TAG_TYPE) {
        Some(value) if value != 1u32.to_le_bytes().as_slice() => {
            return Err(Error::Malformed("TYPE"));
        }
        None if wire == Wire::Rfc => return Err(Error::Malformed("no TYPE")),
        _ => {}
    }

    // The delegation, by the long-term key; the response, by the delegated key.
    let delegation_signature = cert.fixed::<64>(TAG_SIG, "CERT SIG")?;
    if !verify_ed25519(
        public_key,
        wire.delegation_context(),
        dele_bytes,
        &delegation_signature,
    ) {
        return Err(Error::Delegation);
    }
    let delegated = dele.fixed::<32>(TAG_PUBK, "PUBK")?;
    let response_signature = top.fixed::<64>(TAG_SIG, "SIG")?;
    if !verify_ed25519(
        &delegated,
        wire.response_context(),
        srep_bytes,
        &response_signature,
    ) {
        return Err(Error::Response);
    }

    // The Merkle proof that ROOT covers this request.
    let root = srep.fixed::<32>(TAG_ROOT, "ROOT")?;
    let index = u32_of(top.fixed::<4>(TAG_INDX, "INDX")?);
    let path = top.require(TAG_PATH, "no PATH")?;
    if path.len() % 32 != 0 || path.len() / 32 > MAX_PATH {
        return Err(Error::Malformed("PATH"));
    }
    let proven = match wire {
        Wire::Rfc => merkle(request, index, path, &root, false, false),
        Wire::Draft12 => {
            merkle(request, index, path, &root, false, false)
                || merkle(request, index, path, &root, false, true)
        }
        Wire::Draft07 => merkle(nonce, index, path, &root, true, true),
    };
    if !proven {
        return Err(Error::Merkle);
    }

    // The time, within the delegation's validity.
    let midpoint = wire.timestamp(u64_of(srep.fixed::<8>(TAG_MIDP, "MIDP")?))?;
    let not_before = wire.timestamp(u64_of(dele.fixed::<8>(TAG_MINT, "MINT")?))?;
    let not_after = wire
        .timestamp(u64_of(dele.fixed::<8>(TAG_MAXT, "MAXT")?))
        .unwrap_or(i64::MAX);
    if midpoint < not_before || midpoint > not_after {
        return Err(Error::Validity);
    }
    let radius = wire.radius(u32_of(srep.fixed::<4>(TAG_RADI, "RADI")?));
    if radius.is_zero() {
        return Err(Error::Radius);
    }
    let radius_micros = i64::try_from(radius.as_micros()).map_err(|_| Error::Malformed("RADI"))?;
    Ok(Answer {
        version,
        earliest: midpoint.saturating_sub(radius_micros),
        latest: midpoint.saturating_add(radius_micros),
        radius,
    })
}

#[cfg(test)]
#[path = "../../tests/unit/clock/roughtime.rs"]
mod tests;
