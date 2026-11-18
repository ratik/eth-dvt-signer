//! A value of a `commonware-storage` [Metadata](commonware_storage::metadata::Metadata) store,
//! kept in its encoded form.
//!
//! `Metadata` writes a whole new copy of the store whenever a key is added or a value changes
//! size, and that copy encodes every value again. Encoding a BLS12-381 point that this process
//! computed (a DKG output, a public polynomial) is a projective-to-affine conversion with a field
//! inversion, about 4 µs a point; one decoded from bytes is already affine (about 0.1 µs). With
//! values held as [Value]s, every block's `sync` of the replicated state and every write of the
//! secret store therefore cost time in proportion to the number of keys (docs/load-test.md,
//! section 4.1). An [Encoded] value is encoded once, when it is put, and written by copying its
//! bytes.
//!
//! The bytes are exactly the value's encoding: a store is the same on disk with either type.

use bytes::{BufMut, Bytes};
use commonware_codec::{Buf, Copying, Encode, EncodeSize, Error as CodecError, Read, Write};

/// `V` in its encoded form.
#[derive(Clone, Debug)]
pub struct Encoded<V> {
    bytes: Bytes,
    /// The value as read from the store: set by [Read] (once, at start), never by [Encoded::new].
    read: Option<V>,
}

impl<V: Encode> Encoded<V> {
    /// Encode `value` (once).
    pub fn new(value: &V) -> Self {
        Self {
            bytes: value.encode(),
            read: None,
        }
    }
}

impl<V> Encoded<V> {
    /// The value this was read as, if it was read from a store rather than made with
    /// [Encoded::new].
    pub const fn decoded(&self) -> Option<&V> {
        self.read.as_ref()
    }

    /// The encoding.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<V> Write for Encoded<V> {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.bytes);
    }
}

impl<V> EncodeSize for Encoded<V> {
    fn encode_size(&self) -> usize {
        self.bytes.len()
    }
}

impl<V: Read + Encode> Read for Encoded<V> {
    type Cfg = V::Cfg;

    /// Decode a `V` (checked as `V` checks it) and keep its bytes.
    fn read_cfg(buf: &mut impl Buf, cfg: &V::Cfg) -> Result<Self, CodecError> {
        // A contiguous buffer (what `Metadata` decodes from): the bytes are those just read.
        if buf.chunk().len() == buf.remaining() {
            let (value, used) = {
                let chunk = buf.chunk();
                let mut rest = Copying(chunk);
                let value = V::read_cfg(&mut rest, cfg)?;
                (value, chunk.len() - rest.0.len())
            };
            return Ok(Self {
                bytes: buf.copy_to_bytes(used),
                read: Some(value),
            });
        }
        let value = V::read_cfg(buf, cfg)?;
        Ok(Self {
            bytes: value.encode(),
            read: Some(value),
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/encoded.rs"]
mod tests;
