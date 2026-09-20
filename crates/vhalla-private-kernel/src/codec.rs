use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Context, Error, Result, StorageKey};

pub(crate) struct Writer {
    bytes: Vec<u8>,
    limit: usize,
}
impl Writer {
    pub(crate) fn new(magic: &[u8], limit: usize) -> Result<Self> {
        let mut out = Self {
            bytes: Vec::new(),
            limit,
        };
        out.put(magic)?;
        Ok(out)
    }
    pub(crate) fn put(&mut self, bytes: &[u8]) -> Result<()> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > self.limit)
        {
            return Err(Error::Bounds);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    pub(crate) fn byte(&mut self, byte: u8) -> Result<()> {
        self.put(&[byte])
    }
    pub(crate) fn u64(&mut self, value: u64) -> Result<()> {
        self.put(&value.to_be_bytes())
    }
    pub(crate) fn blob(&mut self, bytes: &[u8], limit: usize) -> Result<()> {
        if bytes.len() > limit {
            return Err(Error::Bounds);
        }
        self.put(
            &u32::try_from(bytes.len())
                .map_err(|_| Error::Bounds)?
                .to_be_bytes(),
        )?;
        self.put(bytes)
    }
    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

pub(crate) struct Reader<'a> {
    pub(crate) rest: &'a [u8],
}
impl<'a> Reader<'a> {
    pub(crate) fn new(raw: &'a [u8], magic: &[u8], limit: usize) -> Result<Self> {
        if raw.len() > limit {
            return Err(Error::Bounds);
        }
        let mut r = Self { rest: raw };
        if r.take(magic.len())? != magic {
            return Err(Error::Encoding);
        }
        Ok(r)
    }
    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if count > self.rest.len() {
            return Err(Error::Encoding);
        }
        let (head, tail) = self.rest.split_at(count);
        self.rest = tail;
        Ok(head)
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    pub(crate) fn byte(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub(crate) fn blob(&mut self, limit: usize) -> Result<&'a [u8]> {
        let len = u32::from_be_bytes(self.array()?) as usize;
        // Bound the declared size before offset arithmetic or any allocation.
        if len > limit {
            return Err(Error::Bounds);
        }
        self.take(len)
    }
    pub(crate) fn end(self) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::Encoding)
        }
    }
}

pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Entropy)?;
    Ok(bytes)
}
pub(crate) fn hash(domain: &[u8], raw: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(raw);
    hash.finalize().into()
}
fn aad(context: Context, purpose: &[u8]) -> Vec<u8> {
    let mut out = b"vhalla/private-kernel/encrypted-storage/v1\0".to_vec();
    out.extend(context.encode());
    out.extend(purpose);
    out
}
pub(crate) fn seal(
    key: &StorageKey,
    context: Context,
    purpose: &[u8],
    clear: &[u8],
    maximum: usize,
) -> Result<Vec<u8>> {
    if clear.len().checked_add(40).is_none_or(|len| len > maximum) {
        return Err(Error::Bounds);
    }
    let nonce: [u8; 24] = random()?;
    let cipher = XChaCha20Poly1305::new((&*key.0).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: clear,
                aad: &aad(context, purpose),
            },
        )
        .map_err(|_| Error::Authentication)?;
    let mut out = nonce.to_vec();
    out.extend(cipher);
    Ok(out)
}
pub(crate) fn unseal(
    key: &StorageKey,
    context: Context,
    purpose: &[u8],
    raw: &[u8],
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    if raw.len() < 40 || raw.len() > maximum {
        return Err(Error::Bounds);
    }
    let clear = XChaCha20Poly1305::new((&*key.0).into())
        .decrypt(
            XNonce::from_slice(&raw[..24]),
            Payload {
                msg: &raw[24..],
                aad: &aad(context, purpose),
            },
        )
        .map_err(|_| Error::Authentication)?;
    Ok(Zeroizing::new(clear))
}
