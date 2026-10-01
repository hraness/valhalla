use crate::Error;
use alloc::vec::Vec;
use ed25519_dalek::VerifyingKey;

pub(crate) fn checked_key(key: &[u8; 32]) -> Result<VerifyingKey, Error> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| Error::Key)?;
    if key.is_weak() {
        return Err(Error::Key);
    }
    Ok(key)
}

pub(crate) fn prefix(magic: &[u8; 5]) -> Vec<u8> {
    magic.to_vec()
}

pub(crate) struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8], magic: &[u8; 5]) -> Result<Self, Error> {
        let mut reader = Self(bytes);
        if reader.take(magic.len())? != magic {
            return Err(Error::Protocol);
        }
        Ok(reader)
    }

    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let value = self.0.get(..length).ok_or(Error::Encoding)?;
        self.0 = &self.0[length..];
        Ok(value)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }

    pub(crate) fn count(&mut self, max: usize) -> Result<usize, Error> {
        let count = usize::from(u16::from_be_bytes(self.array()?));
        if count > max {
            return Err(Error::Bounds);
        }
        Ok(count)
    }

    pub(crate) fn finish(self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Encoding)
        }
    }
}
