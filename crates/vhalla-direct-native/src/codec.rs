use crate::{Error, Result};
use sha2::{Digest, Sha256};
use vhalla_direct_store::Record;

pub(crate) const CONFIG: u8 = 1;
pub(crate) const GENESIS: u8 = 2;
pub(crate) const RESERVATION: u8 = 3;
pub(crate) const COMPLETION: u8 = 4;
pub(crate) const EVENT: u8 = 5;
pub(crate) const POLICY: u8 = 6;
pub(crate) const AUTHOR_INDEX: u8 = 7;
pub(crate) const COMMITTED: u8 = 8;
pub(crate) const OBSERVED: u8 = 9;
pub(crate) const POLICY_INDEX: u8 = 10;
pub(crate) const LOCAL_EVENT: u8 = 11;
pub(crate) const LOCAL_POLICY: u8 = 12;
pub(crate) const AUTHOR_FORK: u8 = 13;
pub(crate) const OWNER_FORK: u8 = 14;
pub(crate) const LOST_AUTHOR: u8 = 15;
pub(crate) const LOST_OWNER: u8 = 16;

pub(crate) fn raw_key(tag: u8, id: [u8; 32]) -> [u8; 33] {
    let mut out = [0; 33];
    out[0] = tag;
    out[1..].copy_from_slice(&id);
    out
}
pub(crate) fn key(tag: u8, input: &[u8]) -> [u8; 33] {
    let mut hash = Sha256::new();
    hash.update(b"vhalla/direct-native/key/v1\0");
    hash.update([tag]);
    hash.update(input);
    raw_key(tag, hash.finalize().into())
}
pub(crate) fn config_key() -> [u8; 33] {
    key(CONFIG, b"configuration")
}
pub(crate) fn operation_key(tag: u8, op: [u8; 16]) -> [u8; 33] {
    key(tag, &op)
}
pub(crate) fn revision_key(tag: u8, revision: u64) -> [u8; 33] {
    key(tag, &revision.to_be_bytes())
}
pub(crate) fn author_key(author: [u8; 32], sequence: u64) -> [u8; 33] {
    let mut bytes = author.to_vec();
    bytes.extend_from_slice(&sequence.to_be_bytes());
    key(AUTHOR_INDEX, &bytes)
}
pub(crate) fn record(key: [u8; 33], bytes: &[u8]) -> Result<Record> {
    Record::new(key, bytes).map_err(Error::from)
}
pub(crate) fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| Error::Corrupt)
}

pub(crate) struct Config {
    pub(crate) account: [u8; 32],
    pub(crate) author: [u8; 32],
    pub(crate) created: bool,
    pub(crate) creation_nonce: [u8; 32],
}
impl Config {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = b"VHDNC002".to_vec();
        out.extend_from_slice(&self.account);
        out.extend_from_slice(&self.author);
        out.push(u8::from(self.created));
        out.extend_from_slice(&self.creation_nonce);
        out
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        // Older configurations lack local creation provenance. Refuse them
        // without inventing a nonce or upgrading retained signing state.
        if bytes.len() != 105 || &bytes[..8] != b"VHDNC002" || bytes[72] > 1 {
            return Err(Error::Corrupt);
        }
        let creation_nonce = array(&bytes[73..105])?;
        if creation_nonce == [0; 32] {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            account: array(&bytes[8..40])?,
            author: array(&bytes[40..72])?,
            created: bytes[72] == 1,
            creation_nonce,
        })
    }
}

#[derive(Clone, Default)]
pub(crate) struct Image {
    pub(crate) pending_event: Option<[u8; 16]>,
    pub(crate) pending_policy: Option<[u8; 16]>,
    pub(crate) author_lost: bool,
    pub(crate) owner_lost: bool,
    // A full authenticated frame retained outside the exhausted immutable quota.
    // This crate deliberately has no operation to clear this recovery fence.
    pub(crate) blocked: Option<Record>,
}
impl Image {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = b"VHDNI001".to_vec();
        out.push(u8::from(self.author_lost) | (u8::from(self.owner_lost) << 1));
        for pending in [self.pending_event, self.pending_policy] {
            out.extend_from_slice(&pending.unwrap_or([0; 16]));
        }
        match &self.blocked {
            None => out.push(0),
            Some(record) => {
                out.push(1);
                out.extend_from_slice(&record.key());
                out.extend_from_slice(record.as_bytes());
            }
        }
        out
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 42 || &bytes[..8] != b"VHDNI001" || bytes[8] > 3 {
            return Err(Error::Corrupt);
        }
        let pending = |slice: &[u8]| -> Result<Option<[u8; 16]>> {
            let op = array(slice)?;
            Ok((op != [0; 16]).then_some(op))
        };
        let blocked = match bytes[41] {
            0 if bytes.len() == 42 => None,
            1 if bytes.len() > 75 => Some(record(array(&bytes[42..75])?, &bytes[75..])?),
            _ => return Err(Error::Corrupt),
        };
        Ok(Self {
            author_lost: bytes[8] & 1 != 0,
            owner_lost: bytes[8] & 2 != 0,
            pending_event: pending(&bytes[9..25])?,
            pending_policy: pending(&bytes[25..41])?,
            blocked,
        })
    }
}

pub(crate) struct Reservation {
    pub(crate) operation: [u8; 16],
    pub(crate) kind: u8,
    pub(crate) unsigned: Vec<u8>,
}
impl Reservation {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.kind];
        out.extend_from_slice(&self.operation);
        out.extend_from_slice(&self.unsigned);
        out
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 18 || ![EVENT, POLICY].contains(&bytes[0]) {
            return Err(Error::Corrupt);
        }
        let operation = array(&bytes[1..17])?;
        if operation == [0; 16] {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            operation,
            kind: bytes[0],
            unsigned: bytes[17..].to_vec(),
        })
    }
}

pub(crate) fn index_bytes(prefix: &[u8], id: [u8; 32]) -> Vec<u8> {
    let mut out = prefix.to_vec();
    out.extend_from_slice(&id);
    out
}

#[cfg(test)]
mod provenance_tests {
    use super::*;

    #[test]
    fn configuration_requires_explicit_version_and_nonzero_creation_provenance() {
        let config = Config {
            account: [1; 32],
            author: [2; 32],
            created: false,
            creation_nonce: [3; 32],
        };
        let bytes = config.encode();
        let decoded = Config::decode(&bytes).unwrap();
        assert_eq!(decoded.creation_nonce, config.creation_nonce);
        assert!(!decoded.created);
        let mut legacy = bytes[..73].to_vec();
        legacy[..8].copy_from_slice(b"VHDNC001");
        assert!(matches!(Config::decode(&legacy), Err(Error::Corrupt)));
        let mut zero = bytes.clone();
        zero[73..].fill(0);
        assert!(matches!(Config::decode(&zero), Err(Error::Corrupt)));
        let mut unknown = bytes;
        unknown[..8].copy_from_slice(b"VHDNC003");
        assert!(matches!(Config::decode(&unknown), Err(Error::Corrupt)));
    }
}
