//! Private drained-controller evidence and cumulative browser accounting.
use sha2::{Digest, Sha256};
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
    Context,
};
use vhalla_private_relay::MAX_RELAY_ITEMS;

pub(crate) const RECEIPT_BYTES: usize = 546;
pub(crate) const MAX_GENERATIONS: u64 = 16;
pub(crate) const MAX_ATTEMPTS: u64 = 65_536;
pub(crate) const MAX_BYTES: u64 = 1024 * 1024 * 1024;
type Result<T> = core::result::Result<T, ()>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Accounting {
    pub attempts: u64,
    pub wire_bytes: u64,
    pub retained: u64,
    pub received: u64,
    pub refused_total: u64,
    pub byte_ceiling: u64,
    pub attempt_ceiling: u64,
}
impl Accounting {
    fn fields(self) -> [u64; 7] {
        [
            self.attempts,
            self.wire_bytes,
            self.retained,
            self.received,
            self.refused_total,
            self.byte_ceiling,
            self.attempt_ceiling,
        ]
    }
    fn check(self) -> Result<()> {
        if self.byte_ceiling == 0
            || self.byte_ceiling > MAX_BYTES
            || self.attempt_ceiling == 0
            || self.attempt_ceiling > MAX_ATTEMPTS
            || self.attempts > self.attempt_ceiling
            || self.wire_bytes > self.byte_ceiling
        {
            return Err(());
        }
        Ok(())
    }
    pub fn commitment(self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/private/controller-browser-accounting/v1\0");
        for value in self.fields() {
            hash.update(value.to_be_bytes());
        }
        hash.finalize().into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Receipt {
    pub context: Context,
    pub original_binding: [u8; 32],
    pub transition: [u8; 32],
    pub generation: u64,
    pub namespace: [u8; 32],
    pub endpoint: [u8; 32],
    pub binding: [u8; 32],
    pub head: u64,
    pub items: [u8; 32],
    pub outbox: u64,
    pub controls: u64,
    pub image: [u8; 32],
    pub accounting: Accounting,
    pub prior: [u8; 32],
}
fn context_fields(context: Context) -> [[u8; 32]; 4] {
    [
        *context.scope.room.as_bytes(),
        *context.scope.anchor.as_bytes(),
        *context.account.as_bytes(),
        *context.device.as_bytes(),
    ]
}
impl Receipt {
    fn check(&self) -> Result<()> {
        self.accounting.check()?;
        if self.generation >= MAX_GENERATIONS
            || self.head > MAX_RELAY_ITEMS as u64
            || [
                self.original_binding,
                self.transition,
                self.namespace,
                self.endpoint,
                self.binding,
                self.items,
                self.image,
            ]
            .contains(&[0; 32])
            || (self.generation == 0) != (self.prior == [0; 32])
            || (self.generation == 0 && self.original_binding != self.binding)
        {
            return Err(());
        }
        Ok(())
    }
    pub fn controller_id(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/private/controller-id/v1\0");
        for field in context_fields(self.context) {
            hash.update(field);
        }
        hash.update(self.original_binding);
        hash.finalize().into()
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check()?;
        let mut out = b"VHCDRAIN\x01".to_vec();
        for field in context_fields(self.context) {
            out.extend(field);
        }
        out.extend(self.controller_id());
        out.extend(self.original_binding);
        out.extend(self.transition);
        out.extend(self.generation.to_be_bytes());
        out.extend(self.namespace);
        out.extend(self.endpoint);
        out.extend(self.binding);
        out.extend(self.head.to_be_bytes());
        out.extend(self.items);
        out.extend(self.outbox.to_be_bytes());
        out.extend(self.controls.to_be_bytes());
        out.extend(self.image);
        out.push(1);
        for value in self.accounting.fields() {
            out.extend(value.to_be_bytes());
        }
        out.extend(self.accounting.commitment());
        out.extend(self.prior);
        Ok(out)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != RECEIPT_BYTES || &raw[..9] != b"VHCDRAIN\x01" || raw[425] != 1 {
            return Err(());
        }
        let mut r = Reader(&raw[9..]);
        let context = Context {
            scope: PrivateRoomScope {
                room: RoomId::from_bytes(r.array()?).map_err(|_| ())?,
                anchor: AnchorId::from_bytes(r.array()?).map_err(|_| ())?,
            },
            account: Key::from_bytes(r.array()?).map_err(|_| ())?,
            device: Key::from_bytes(r.array()?).map_err(|_| ())?,
        };
        let controller = r.array()?;
        let mut value = Self {
            context,
            original_binding: r.array()?,
            transition: r.array()?,
            generation: r.number()?,
            namespace: r.array()?,
            endpoint: r.array()?,
            binding: r.array()?,
            head: r.number()?,
            items: r.array()?,
            outbox: r.number()?,
            controls: r.number()?,
            image: r.array()?,
            accounting: Accounting {
                attempts: 0,
                wire_bytes: 0,
                retained: 0,
                received: 0,
                refused_total: 0,
                byte_ceiling: 0,
                attempt_ceiling: 0,
            },
            prior: [0; 32],
        };
        if r.array::<1>()? != [1] {
            return Err(());
        }
        value.accounting = Accounting {
            attempts: r.number()?,
            wire_bytes: r.number()?,
            retained: r.number()?,
            received: r.number()?,
            refused_total: r.number()?,
            byte_ceiling: r.number()?,
            attempt_ceiling: r.number()?,
        };
        let accounting = r.array::<32>()?;
        value.prior = r.array()?;
        if !r.0.is_empty()
            || controller != value.controller_id()
            || accounting != value.accounting.commitment()
        {
            return Err(());
        }
        value.check()?;
        Ok(value)
    }
    pub fn commitment(&self) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/private/controller-pause-receipt/v1\0");
        hash.update(self.encode()?);
        Ok(hash.finalize().into())
    }
}
struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, tail) = self.0.split_at_checked(N).ok_or(())?;
        self.0 = tail;
        head.try_into().map_err(|_| ())
    }
    fn number(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}

pub(crate) fn items_commitment(namespace: [u8; 32], items: &[[u8; 32]]) -> Result<[u8; 32]> {
    if items.len() > MAX_RELAY_ITEMS {
        return Err(());
    }
    let mut hash = Sha256::new();
    hash.update(b"vhalla/private/relay-generation-items/v1\0");
    hash.update(namespace);
    for (i, digest) in items.iter().enumerate() {
        hash.update((i as u64 + 1).to_be_bytes());
        hash.update(digest);
    }
    hash.update((items.len() as u64).to_be_bytes());
    Ok(hash.finalize().into())
}
