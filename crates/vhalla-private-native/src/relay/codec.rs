//! Native mailbox dispatch for the shared canonical wire codec.
use super::net::Mailbox;
use super::RelayItem;
pub(super) use vhalla_private_relay::codec::*;
type NetResult<T> = std::result::Result<T, NetError>;
pub(super) fn dispatch(store: &mut dyn Mailbox, op: u8, body: &[u8]) -> NetResult<(u8, Vec<u8>)> {
    match op {
        OP_PUT => match RelayItem::decode(body).and_then(|item| store.put(item)) {
            Ok(receipt) => Ok((STATUS_OK, encode_receipt(receipt))),
            Err(error) => Ok((status(error), Vec::new())),
        },
        OP_PAGE if body.len() == 10 => {
            let after = u64::from_be_bytes(body[..8].try_into().expect("bounded"));
            let limit = u16::from_be_bytes(body[8..].try_into().expect("bounded")) as usize;
            match store.page(after, limit) {
                Ok(page) => Ok((STATUS_OK, encode_page(&page)?)),
                Err(error) => Ok((status(error), Vec::new())),
            }
        }
        _ => Ok((STATUS_BOUNDS, Vec::new())),
    }
}
