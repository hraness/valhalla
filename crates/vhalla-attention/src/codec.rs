use super::*;

const MAGIC: &[u8; 8] = b"VHAT\0\0\0\x01";
const DOMAIN: &[u8] = b"vhalla/attention/private-state/v1\0";

pub(super) fn encode(state: &Attention) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&state.reader.digest());
    out.extend_from_slice(&state.generation.to_be_bytes());
    for marks in [&state.selected, &state.requests] {
        out.push(u8::from(marks.groups_unknown));
        out.push(u8::from(marks.updates_unknown));
        count(&mut out, marks.group_unknown_owners.len());
        for owner in &marks.group_unknown_owners {
            out.extend_from_slice(owner.as_bytes());
        }
        count(&mut out, marks.update_unknown_owners.len());
        for owner in &marks.update_unknown_owners {
            out.extend_from_slice(owner.as_bytes());
        }
        count(&mut out, marks.groups.len());
        for (group, witness) in &marks.groups {
            put_group(&mut out, *group);
            out.extend_from_slice(witness.as_bytes());
        }
        count(&mut out, marks.updates.len());
        for update in &marks.updates {
            put_group(&mut out, update.group);
            out.extend_from_slice(update.event.as_bytes());
        }
    }
    let digest = checksum(&out);
    out.extend_from_slice(&digest);
    assert!(out.len() <= MAX_STATE_BYTES);
    out
}
pub(super) fn decode(bytes: &[u8], expected: ReaderScope) -> Result<Attention, Error> {
    if bytes.len() < 8 + 32 + 8 + 12 + 32 || bytes.len() > MAX_STATE_BYTES {
        return Err(Error::Bounds);
    }
    let (body, digest) = bytes.split_at(bytes.len() - 32);
    if checksum(body) != digest {
        return Err(Error::Encoding);
    }
    let mut input = Input { bytes: body, at: 0 };
    if input.take(8)? != MAGIC || input.take(32)? != expected.digest() {
        return Err(Error::Context);
    }
    let generation = u64::from_be_bytes(input.take(8)?.try_into().map_err(|_| Error::Encoding)?);
    let selected = input.marks(expected.owner)?;
    let requests = input.marks(expected.owner)?;
    if input.at != body.len() {
        return Err(Error::Encoding);
    }
    Ok(Attention {
        reader: expected,
        generation,
        selected,
        requests,
    })
}
fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}
fn count(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&u16::try_from(n).expect("bounded marks").to_be_bytes());
}
fn put_group(out: &mut Vec<u8>, group: Group) {
    out.extend_from_slice(group.recipient.as_bytes());
    out.extend_from_slice(group.source_owner.as_bytes());
    out.extend_from_slice(group.target.as_bytes());
    out.push(group.reason as u8);
}
struct Input<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Input<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(len).ok_or(Error::Bounds)?;
        let value = self.bytes.get(self.at..end).ok_or(Error::Encoding)?;
        self.at = end;
        Ok(value)
    }
    fn id(&mut self) -> Result<[u8; 32], Error> {
        self.take(32)?.try_into().map_err(|_| Error::Encoding)
    }
    fn boolean(&mut self) -> Result<bool, Error> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Encoding),
        }
    }
    fn count(&mut self) -> Result<usize, Error> {
        let count = usize::from(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Encoding)?,
        ));
        if count > MAX_MARKS {
            Err(Error::Bounds)
        } else {
            Ok(count)
        }
    }
    fn group(&mut self) -> Result<Group, Error> {
        let recipient = OwnerId::from_bytes(self.id()?);
        let source_owner = OwnerId::from_bytes(self.id()?);
        let target = RecordId::from_bytes(self.id()?);
        let reason = match self.take(1)?[0] {
            0 => Reason::Mention,
            1 => Reason::Reply,
            2 => Reason::Follow,
            3 => Reason::Reaction,
            4 => Reason::Repost,
            5 => Reason::Quote,
            6 => Reason::WatchedThread,
            _ => return Err(Error::Encoding),
        };
        Ok(Group {
            recipient,
            source_owner,
            target,
            reason,
        })
    }
    fn marks(&mut self, recipient: OwnerId) -> Result<Marks, Error> {
        let groups_unknown = self.boolean()?;
        let updates_unknown = self.boolean()?;
        let group_unknown_owners = self.owners()?;
        let update_unknown_owners = self.owners()?;
        let mut groups = BTreeMap::new();
        let mut previous = None;
        for _ in 0..self.count()? {
            let group = self.group()?;
            let witness = RecordId::from_bytes(self.id()?);
            if group.recipient != recipient || previous.is_some_and(|old| old >= group) {
                return Err(Error::Encoding);
            };
            previous = Some(group);
            groups.insert(group, witness);
        }
        let mut updates = BTreeSet::new();
        let mut previous = None;
        for _ in 0..self.count()? {
            let update = Update {
                group: self.group()?,
                event: RecordId::from_bytes(self.id()?),
            };
            if update.group.recipient != recipient
                || previous.is_some_and(|old| old >= update)
                || (!groups_unknown
                    && !group_unknown_owners.contains(&update.group.source_owner)
                    && !groups.contains_key(&update.group))
            {
                return Err(Error::Encoding);
            };
            previous = Some(update);
            updates.insert(update);
        }
        Ok(Marks {
            groups,
            updates,
            groups_unknown,
            updates_unknown,
            group_unknown_owners,
            update_unknown_owners,
        })
    }
    fn owners(&mut self) -> Result<BTreeSet<OwnerId>, Error> {
        let mut result = BTreeSet::new();
        let mut previous = None;
        for _ in 0..self.count()? {
            let owner = OwnerId::from_bytes(self.id()?);
            if previous.is_some_and(|old| old >= owner) {
                return Err(Error::Encoding);
            };
            previous = Some(owner);
            result.insert(owner);
        }
        Ok(result)
    }
}
