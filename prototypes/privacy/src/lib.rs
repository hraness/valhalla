//! Reference state machine for membership epochs. It deliberately does not
//! implement cryptography; it tests the policy semantics around key rotation.

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Member(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Epoch(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyFingerprint(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateEnvelope { pub epoch: Epoch, pub key: KeyFingerprint, pub bytes: [u8; 4] }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject { NotMember, StaleEpoch, WrongKey }

pub struct Group {
    epoch: Epoch,
    key: KeyFingerprint,
    members: Vec<Member>,
}

impl Group {
    pub fn new(owner: Member, key: KeyFingerprint) -> Self { Self { epoch: Epoch(0), key, members: vec![owner] } }
    pub fn epoch(&self) -> Epoch { self.epoch }
    pub fn join(&mut self, member: Member, next_key: KeyFingerprint) { self.members.push(member); self.rotate(next_key); }
    pub fn leave(&mut self, member: Member, next_key: KeyFingerprint) { self.members.retain(|m| *m != member); self.rotate(next_key); }
    fn rotate(&mut self, key: KeyFingerprint) { self.epoch = Epoch(self.epoch.0 + 1); self.key = key; }
    pub fn seal(&self, sender: Member, bytes: [u8; 4]) -> Result<PrivateEnvelope, Reject> {
        if !self.members.contains(&sender) { return Err(Reject::NotMember); }
        Ok(PrivateEnvelope { epoch: self.epoch, key: self.key, bytes })
    }
    pub fn open(&self, recipient: Member, envelope: PrivateEnvelope) -> Result<[u8; 4], Reject> {
        if !self.members.contains(&recipient) { return Err(Reject::NotMember); }
        if envelope.epoch != self.epoch { return Err(Reject::StaleEpoch); }
        if envelope.key != self.key { return Err(Reject::WrongKey); }
        Ok(envelope.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn membership_changes_rotate_the_group_epoch_and_key() {
        let owner = Member(1);
        let removed = Member(2);
        let mut group = Group::new(owner, KeyFingerprint(10));
        group.join(removed, KeyFingerprint(11));
        let before_leave = group.seal(owner, *b"old!").unwrap();
        group.leave(removed, KeyFingerprint(12));
        assert_eq!(group.open(owner, before_leave), Err(Reject::StaleEpoch));
        assert_eq!(group.open(removed, group.seal(owner, *b"new!").unwrap()), Err(Reject::NotMember));
    }
}
