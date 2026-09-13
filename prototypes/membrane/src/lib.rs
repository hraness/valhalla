use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type RealmId = u64;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Capability {
    Read,
    Write,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub id: u64,
    pub realm: RealmId,
    pub capability: Capability,
    pub context: u64,
    pub epoch: u64,
    pub payload: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    UnknownRealm,
    WrongContext,
    Revoked,
    Capability,
    TooLarge,
    QueueFull,
    Replay,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    Accepted,
    Rejected(Reject),
}
struct Cell {
    context: u64,
    epoch: u64,
    grants: BTreeSet<Capability>,
    revoked: bool,
    max_frame: usize,
    seen: BTreeSet<u64>,
    queue: VecDeque<Frame>,
}
pub struct Membrane {
    cells: BTreeMap<RealmId, Cell>,
    queue_limit: usize,
    seen_limit: usize,
    queued: usize,
    seen: usize,
}
impl Membrane {
    pub fn new(queue_limit: usize) -> Self {
        Self {
            cells: BTreeMap::new(),
            queue_limit,
            seen_limit: queue_limit.max(1).saturating_mul(4),
            queued: 0,
            seen: 0,
        }
    }
    pub fn admit(
        &mut self,
        realm: RealmId,
        context: u64,
        grants: impl IntoIterator<Item = Capability>,
        max_frame: usize,
    ) {
        if let Some(cell) = self.cells.get_mut(&realm) {
            cell.epoch = cell.epoch.saturating_add(1);
            let removed = cell.queue.len();
            cell.queue.clear();
            self.queued = self.queued.saturating_sub(removed);
            cell.context = context;
            cell.grants = grants.into_iter().collect();
            cell.max_frame = max_frame;
            return;
        }
        self.cells.insert(
            realm,
            Cell {
                context,
                epoch: 1,
                grants: grants.into_iter().collect(),
                revoked: false,
                max_frame,
                seen: BTreeSet::new(),
                queue: VecDeque::new(),
            },
        );
    }
    pub fn revoke(&mut self, realm: RealmId) {
        if let Some(c) = self.cells.get_mut(&realm) {
            c.revoked = true;
            c.epoch = c.epoch.saturating_add(1);
            let removed = c.queue.len();
            c.queue.clear();
            self.queued = self.queued.saturating_sub(removed);
            self.seen = self.seen.saturating_sub(c.seen.len());
            c.seen.clear();
        }
    }
    pub fn receive(&mut self, frame: Frame) -> Admission {
        let Some(c) = self.cells.get(&frame.realm) else {
            return Admission::Rejected(Reject::UnknownRealm);
        };
        if c.revoked {
            return Admission::Rejected(Reject::Revoked);
        }
        if frame.context != c.context {
            return Admission::Rejected(Reject::WrongContext);
        }
        if frame.epoch != c.epoch {
            return Admission::Rejected(Reject::WrongContext);
        }
        if frame.payload.len() > c.max_frame {
            return Admission::Rejected(Reject::TooLarge);
        }
        if !c.grants.contains(&frame.capability) {
            return Admission::Rejected(Reject::Capability);
        }
        if c.seen.contains(&frame.id) {
            return Admission::Rejected(Reject::Replay);
        }
        if self.queued >= self.queue_limit {
            return Admission::Rejected(Reject::QueueFull);
        }
        if self.seen >= self.seen_limit {
            if let Some(cell) = self.cells.values_mut().find(|cell| !cell.seen.is_empty()) {
                if let Some(oldest) = cell.seen.iter().next().copied() {
                    cell.seen.remove(&oldest);
                    self.seen = self.seen.saturating_sub(1);
                }
            }
        }
        let c = self
            .cells
            .get_mut(&frame.realm)
            .expect("cell checked above");
        c.seen.insert(frame.id);
        c.queue.push_back(frame);
        self.seen = self.seen.saturating_add(1);
        self.queued = self.queued.saturating_add(1);
        Admission::Accepted
    }
    pub fn pop(&mut self, realm: RealmId) -> Option<Frame> {
        let frame = self.cells.get_mut(&realm)?.queue.pop_front();
        if frame.is_some() {
            self.queued = self.queued.saturating_sub(1);
        }
        frame
    }
    pub fn queued(&self, realm: RealmId) -> usize {
        self.cells.get(&realm).map_or(0, |c| c.queue.len())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    fn f(id: u64, realm: u64, cap: Capability) -> Frame {
        f_at(id, realm, cap, 1)
    }
    fn f_at(id: u64, realm: u64, cap: Capability, epoch: u64) -> Frame {
        Frame {
            id,
            realm,
            capability: cap,
            context: 9,
            epoch,
            payload: vec![1],
        }
    }
    #[test]
    fn context_and_capability_are_membrane_bound() {
        let mut m = Membrane::new(2);
        m.admit(1, 9, [Capability::Read], 4);
        assert_eq!(m.receive(f(1, 1, Capability::Read)), Admission::Accepted);
        assert_eq!(
            m.receive(Frame {
                context: 8,
                ..f(2, 1, Capability::Read)
            }),
            Admission::Rejected(Reject::WrongContext)
        );
        assert_eq!(
            m.receive(f(3, 1, Capability::Write)),
            Admission::Rejected(Reject::Capability)
        );
    }
    #[test]
    fn bounded_queue_and_replay() {
        let mut m = Membrane::new(1);
        m.admit(1, 9, [Capability::Read], 4);
        assert_eq!(m.receive(f(1, 1, Capability::Read)), Admission::Accepted);
        assert_eq!(
            m.receive(f(1, 1, Capability::Read)),
            Admission::Rejected(Reject::Replay)
        );
        assert_eq!(
            m.receive(f(2, 1, Capability::Read)),
            Admission::Rejected(Reject::QueueFull)
        );
        assert!(m.pop(1).is_some());
        assert_eq!(m.receive(f(2, 1, Capability::Read)), Admission::Accepted);
    }
    #[test]
    fn hostile_sizes_and_revocation_fail_closed() {
        let mut m = Membrane::new(2);
        m.admit(1, 9, [Capability::Read], 2);
        assert_eq!(
            m.receive(Frame {
                payload: vec![0; 3],
                ..f(1, 1, Capability::Read)
            }),
            Admission::Rejected(Reject::TooLarge)
        );
        m.revoke(1);
        assert_eq!(
            m.receive(f(2, 1, Capability::Read)),
            Admission::Rejected(Reject::Revoked)
        );
        assert_eq!(m.queued(1), 0);
    }

    #[test]
    fn re_admission_does_not_clear_revocation_or_replay_state() {
        let mut m = Membrane::new(2);
        m.admit(1, 9, [Capability::Read], 4);
        assert_eq!(m.receive(f(1, 1, Capability::Read)), Admission::Accepted);
        m.revoke(1);
        m.admit(1, 9, [Capability::Read], 4);
        assert_eq!(
            m.receive(f(1, 1, Capability::Read)),
            Admission::Rejected(Reject::Revoked)
        );
    }

    #[test]
    fn re_admission_rotates_epoch_for_live_cells() {
        let mut m = Membrane::new(2);
        m.admit(1, 9, [Capability::Read], 4);
        let old = f(1, 1, Capability::Read);
        m.admit(1, 9, [Capability::Read], 4);
        assert_eq!(m.receive(old), Admission::Rejected(Reject::WrongContext));
        assert_eq!(
            m.receive(f_at(2, 1, Capability::Read, 2)),
            Admission::Accepted
        );
    }

    #[test]
    fn queue_limit_is_global_across_realms() {
        let mut m = Membrane::new(1);
        m.admit(1, 9, [Capability::Read], 4);
        m.admit(2, 9, [Capability::Read], 4);
        assert_eq!(m.receive(f(1, 1, Capability::Read)), Admission::Accepted);
        assert_eq!(
            m.receive(f(2, 2, Capability::Read)),
            Admission::Rejected(Reject::QueueFull)
        );
    }

    #[derive(Clone, Debug)]
    enum Action {
        Admit(u8),
        Revoke(u8),
        Receive(u8, u16, bool),
        Pop(u8),
    }

    fn action_strategy() -> impl Strategy<Value = Action> {
        prop_oneof![
            any::<u8>().prop_map(Action::Admit),
            any::<u8>().prop_map(Action::Revoke),
            (any::<u8>(), any::<u16>(), any::<bool>())
                .prop_map(|(realm, id, stale)| Action::Receive(realm, id, stale)),
            any::<u8>().prop_map(Action::Pop),
        ]
    }

    proptest! {
        #[test]
        fn arbitrary_lifecycle_keeps_global_bounds(actions in prop::collection::vec(action_strategy(), 0..128)) {
            let mut membrane = Membrane::new(3);
            for (step, action) in actions.into_iter().enumerate() {
                let is_pop = matches!(&action, Action::Pop(_));
                let realm = match action {
                    Action::Admit(raw) => {
                        let realm = u64::from(raw % 4);
                        membrane.admit(realm, 9, [Capability::Read], 8);
                        realm
                    }
                    Action::Revoke(raw) => {
                        let realm = u64::from(raw % 4);
                        membrane.revoke(realm);
                        realm
                    }
                    Action::Receive(raw, id, stale) => {
                        let realm = u64::from(raw % 4);
                        if let Some((context, current_epoch)) = membrane
                            .cells.get(&realm).map(|cell| (cell.context, cell.epoch)) {
                            let epoch = if stale { current_epoch.saturating_sub(1) } else { current_epoch };
                            let _ = membrane.receive(Frame {
                                id: u64::from(id), realm, capability: Capability::Read,
                                context, epoch, payload: vec![step as u8],
                            });
                        }
                        realm
                    }
                    Action::Pop(raw) => u64::from(raw % 4),
                };
                if is_pop {
                    let _ = membrane.pop(realm);
                }
                let total: usize = membrane.cells.values().map(|cell| cell.queue.len()).sum();
                prop_assert!(total <= 3);
                prop_assert_eq!(total, membrane.queued);
                prop_assert!(membrane.cells.values().all(|cell| !cell.revoked || cell.queue.is_empty()));
            }
        }
    }
}
