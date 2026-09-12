//! Throwaway transport-neutral simulation. No socket or runtime dependency.

use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Path { NativeDirect, BrowserDirect, Relay }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppEvent { pub id: u64, pub bytes: Vec<u8> }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultPlan { pub drop_every: Option<usize>, pub duplicate: bool, pub reverse: bool }

/// Models delivery semantics without pretending to model cryptographic trust.
pub fn deliver(mut events: Vec<AppEvent>, faults: FaultPlan) -> Vec<AppEvent> {
    if let Some(n) = faults.drop_every.filter(|n| *n > 0) {
        events = events.into_iter().enumerate().filter(|(i, _)| (i + 1) % n != 0).map(|(_, e)| e).collect();
    }
    if faults.duplicate { let copy = events.clone(); events.extend(copy); }
    if faults.reverse { events.reverse(); }
    events
}

pub struct BoundedInbox { max_events: usize, queue: VecDeque<AppEvent> }

impl BoundedInbox {
    pub fn new(max_events: usize) -> Self { Self { max_events, queue: VecDeque::new() } }
    pub fn push(&mut self, event: AppEvent) -> bool {
        if self.queue.len() >= self.max_events { return false; }
        self.queue.push_back(event); true
    }
    pub fn pop(&mut self) -> Option<AppEvent> { self.queue.pop_front() }
    pub fn len(&self) -> usize { self.queue.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn events() -> Vec<AppEvent> { (0..4).map(|id| AppEvent { id, bytes: vec![id as u8] }).collect() }

    #[test]
    fn relay_is_delivery_only_and_can_reorder_duplicate_or_drop() {
        let got = deliver(events(), FaultPlan { drop_every: Some(3), duplicate: true, reverse: true });
        assert_eq!(got.iter().map(|e| e.id).collect::<Vec<_>>(), vec![3, 1, 0, 3, 1, 0]);
    }

    #[test]
    fn slow_consumers_hit_a_bound() {
        let mut inbox = BoundedInbox::new(2);
        assert!(inbox.push(AppEvent { id: 1, bytes: vec![] }));
        assert!(inbox.push(AppEvent { id: 2, bytes: vec![] }));
        assert!(!inbox.push(AppEvent { id: 3, bytes: vec![] }));
        assert_eq!(inbox.len(), 2);
    }
}
