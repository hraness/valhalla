//! Local view freshness, separate from the service's authoritative receipt checks.
use std::cell::Cell;
use vhalla_dioxus_services_spike::Error;

#[derive(Clone, Copy)]
pub(crate) struct Ticket {
    reader: usize,
    generation: u64,
}
pub(crate) struct Generation(Cell<Option<u64>>);
impl Default for Generation {
    fn default() -> Self {
        Self(Cell::new(Some(0)))
    }
}
impl Generation {
    pub(crate) fn invalidate(&self) {
        self.0.set(self.0.get().and_then(|n| n.checked_add(1)));
    }
    pub(crate) fn issue(&self, reader: usize) -> Option<Ticket> {
        self.invalidate();
        self.0.get().map(|generation| Ticket { reader, generation })
    }
    pub(crate) fn apply<T>(
        &self,
        ticket: Option<Ticket>,
        current_reader: usize,
        action: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        if !ticket.is_some_and(|t| t.reader == current_reader && self.0.get() == Some(t.generation))
        {
            return Err(Error::Stale);
        }
        action()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switching_reader_invalidates_queued_action_even_when_switching_back() {
        let generation = Generation::default();
        let ticket = generation.issue(0);
        let calls = Cell::new(0);
        let action = || {
            calls.set(calls.get() + 1);
            Ok(())
        };
        assert_eq!(generation.apply(ticket, 0, action), Ok(()));
        assert_eq!(generation.apply(ticket, 1, action), Err(Error::Stale));
        generation.invalidate();
        assert_eq!(generation.apply(ticket, 0, action), Err(Error::Stale));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn a_new_render_rejects_the_old_handler_before_invoking_its_service() {
        let generation = Generation::default();
        let old = generation.issue(0);
        let current = generation.issue(0);
        assert_eq!(
            generation.apply(old, 0, || panic!("stale service called")),
            Err::<(), _>(Error::Stale)
        );
        assert_eq!(generation.apply(current, 0, || Ok(7)), Ok(7));
    }

    #[test]
    fn exhausted_generation_never_reuses_a_ticket() {
        let generation = Generation(Cell::new(Some(u64::MAX - 1)));
        let last = generation.issue(0);
        assert!(last.is_some());
        assert!(generation.issue(0).is_none());
        assert_eq!(
            generation.apply(last, 0, || panic!("exhausted service called")),
            Err::<(), _>(Error::Stale)
        );
        assert!(generation.issue(0).is_none());
    }
}
