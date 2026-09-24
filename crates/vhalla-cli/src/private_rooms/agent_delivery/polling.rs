//! Monotonic mailbox scheduling, separate from durable outbound retry policy.
use std::time::{Duration, Instant};

use serde::Deserialize;

const ADAPTIVE_BASE: Duration = Duration::from_secs(5);
const ADAPTIVE_MAX: Duration = Duration::from_secs(30);
const INTERACTIVE_IDLE: Duration = Duration::from_secs(5);
const INTERACTIVE_ACTIVE: Duration = Duration::from_secs(1);
const ACTIVITY_WINDOW: Duration = Duration::from_secs(30);
const ERROR_BASE: Duration = Duration::from_secs(1);
const ERROR_MAX: Duration = Duration::from_secs(30);

/// An explicit selection for a new delivery profile. Adaptive retains the
/// existing cadence; interactive spends more empty TLS exchanges to discover
/// arrivals sooner. Neither policy is a delivery-latency guarantee.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Policy {
    #[default]
    Adaptive,
    Interactive,
}

pub(super) struct Schedule {
    policy: Policy,
    next_poll: Instant,
    retry_not_before: Option<Instant>,
    idle: Duration,
    error: Duration,
    active_until: Option<Instant>,
}

impl Schedule {
    pub(super) fn new(policy: Policy, now: Instant) -> Self {
        Self {
            policy,
            next_poll: now,
            retry_not_before: None,
            idle: ADAPTIVE_BASE,
            error: ERROR_BASE,
            active_until: None,
        }
    }

    pub(super) fn due(&self, now: Instant) -> bool {
        now >= self.next_poll && self.retry_not_before.is_none_or(|retry| now >= retry)
    }

    /// Only newly observed or queued work opens a fast window. Local activity
    /// cannot wake another host or override a failed scan's retry deadline.
    pub(super) fn activity(&mut self, now: Instant) {
        if self.policy == Policy::Interactive {
            self.active_until = Some(now + ACTIVITY_WINDOW);
            self.next_poll = self.next_poll.min(now + INTERACTIVE_ACTIVE);
        }
    }

    pub(super) fn success(&mut self, now: Instant, has_work: bool) {
        self.retry_not_before = None;
        self.error = ERROR_BASE;
        if has_work {
            self.activity(now);
            self.idle = ADAPTIVE_BASE;
            // The enclosing driver still permits only one PAGE per bounded
            // tick. A retained backlog must not wait for an idle interval.
            self.next_poll = now;
        } else {
            let interval = match self.policy {
                Policy::Adaptive => {
                    self.idle = (self.idle * 2).min(ADAPTIVE_MAX);
                    self.idle
                }
                Policy::Interactive => {
                    if self.active_until.is_some_and(|until| now < until) {
                        INTERACTIVE_ACTIVE
                    } else {
                        INTERACTIVE_IDLE
                    }
                }
            };
            self.next_poll = now + interval;
        }
    }

    pub(super) fn network_error(&mut self, now: Instant) {
        let retry = now + self.error;
        self.retry_not_before = Some(retry);
        self.next_poll = retry;
        self.error = (self.error * 2).min(ERROR_MAX);
    }

    /// Exhausting this tick's scan budget is not a network failure or a
    /// successful exchange. Retry on a later driver tick without resetting the
    /// independent error sequence or extending the activity window.
    pub(super) fn budget_exhausted(&mut self, now: Instant) {
        self.next_poll = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_retains_quiet_cadence_and_backlog_catchup() {
        let mut now = Instant::now();
        let mut schedule = Schedule::new(Policy::Adaptive, now);
        assert!(schedule.due(now));
        for seconds in [10, 20, 30, 30] {
            schedule.success(now, false);
            schedule.activity(now);
            assert!(!schedule.due(now + Duration::from_secs(seconds - 1)));
            now += Duration::from_secs(seconds);
            assert!(schedule.due(now));
        }
        schedule.success(now, true);
        assert!(schedule.due(now));
        schedule.success(now, false);
        assert!(!schedule.due(now + Duration::from_secs(9)));
        assert!(schedule.due(now + Duration::from_secs(10)));
    }

    #[test]
    fn independent_receiver_discovers_every_quiet_arrival_phase_within_five_seconds() {
        // No local activity notification is sent to the receiver. Its only
        // input is empty successful scans until this independent arrival.
        for phase in 0..50 {
            let start = Instant::now();
            let mut schedule = Schedule::new(Policy::Interactive, start);
            let arrival = Duration::from_secs(90) + Duration::from_millis(phase * 100);
            let mut seen = None;
            let mut exchanges = 0;
            for step in 0..=1000 {
                let elapsed = Duration::from_millis(step * 100);
                if schedule.due(start + elapsed) {
                    exchanges += 1;
                    if elapsed >= arrival {
                        seen = Some(elapsed);
                        break;
                    }
                    schedule.success(start + elapsed, false);
                }
            }
            let latency = seen.unwrap() - arrival;
            assert!(latency <= Duration::from_secs(5));
            assert!(
                exchanges <= 20,
                "quiet polling exceeded its exchange budget"
            );
        }
    }

    #[test]
    fn activity_window_expires_without_network_activity_extending_it() {
        let start = Instant::now();
        let mut schedule = Schedule::new(Policy::Interactive, start);
        schedule.success(start, false);
        schedule.activity(start);
        assert!(!schedule.due(start + Duration::from_millis(999)));
        let mut exchanges = 0;
        for second in 1..=60 {
            let now = start + Duration::from_secs(second);
            if schedule.due(now) {
                exchanges += 1;
                schedule.success(now, false);
            }
        }
        // 1..=30 uses one exchange per second; after expiry, 35..=60
        // uses one per five seconds. Empty exchanges never renew the window.
        assert_eq!(exchanges, 36);
    }

    #[test]
    fn local_activity_and_tick_timeouts_cannot_bypass_error_backoff() {
        let mut now = Instant::now();
        let mut schedule = Schedule::new(Policy::Interactive, now);
        for seconds in [1, 2, 4, 8, 16, 30, 30] {
            schedule.network_error(now);
            schedule.activity(now);
            schedule.budget_exhausted(now);
            assert!(!schedule.due(now + Duration::from_secs(seconds) - Duration::from_nanos(1)));
            now += Duration::from_secs(seconds);
            assert!(schedule.due(now));
        }
        // Only an actual successful exchange restores the initial retry delay.
        schedule.success(now, false);
        schedule.network_error(now);
        assert!(!schedule.due(now));
        assert!(schedule.due(now + Duration::from_secs(1)));
    }

    #[test]
    fn long_descheduling_allows_one_exchange_not_a_catchup_burst() {
        let start = Instant::now();
        let mut schedule = Schedule::new(Policy::Interactive, start);
        schedule.activity(start);
        schedule.success(start, false);
        let resumed = start + Duration::from_secs(24 * 60 * 60);
        assert!(schedule.due(resumed));
        schedule.success(resumed, false);
        assert!(!schedule.due(resumed));
        assert!(!schedule.due(resumed + Duration::from_secs(4)));
        assert!(schedule.due(resumed + Duration::from_secs(5)));
    }

    #[test]
    fn scheduling_uses_only_injected_monotonic_time() {
        let earlier = Instant::now();
        let start = earlier + Duration::from_secs(3600);
        let mut schedule = Schedule::new(Policy::Interactive, start);
        schedule.success(start, false);
        // An older observation cannot make a pending scan due; advancing
        // wall-clock time is deliberately not an input to this policy.
        assert!(!schedule.due(earlier));
        assert!(!schedule.due(start + Duration::from_secs(4)));
        assert!(schedule.due(start + Duration::from_secs(5)));
    }
}
