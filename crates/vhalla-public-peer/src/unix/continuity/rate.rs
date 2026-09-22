//! Fixed process-local work credits, not fairness, Sybil resistance or throughput.
use super::*;
const WINDOW: Duration = Duration::from_secs(60);
const MAX_IPS: usize = 256;
#[derive(Clone, Copy, Default)]
pub(super) struct Cost {
    pub requests: u64,
    pub submitted: u64,
    pub stored: u64,
    // One ancestor credit includes the current six finalization traversals.
    pub prefix: u64,
    pub cleanup: u64,
}
const GLOBAL: Cost = Cost {
    requests: 120,
    submitted: 4096,
    stored: 16384,
    prefix: 16384,
    cleanup: 128,
};
const IP: Cost = Cost {
    requests: 30,
    submitted: 1024,
    stored: 4096,
    prefix: 4096,
    cleanup: 32,
};
impl Cost {
    fn add(self, other: Self, limit: Self) -> Option<Self> {
        fn field(a: u64, b: u64, limit: u64) -> Option<u64> {
            a.checked_add(b).filter(|n| *n <= limit)
        }
        Some(Self {
            requests: field(self.requests, other.requests, limit.requests)?,
            submitted: field(self.submitted, other.submitted, limit.submitted)?,
            stored: field(self.stored, other.stored, limit.stored)?,
            prefix: field(self.prefix, other.prefix, limit.prefix)?,
            cleanup: field(self.cleanup, other.cleanup, limit.cleanup)?,
        })
    }
}
struct Window {
    at: Instant,
    used: Cost,
}
pub(super) struct Rate {
    global: Window,
    ips: BTreeMap<IpAddr, Window>,
}
impl Rate {
    pub fn new() -> Self {
        Self {
            global: Window {
                at: Instant::now(),
                used: Cost::default(),
            },
            ips: BTreeMap::new(),
        }
    }
    pub fn charge(&mut self, ip: Option<IpAddr>, cost: Cost, now: Instant) -> bool {
        if now.saturating_duration_since(self.global.at) >= WINDOW {
            self.global = Window {
                at: now,
                used: Cost::default(),
            };
        }
        self.ips
            .retain(|_, value| now.saturating_duration_since(value.at) < WINDOW);
        let Some(global) = self.global.used.add(cost, GLOBAL) else {
            return false;
        };
        if let Some(ip) = ip {
            if !self.ips.contains_key(&ip) && self.ips.len() >= MAX_IPS {
                return false;
            }
            let used = self
                .ips
                .get(&ip)
                .map_or(Cost::default(), |value| value.used);
            let Some(next) = used.add(cost, IP) else {
                return false;
            };
            self.ips
                .entry(ip)
                .or_insert(Window {
                    at: now,
                    used: Cost::default(),
                })
                .used = next;
        }
        self.global.used = global;
        true
    }
}
pub(super) fn request_cost(kind: wire::Kind) -> Cost {
    let (submitted, stored) = match kind {
        wire::Kind::Stage { .. } => (32, 168), // quote68 + checked100
        wire::Kind::Commit {
            base,
            stage,
            terminal,
            ..
        } => (
            terminal.sequence() - stage.map_or(base, |s| s.tail()).sequence(),
            202,
        ), // upper body count; quote67 + checked134 + reply1
        wire::Kind::Status { .. } => (0, 36),
        wire::Kind::Feed { count, .. } => (0, u64::from(count) * 2 + 1),
        // Includes author_status36, then evidence reads2n+6, reply verification n.
        wire::Kind::Evidence { count, .. } => (0, u64::from(count) * 3 + 42),
    };
    Cost {
        requests: 1,
        submitted,
        stored,
        ..Cost::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuity_rate_dimensions_are_atomic_bounded_and_not_refunded() {
        let mut rate = Rate::new();
        let clock = Instant::now();
        let ip = "127.0.0.1".parse().unwrap();
        assert!(rate.charge(
            Some(ip),
            Cost {
                prefix: 4096,
                ..Cost::default()
            },
            clock
        ));
        assert!(!rate.charge(
            Some(ip),
            Cost {
                prefix: 1,
                requests: 1,
                ..Cost::default()
            },
            clock
        ));
        assert_eq!(rate.global.used.requests, 0);
        assert!(rate.charge(
            Some(ip),
            Cost {
                stored: 4096,
                ..Cost::default()
            },
            clock
        ));
        assert!(!rate.charge(
            Some(ip),
            Cost {
                stored: 1,
                ..Cost::default()
            },
            clock
        ));
        assert!(rate.charge(
            Some(ip),
            Cost {
                submitted: 1024,
                ..Cost::default()
            },
            clock
        ));
        assert!(!rate.charge(
            Some(ip),
            Cost {
                submitted: 1,
                ..Cost::default()
            },
            clock
        ));
        assert!(rate.charge(
            Some(ip),
            Cost {
                cleanup: 32,
                ..Cost::default()
            },
            clock
        ));
        assert!(!rate.charge(
            Some(ip),
            Cost {
                cleanup: 1,
                ..Cost::default()
            },
            clock
        ));
        assert!(rate.charge(
            None,
            Cost {
                cleanup: 96,
                ..Cost::default()
            },
            clock
        ));
        assert!(!rate.charge(
            None,
            Cost {
                cleanup: 1,
                ..Cost::default()
            },
            clock
        ));
        assert!(rate.charge(
            Some(ip),
            Cost {
                requests: 30,
                ..Cost::default()
            },
            clock
        ));
        assert!(!rate.charge(
            Some(ip),
            Cost {
                requests: 1,
                ..Cost::default()
            },
            clock
        ));
        assert!(rate.charge(
            Some(ip),
            Cost {
                requests: 1,
                ..Cost::default()
            },
            clock + WINDOW
        ));
    }
}
