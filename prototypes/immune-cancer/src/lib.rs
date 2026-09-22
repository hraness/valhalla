//! Bounded immune-system prototype for Valhalla realms.
//!
//! This models containment policy only. Reports are hints, never authority;
//! owner revocation is immediate, while community quarantine requires distinct
//! reporters and an evidence commitment. All queues and replication are bounded.

pub const MAX_AGENTS: usize = 256;
pub const MAX_REPORTS: usize = 1024;
pub const MAX_CHILDREN_PER_ROOT: u32 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Active,
    Quarantined,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Agent {
    pub id: u64,
    pub owner: u64,
    pub root: u64,
    pub status: Status,
    pub children: u32,
    pub failures: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    pub subject: u64,
    pub reporter: u64,
    pub evidence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Full,
    Unknown,
    Revoked,
    Quarantined,
    Duplicate,
    NotOwner,
    InvalidEvidence,
    CircuitOpen,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Realm {
    pub agents: Vec<Agent>,
    reports: Vec<Report>,
    pub report_threshold: usize,
    pub max_failures: u32,
    pub replication_budget: u32,
    pub kill_epoch: u64,
    pub circuit_open: bool,
}

impl Realm {
    pub fn new(report_threshold: usize, max_failures: u32, replication_budget: u32) -> Self {
        Self {
            agents: Vec::new(),
            reports: Vec::new(),
            report_threshold: report_threshold.max(1),
            max_failures: max_failures.max(1),
            replication_budget: replication_budget.min(MAX_CHILDREN_PER_ROOT),
            kill_epoch: 0,
            circuit_open: false,
        }
    }

    pub fn register(&mut self, id: u64, owner: u64) -> Result<(), Error> {
        if self.agents.len() >= MAX_AGENTS {
            return Err(Error::Full);
        }
        if self.agents.iter().any(|a| a.id == id) {
            return Err(Error::Duplicate);
        }
        self.agents.push(Agent {
            id,
            owner,
            root: id,
            status: Status::Active,
            children: 0,
            failures: 0,
        });
        Ok(())
    }

    pub fn spawn(&mut self, parent: u64, child: u64) -> Result<(), Error> {
        if self.circuit_open {
            return Err(Error::CircuitOpen);
        }
        let parent_index = self.find(parent)?;
        if self.agents[parent_index].status != Status::Active {
            return Err(Error::Revoked);
        }
        let root = self.agents[parent_index].root;
        let root_index = self.find(root)?;
        if self.agents[root_index].children >= self.replication_budget {
            self.circuit_open = true;
            return Err(Error::CircuitOpen);
        }
        if self.agents.iter().any(|a| a.id == child) {
            return Err(Error::Duplicate);
        }
        if self.agents.len() >= MAX_AGENTS {
            self.circuit_open = true;
            return Err(Error::Full);
        }
        self.agents[root_index].children += 1;
        self.agents.push(Agent {
            id: child,
            owner: self.agents[parent_index].owner,
            root,
            status: Status::Active,
            children: 0,
            failures: 0,
        });
        Ok(())
    }

    pub fn record_failure(&mut self, id: u64) -> Result<(), Error> {
        let i = self.find(id)?;
        if self.agents[i].status == Status::Revoked {
            return Err(Error::Revoked);
        }
        if self.agents[i].status == Status::Quarantined {
            return Err(Error::Quarantined);
        }
        self.agents[i].failures = self.agents[i].failures.saturating_add(1);
        if self.agents[i].failures >= self.max_failures {
            self.agents[i].status = Status::Quarantined;
        }
        Ok(())
    }

    pub fn report(&mut self, subject: u64, reporter: u64, evidence: u64) -> Result<Status, Error> {
        if evidence == 0 || subject == reporter {
            return Err(Error::InvalidEvidence);
        }
        let subject_i = self.find(subject)?;
        self.find(reporter)?;
        if self.reports.len() >= MAX_REPORTS {
            return Err(Error::Full);
        }
        if self
            .reports
            .iter()
            .any(|r| r.subject == subject && r.reporter == reporter)
        {
            return Err(Error::Duplicate);
        }
        self.reports.push(Report {
            subject,
            reporter,
            evidence,
        });
        let distinct_evidence = self
            .reports
            .iter()
            .filter(|r| r.subject == subject)
            .map(|r| r.evidence)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        if distinct_evidence >= self.report_threshold
            && self.agents[subject_i].status == Status::Active
        {
            self.agents[subject_i].status = Status::Quarantined;
        }
        Ok(self.agents[subject_i].status)
    }

    pub fn appeal(
        &mut self,
        subject: u64,
        owner: u64,
        recovery_evidence: u64,
    ) -> Result<(), Error> {
        let i = self.find(subject)?;
        if self.agents[i].owner != owner {
            return Err(Error::NotOwner);
        }
        if recovery_evidence == 0 {
            return Err(Error::InvalidEvidence);
        }
        if self.agents[i].status == Status::Revoked {
            return Err(Error::Revoked);
        }
        self.agents[i].status = Status::Active;
        self.reports.retain(|r| r.subject != subject);
        self.agents[i].failures = 0;
        Ok(())
    }

    pub fn owner_kill(&mut self, owner: u64) {
        for a in &mut self.agents {
            if a.owner == owner {
                a.status = Status::Revoked;
            }
        }
        self.kill_epoch = self.kill_epoch.wrapping_add(1);
    }
    pub fn clear_circuit(&mut self) {
        self.circuit_open = false;
    }
    pub fn status(&self, id: u64) -> Result<Status, Error> {
        Ok(self.agents[self.find(id)?].status)
    }
    fn find(&self, id: u64) -> Result<usize, Error> {
        self.agents
            .iter()
            .position(|a| a.id == id)
            .ok_or(Error::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn realm() -> Realm {
        let mut r = Realm::new(2, 3, 2);
        r.register(1, 10).unwrap();
        r.register(2, 20).unwrap();
        r
    }
    #[test]
    fn sybil_and_collusion_do_not_amplify_one_reporter() {
        let mut r = realm();
        r.register(3, 30).unwrap();
        r.register(4, 40).unwrap();
        assert_eq!(r.report(1, 2, 11).unwrap(), Status::Active);
        assert_eq!(r.report(1, 3, 11).unwrap(), Status::Active);
        assert_eq!(r.report(1, 4, 12).unwrap(), Status::Quarantined);
    }
    #[test]
    fn false_positive_can_be_appealed_by_owner() {
        let mut r = realm();
        r.register(3, 30).unwrap();
        r.report(1, 2, 9).unwrap();
        r.report(1, 3, 10).unwrap();
        assert_eq!(r.appeal(1, 10, 77), Ok(()));
        assert_eq!(r.status(1), Ok(Status::Active));
        assert_eq!(r.appeal(1, 20, 77), Err(Error::NotOwner));
    }
    #[test]
    fn runaway_replication_trips_circuit_breaker() {
        let mut r = realm();
        r.spawn(1, 4).unwrap();
        r.spawn(1, 5).unwrap();
        assert_eq!(r.spawn(1, 6), Err(Error::CircuitOpen));
        assert_eq!(r.spawn(1, 7), Err(Error::CircuitOpen));
        r.clear_circuit();
        assert_eq!(r.spawn(1, 6), Err(Error::CircuitOpen));
    }
    #[test]
    fn failure_quarantine_and_owner_kill_are_monotonic() {
        let mut r = realm();
        for _ in 0..3 {
            r.record_failure(1).unwrap();
        }
        assert_eq!(r.status(1), Ok(Status::Quarantined));
        assert_eq!(r.record_failure(1), Err(Error::Quarantined));
        r.owner_kill(10);
        assert_eq!(r.status(1), Ok(Status::Revoked));
        assert_eq!(r.appeal(1, 10, 1), Err(Error::Revoked));
    }
}
