//! The work ledger: the thirteen-counter `Costs` and its `Meter`,
//! restated with checked arithmetic.
//!
//! The engine charges one unit at a time and stops at the first unit that
//! would reach the fuel bound or the activation window
//! (`sim.rs` `Meter::charge`). The batched restatement below adds exactly as
//! many units as that loop would and reports the same stop, with fuel taking
//! precedence over the activation window.

/// A checked-arithmetic failure. Unreachable within the static bounds; kept
/// explicit so no counter can wrap silently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arithmetic;

/// Why a charge stopped short.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// The run's total fuel is spent.
    Fuel,
    /// The current activation's window is spent.
    Activation,
}

/// A charge result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeterError {
    /// The charge stopped short.
    Stop(Stop),
    /// A counter would overflow.
    Arithmetic,
}

impl From<Arithmetic> for MeterError {
    fn from(_: Arithmetic) -> Self {
        Self::Arithmetic
    }
}

/// A chargeable category. `copying` and `construction` exist in the ledger
/// (they are part of the `Costs::total`) but nothing in v1 charges
/// them, so they have no category here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    /// Canonical input bytes.
    Loading,
    /// Tick and activation scheduling.
    Scheduling,
    /// Condition evaluations.
    Conditions,
    /// Sensor reads.
    Sensors,
    /// Memory slot reads.
    MemoryReads,
    /// Memory slot writes.
    MemoryWrites,
    /// Actions and event applications.
    Actions,
    /// Signal emission, expiry, delivery, and consumption.
    Messages,
    /// Physical transfers: moves, turns, pickups, drops, credits.
    Transfers,
    /// Modeled checking work.
    Checking,
    /// Beacon drains.
    Draining,
}

/// The thirteen cost counters of the v1 `Costs` model.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    /// Canonical input bytes.
    pub loading: u64,
    /// Scheduling.
    pub scheduling: u64,
    /// Conditions.
    pub conditions: u64,
    /// Sensors.
    pub sensors: u64,
    /// Memory reads.
    pub memory_reads: u64,
    /// Memory writes.
    pub memory_writes: u64,
    /// Actions.
    pub actions: u64,
    /// Messages.
    pub messages: u64,
    /// Transfers.
    pub transfers: u64,
    /// Checking.
    pub checking: u64,
    /// Draining.
    pub draining: u64,
    /// v3 copying; always zero in v1.
    pub copying: u64,
    /// v3 construction; always zero in v1.
    pub construction: u64,
}

impl Ledger {
    /// The checked sum of all thirteen counters (`Costs::total`).
    pub fn total(&self) -> Result<u64, Arithmetic> {
        [
            self.loading,
            self.scheduling,
            self.conditions,
            self.sensors,
            self.memory_reads,
            self.memory_writes,
            self.actions,
            self.messages,
            self.transfers,
            self.checking,
            self.draining,
            self.copying,
            self.construction,
        ]
        .iter()
        .try_fold(0u64, |sum, value| sum.checked_add(*value).ok_or(Arithmetic))
    }

    fn counter(&mut self, category: Category) -> &mut u64 {
        match category {
            Category::Loading => &mut self.loading,
            Category::Scheduling => &mut self.scheduling,
            Category::Conditions => &mut self.conditions,
            Category::Sensors => &mut self.sensors,
            Category::MemoryReads => &mut self.memory_reads,
            Category::MemoryWrites => &mut self.memory_writes,
            Category::Actions => &mut self.actions,
            Category::Messages => &mut self.messages,
            Category::Transfers => &mut self.transfers,
            Category::Checking => &mut self.checking,
            Category::Draining => &mut self.draining,
        }
    }
}

/// The fuel meter (`sim.rs` `Meter`).
#[derive(Clone, Debug)]
pub struct Meter {
    ledger: Ledger,
    fuel: u64,
    activation: Option<(u64, u32)>,
}

impl Meter {
    /// A meter with empty counters and a total fuel bound.
    pub const fn new(fuel: u64) -> Self {
        Self {
            ledger: Ledger {
                loading: 0,
                scheduling: 0,
                conditions: 0,
                sensors: 0,
                memory_reads: 0,
                memory_writes: 0,
                actions: 0,
                messages: 0,
                transfers: 0,
                checking: 0,
                draining: 0,
                copying: 0,
                construction: 0,
            },
            fuel,
            activation: None,
        }
    }
    /// The counters so far.
    pub const fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    /// The checked total.
    pub fn total(&self) -> Result<u64, Arithmetic> {
        self.ledger.total()
    }
    /// Charges up to `amount` units to a category, stopping where the
    /// unit-by-unit loop would stop. A zero amount never fails.
    pub fn charge(&mut self, category: Category, amount: u64) -> Result<(), MeterError> {
        let total = self.total()?;
        let fuel_room = self.fuel.saturating_sub(total);
        let activation_room = match self.activation {
            None => u64::MAX,
            Some((start, limit)) => {
                let spent = total.checked_sub(start).ok_or(Arithmetic)?;
                u64::from(limit).saturating_sub(spent)
            }
        };
        let allowed = amount.min(fuel_room).min(activation_room);
        let counter = self.ledger.counter(category);
        *counter = counter.checked_add(allowed).ok_or(Arithmetic)?;
        if allowed == amount {
            return Ok(());
        }
        let total = self.total()?;
        if total >= self.fuel {
            Err(MeterError::Stop(Stop::Fuel))
        } else {
            Err(MeterError::Stop(Stop::Activation))
        }
    }
    /// Opens an activation window of `limit` units above the current total.
    pub fn begin_activation(&mut self, limit: u32) -> Result<(), Arithmetic> {
        self.activation = Some((self.total()?, limit));
        Ok(())
    }
    /// Closes the activation window.
    pub fn end_activation(&mut self) {
        self.activation = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The unit-by-unit loop of `sim.rs`.
    fn reference(meter: &mut Meter, category: Category, amount: u64) -> Result<(), Stop> {
        for _ in 0..amount {
            let total = meter.total().unwrap();
            if total >= meter.fuel {
                return Err(Stop::Fuel);
            }
            if meter
                .activation
                .is_some_and(|(start, limit)| total - start >= u64::from(limit))
            {
                return Err(Stop::Activation);
            }
            *meter.ledger.counter(category) += 1;
        }
        Ok(())
    }

    #[test]
    fn batched_charge_matches_unit_loop() {
        let categories = [
            Category::Loading,
            Category::Checking,
            Category::Messages,
            Category::Transfers,
        ];
        for fuel in [0u64, 1, 5, 17, 40] {
            for limit in [1u32, 2, 3, 7] {
                for amounts in [[0u64, 3, 1, 4], [4, 4, 4, 4], [1, 0, 9, 2], [7, 1, 1, 1]] {
                    let mut batched = Meter::new(fuel);
                    let mut looped = Meter::new(fuel);
                    for (index, amount) in amounts.iter().enumerate() {
                        if index == 1 {
                            batched.begin_activation(limit).unwrap();
                            looped.begin_activation(limit).unwrap();
                        }
                        if index == 3 {
                            batched.end_activation();
                            looped.end_activation();
                        }
                        let expected = reference(&mut looped, categories[index], *amount);
                        let actual =
                            batched.charge(categories[index], *amount).map_err(
                                |error| match error {
                                    MeterError::Stop(stop) => stop,
                                    MeterError::Arithmetic => panic!("arithmetic"),
                                },
                            );
                        assert_eq!(actual, expected, "fuel {fuel} limit {limit} {amounts:?}");
                        assert_eq!(batched.ledger, looped.ledger);
                    }
                }
            }
        }
    }
}
