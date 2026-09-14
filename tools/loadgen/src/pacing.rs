//! Shared rate pacing for every `loadgen` subcommand.
//!
//! Extracted from `syslog_udp` when the second and third subcommands landed:
//! the fractional-carry accumulator below fixes a real bug (see the
//! regression test) and copying it per-subcommand would copy the bug risk
//! with it.

/// Advances the rate-pacing accumulator by one tick and returns how many
/// records to send this tick. `carry` carries the fractional remainder across
/// ticks so low target rates (e.g. 0.1 records/tick) are honored exactly over
/// many ticks instead of being rounded away on any single tick.
pub fn tick_record_count(carry: &mut f64, records_per_tick_target: f64) -> u64 {
    *carry += records_per_tick_target;
    let count = carry.floor() as u64;
    *carry -= count as f64;
    count
}

/// The tick interval every subcommand paces on. Ticks faster than practical
/// per-record timer resolution allows, batching multiple sends per tick rather
/// than chasing unrealistic per-record timer precision.
pub const TICK: std::time::Duration = std::time::Duration::from_micros(1000);

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the bug fixed in 9c03a62: the old pacer computed
    /// `round(target_rate * 0.001)` once and either floored sub-1/tick rates to
    /// 0 forever, or clamped to a wrong minimum of 1. At target_rate=100
    /// (0.1/tick), the fractional accumulator must still deliver ~300 records
    /// over a simulated 3s run (3000 ticks) instead of 0 or 3000.
    #[test]
    fn tick_record_count_honors_low_sub_one_per_tick_rate() {
        let records_per_tick_target = 100.0_f64 * 0.001;
        let mut carry = 0.0_f64;
        let total: u64 = (0..3000)
            .map(|_| tick_record_count(&mut carry, records_per_tick_target))
            .sum();
        assert!(
            (299..=301).contains(&total),
            "expected ~300 records over 3000 ticks at 0.1/tick, got {total}"
        );
    }

    #[test]
    fn tick_record_count_handles_many_per_tick() {
        // target_rate=200_000 -> 200/tick, no fractional part to carry.
        let mut carry = 0.0_f64;
        assert_eq!(tick_record_count(&mut carry, 200.0), 200);
        assert_eq!(carry, 0.0);
    }
}
