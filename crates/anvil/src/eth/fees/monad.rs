//! Monad's base fee controller, section 3 of its transaction fee mechanism (TFM).
//!
//! Ports `compute_base_fee` from monad-bft's `monad-tfm` crate. Monad keeps the controller's
//! trend and moment in its consensus header, not in the Ethereum header.

use alloy_primitives::aliases::I512;
use serde::{Deserialize, Serialize};

/// Lowest base fee Monad accepts, 100 gwei.
pub const MONAD_MIN_BASE_FEE: u64 = 100_000_000_000;

/// Highest base fee Monad accepts, a million times [`MONAD_MIN_BASE_FEE`].
const MAX_BASE_FEE: u64 = 100_000_000_000_000_000;

/// Inverse of the largest step the base fee takes per block, `1 / 28`.
const MAX_STEP_SIZE_DENOM: u64 = 28;

/// Weight, in percent, the trend and moment keep from the parent block.
const BETA: u64 = 96;

/// Base fee controller state a Monad block carries in its consensus header.
///
/// Monad's genesis block carries zero for both.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonadBaseFeeState {
    /// Moving average of how far the block gas sat below its target.
    pub trend: i64,
    /// Moving average of the squared distance between the block gas and its target.
    pub moment: u64,
}

impl MonadBaseFeeState {
    /// Returns the base fee and controller state of the child of a block that carries `self`.
    ///
    /// Monad measures `gas_used` as the sum of the transaction gas limits. The arithmetic runs on
    /// 512-bit integers, so it matches Monad wherever Monad's 64-bit arithmetic holds, and
    /// saturates on the larger gas limits that anvil allows.
    pub fn next_block(self, gas_limit: u64, gas_used: u64, base_fee: u64) -> (u64, Self) {
        let gas_limit = int(gas_limit);
        let gas_used = int(gas_used).min(gas_limit);
        let trend = int(self.trend);
        let moment = int(self.moment);

        // The target is 80% of the gas limit.
        let target = gas_limit * int(8u64) / int(10u64);
        let delta = gas_used - target;

        // eta = max_step_size * target / (target + sqrt(moment - trend^2))
        // base_fee' = base_fee * e^(eta * delta / (gas_limit - target))
        let deviation = (moment - trend * trend).max(I512::ZERO).into_raw().root(2);
        let denominator =
            int(MAX_STEP_SIZE_DENOM) * (target + I512::from_raw(deviation)) * (gas_limit - target);
        let base_fee = if denominator.is_zero() {
            int(base_fee)
        } else {
            fake_exponential(int(base_fee), target * delta, denominator)
        };
        let base_fee = base_fee.clamp(int(MONAD_MIN_BASE_FEE), int(MAX_BASE_FEE));

        // trend' = beta * trend + (1 - beta) * (target - gas_used)
        let trend = (int(BETA) * trend - int(100 - BETA) * delta) / int(100u64);
        // moment' = beta * moment + (1 - beta) * (target - gas_used)^2
        let moment = (int(BETA) * moment + int(100 - BETA) * delta * delta) / int(100u64);

        let saturated_trend = if trend.is_negative() { i64::MIN } else { i64::MAX };
        let next = Self {
            trend: trend.try_into().unwrap_or(saturated_trend),
            moment: moment.try_into().unwrap_or(u64::MAX),
        };
        (base_fee.try_into().expect("base fee is clamped to u64"), next)
    }
}

/// Approximates `factor * e^(numerator / denominator)` with a Taylor series, as EIP-4844 does.
fn fake_exponential(factor: I512, numerator: I512, denominator: I512) -> I512 {
    let mut i = 1u64;
    let mut output = I512::ZERO;
    let mut accum = factor * denominator;
    while !accum.is_zero() {
        output += accum;
        accum = accum * numerator / (denominator * int(i));
        i += 1;
    }
    output / denominator
}

fn int(value: impl TryInto<I512>) -> I512 {
    value.try_into().unwrap_or_else(|_| unreachable!("64-bit values fit in 512 bits"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected values come from monad-bft's `monad_tfm::base_fee::compute_base_fee`.
    #[test]
    fn matches_monad_from_genesis() {
        let mut state = MonadBaseFeeState::default();
        let mut base_fee = MONAD_MIN_BASE_FEE;
        let mut blocks = Vec::new();
        for gas_used in [150_000_000, 150_000_000, 0, 120_000_000] {
            (base_fee, state) = state.next_block(150_000_000, gas_used, base_fee);
            blocks.push((base_fee, state.trend, state.moment));
        }
        assert_eq!(
            blocks,
            [
                (103_635_970_141, -1_200_000, 36_000_000_000_000),
                (107_225_150_420, -2_352_000, 70_560_000_000_000),
                (MONAD_MIN_BASE_FEE, 2_542_080, 643_737_600_000_000),
                (MONAD_MIN_BASE_FEE, 2_440_396, 617_988_096_000_000),
            ]
        );
    }

    #[test]
    fn matches_monad_with_accumulated_state() {
        let state = MonadBaseFeeState { trend: -5_000_000, moment: 900_000_000_000_000 };
        assert_eq!(
            state.next_block(150_000_000, 30_000_000, 1_000_000_000_000),
            (
                917_635_770_830,
                MonadBaseFeeState { trend: -1_200_000, moment: 1_188_000_000_000_000 }
            )
        );
    }

    #[test]
    fn saturates_on_inputs_monad_never_sees() {
        let state = MonadBaseFeeState::default();
        assert_eq!(state.next_block(u64::MAX, u64::MAX, u64::MAX).0, MAX_BASE_FEE);
        assert_eq!(state.next_block(u64::MAX, 0, 0).0, MONAD_MIN_BASE_FEE);
        assert_eq!(state.next_block(0, 0, 1), (MONAD_MIN_BASE_FEE, state));
    }
}
