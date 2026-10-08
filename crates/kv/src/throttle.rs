//! Backoff after wrong passphrases, so the control socket cannot be used to
//! guess the passphrase quickly.

use std::time::{Duration, Instant};

const FREE_ATTEMPTS: u32 = 5;
const MAX_DELAY: Duration = Duration::from_secs(300);

#[derive(Debug, Default)]
pub struct Throttle {
    failures: u32,
    blocked_until: Option<Instant>,
}

impl Throttle {
    /// `Err(wait)` while attempts are blocked.
    pub fn check(&self, now: Instant) -> Result<(), Duration> {
        match self.blocked_until {
            Some(until) if until > now => Err(until - now),
            _ => Ok(()),
        }
    }

    /// From the fifth consecutive failure on, each failure blocks further
    /// attempts for 1s, 2s, 4s and so on, up to 5 minutes.
    pub fn record_failure(&mut self, now: Instant) {
        self.failures += 1;
        if self.failures >= FREE_ATTEMPTS {
            let exponent = (self.failures - FREE_ATTEMPTS).min(16);
            let delay = Duration::from_secs(1 << exponent).min(MAX_DELAY);
            self.blocked_until = Some(now + delay);
        }
    }

    pub fn record_success(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fail(throttle: &mut Throttle, now: Instant, times: u32) {
        for _ in 0..times {
            throttle.record_failure(now);
        }
    }

    #[test]
    fn first_four_failures_are_free() {
        let now = Instant::now();
        let mut throttle = Throttle::default();
        fail(&mut throttle, now, 4);
        assert_eq!(throttle.check(now), Ok(()));
    }

    #[test]
    fn delay_doubles_from_the_fifth_failure() {
        let now = Instant::now();
        let mut throttle = Throttle::default();
        fail(&mut throttle, now, 5);
        assert_eq!(throttle.check(now), Err(Duration::from_secs(1)));
        assert_eq!(throttle.check(now + Duration::from_secs(1)), Ok(()));
        throttle.record_failure(now);
        assert_eq!(throttle.check(now), Err(Duration::from_secs(2)));
        throttle.record_failure(now);
        assert_eq!(throttle.check(now), Err(Duration::from_secs(4)));
    }

    #[test]
    fn delay_is_capped_at_five_minutes() {
        let now = Instant::now();
        let mut throttle = Throttle::default();
        fail(&mut throttle, now, 100);
        assert_eq!(throttle.check(now), Err(MAX_DELAY));
    }

    #[test]
    fn success_resets_the_count() {
        let now = Instant::now();
        let mut throttle = Throttle::default();
        fail(&mut throttle, now, 7);
        throttle.record_success();
        fail(&mut throttle, now, 4);
        assert_eq!(throttle.check(now), Ok(()));
    }
}
