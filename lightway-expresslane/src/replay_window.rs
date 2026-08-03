//! RFC-6479-style sliding replay window, indexed by absolute counter.
//!
//! Indexing rather than shifting matters: the steady-state path is in-order
//! arrival, and a shifting window rewrites every word of the bitmap on each
//! one. Here an in-order advance touches a single word.

pub(crate) struct ReplayWindow {
    /// Highest counter committed so far.
    high: u64,
    /// One bit per counter, indexed by `counter % WINDOW_SIZE`.
    bitmap: [u64; Self::NUM_BLOCKS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            high: 0,
            bitmap: [0; Self::NUM_BLOCKS],
        }
    }
}

impl ReplayWindow {
    const NUM_BLOCKS: usize = 128;
    /// Counters more than this far below the highest seen are rejected.
    pub(crate) const WINDOW_SIZE: u64 = (Self::NUM_BLOCKS as u64) * 64;

    fn index(counter: u64) -> (usize, u64) {
        let bit = counter % Self::WINDOW_SIZE;
        ((bit / 64) as usize, 1u64 << (bit % 64))
    }

    fn is_set(&self, counter: u64) -> bool {
        let (block, mask) = Self::index(counter);
        self.bitmap[block] & mask != 0
    }

    /// True when this counter would be rejected.
    ///
    /// Never mutates. Committing is reserved for [`Self::commit`], after the
    /// AEAD has authenticated the packet - otherwise a forged counter could
    /// advance the window and lock out real traffic.
    pub(crate) fn would_reject(&self, counter: u64) -> bool {
        if counter == 0 {
            return true;
        }
        if counter > self.high {
            return false;
        }
        if self.high - counter >= Self::WINDOW_SIZE {
            return true;
        }
        self.is_set(counter)
    }

    /// Record an authenticated counter. Returns false if it must be rejected.
    pub(crate) fn commit(&mut self, counter: u64) -> bool {
        if self.would_reject(counter) {
            return false;
        }

        if counter > self.high {
            if counter - self.high >= Self::WINDOW_SIZE {
                // The window has moved on entirely; nothing old can survive.
                self.bitmap = [0; Self::NUM_BLOCKS];
            } else {
                // Clear the slots the window slides across, so stale bits from
                // the previous lap cannot masquerade as already-seen.
                let clear_from = (self.high + 1).max(counter.saturating_sub(Self::WINDOW_SIZE - 1));
                for c in clear_from..counter {
                    let (block, mask) = Self::index(c);
                    self.bitmap[block] &= !mask;
                }
            }
            self.high = counter;
        }

        let (block, mask) = Self::index(counter);
        self.bitmap[block] |= mask;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accept(w: &mut ReplayWindow, c: u64) -> bool {
        !w.would_reject(c) && w.commit(c)
    }

    #[test]
    fn accepts_in_order() {
        let mut w = ReplayWindow::default();
        for c in 1..=10_000u64 {
            assert!(accept(&mut w, c), "rejected in-order counter {c}");
        }
    }

    #[test]
    fn rejects_exact_replay() {
        let mut w = ReplayWindow::default();
        assert!(accept(&mut w, 5));
        assert!(!accept(&mut w, 5));
    }

    #[test]
    fn accepts_out_of_order_within_window() {
        let mut w = ReplayWindow::default();
        assert!(accept(&mut w, 100));
        assert!(accept(&mut w, 98));
        assert!(accept(&mut w, 99));
        assert!(!accept(&mut w, 98));
    }

    #[test]
    fn rejects_below_window() {
        let mut w = ReplayWindow::default();
        assert!(accept(&mut w, ReplayWindow::WINDOW_SIZE + 10));
        assert!(!accept(&mut w, 1));
    }

    #[test]
    fn rejects_zero() {
        let mut w = ReplayWindow::default();
        assert!(!accept(&mut w, 0));
    }

    #[test]
    fn large_jump_clears_stale_bits() {
        let mut w = ReplayWindow::default();
        assert!(accept(&mut w, 1));
        assert!(accept(&mut w, 1_000_000));
        assert!(!accept(&mut w, 1), "1 is far below the window now");
        assert!(accept(&mut w, 1_000_000 - 1), "aliasing slot must be free");
    }

    #[test]
    fn would_reject_does_not_mutate() {
        let mut w = ReplayWindow::default();
        assert!(accept(&mut w, 7));
        assert!(w.would_reject(7));
        assert!(w.would_reject(7), "would_reject must be side-effect free");
    }

    /// The pre-extraction shifting implementation, frozen verbatim as a
    /// reference. Semantics must match exactly; only the cost changes.
    mod reference {
        pub struct Shifting {
            bitmap: [u64; 128],
            high: u64,
        }
        impl Default for Shifting {
            fn default() -> Self {
                Self {
                    bitmap: [0; 128],
                    high: 0,
                }
            }
        }
        impl Shifting {
            const WINDOW_SIZE: u64 = 128 * 64;
            fn set_bit(&mut self, position: u64) {
                self.bitmap[(position / 64) as usize] |= 1u64 << (position % 64);
            }
            fn test_bit(&self, position: u64) -> bool {
                self.bitmap[(position / 64) as usize] & (1u64 << (position % 64)) != 0
            }
            fn shift_left(&mut self, count: u64) {
                if count >= Self::WINDOW_SIZE {
                    self.bitmap = [0; 128];
                    return;
                }
                let block_shift = (count / 64) as usize;
                let bit_shift = (count % 64) as u32;
                if bit_shift == 0 {
                    for i in (block_shift..128).rev() {
                        self.bitmap[i] = self.bitmap[i - block_shift];
                    }
                } else {
                    for i in (0..128).rev() {
                        let lower = if i >= block_shift {
                            self.bitmap[i - block_shift] << bit_shift
                        } else {
                            0
                        };
                        let upper = if i > block_shift {
                            self.bitmap[i - block_shift - 1] >> (64 - bit_shift)
                        } else {
                            0
                        };
                        self.bitmap[i] = lower | upper;
                    }
                }
                for i in 0..block_shift.min(128) {
                    self.bitmap[i] = 0;
                }
            }
            pub fn accept(&mut self, counter: u64) -> bool {
                if counter == 0 {
                    return false;
                }
                if counter > self.high {
                    let diff = counter - self.high;
                    self.shift_left(diff);
                    self.high = counter;
                    self.set_bit(0);
                    return true;
                }
                let age = self.high - counter;
                if age >= Self::WINDOW_SIZE {
                    return false;
                }
                if self.test_bit(age) {
                    return false;
                }
                self.set_bit(age);
                true
            }
        }
    }

    /// Deterministic xorshift, so the test needs no rand dependency.
    fn next_rand(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    #[test]
    fn matches_the_shifting_reference() {
        for seed in 1..=5u64 {
            let mut rng = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let mut new = ReplayWindow::default();
            let mut old = reference::Shifting::default();
            let mut counter: u64 = 0;

            for step in 0..100_000u64 {
                let r = next_rand(&mut rng);
                let candidate = match r % 5 {
                    // in order
                    0 => {
                        counter += 1;
                        counter
                    }
                    // reordered, just behind the front
                    1 => counter.saturating_sub(r % 64).max(1),
                    // exact replay of the front
                    2 => counter.max(1),
                    // forward jump
                    3 => {
                        counter += 1 + (r % 5000);
                        counter
                    }
                    // far below the window
                    _ => counter
                        .saturating_sub(ReplayWindow::WINDOW_SIZE + (r % 100))
                        .max(1),
                };

                let got = !new.would_reject(candidate) && new.commit(candidate);
                let want = old.accept(candidate);
                assert_eq!(
                    got, want,
                    "seed {seed} step {step} counter {candidate}: new={got} old={want}"
                );
            }
        }
    }
}
