//! Implementation of DPLPMTUD: Packetization Layer Path MTU Discovery for Datagram Transports.
//!
//! Described in <https://datatracker.ietf.org/doc/html/rfc8899>

use std::{sync::Arc, time::Duration};

use crate::{IPV4_HEADER_SIZE, MAX_DTLS_HEADER_SIZE, UDP_HEADER_SIZE, wire};

use more_asserts::*;

const MAX_PROBES: usize = 3;

/// The BASE_PLPMTU is a configured size expected to work for most paths
pub(crate) const BASE_PLPMTU: u16 = 1250;

/// Number of bytes to increase for the next probe
const PROBE_BIG_STEP: u16 = 32;

/// The minimal number of bytes to increase for the next probe
const PROBE_SMALL_STEP: u16 = 8;

/// Timeout for the PROBE_TIMER timer
const PROBE_TIME_TIMEOUT: Duration = Duration::from_secs(5);
/// Timeout for the PMTU_RAISE_TIMER timer. Also used a CONFIRMATION_TIMER.
const PMTU_RAISE_TIMER_TIMEOUT: Duration = Duration::from_secs(600);

/// Returns the required [`wire::Ping`] payload size needed to
/// construct a probe frame corresponding to the given PLPMTU.
///
/// plpmtu is the total size of PL payload and headers/overhead, as
/// shown in the RFC:
///
/// ```noformat
///    Any additional
///      headers         .--- MPS -----.
///             |        |             |
///             v        v             v
///      +------------------------------+
///      | IP | ** | PL | protocol data |
///      +------------------------------+
///
///                 <----- PLPMTU ----->
///      <---------- PMTU -------------->
/// ```
///
/// Therefore PL headers/overhead must be subtracted.
///
/// Note:
///
/// MPS: Maximum Packet Size (largest possible application data
///      block).
/// PLPMTU: The Packetization Layer PMTU (largest PL datagram)
/// PMTU: Path PMTU (minimum MTU of path)
///
/// Here the "Packetization Layer" is "Lightway" itself (not
/// including DTLS or lower layers)
fn probe_payload_size_for_plpmtu(plpmtu: u16) -> u16 {
    let overhead = std::mem::size_of::<wire::FrameKind>() + wire::Ping::WIRE_OVERHEAD;
    debug_assert_ge!(plpmtu, overhead as u16);
    plpmtu - (overhead as u16)
}

/// Manage a PMTUD timer.
pub trait Timer<AppState> {
    /// Start a timer for the duration `d` after which
    /// `crate::Connection::pmtud_tick` must be called.
    ///
    /// Any existing pending timer must be cancelled.
    fn start(&self, d: Duration, state: &mut AppState);

    /// Stop any existing timer.
    fn stop(&self, state: &mut AppState);
}

pub type TimerArg<AppState> = Arc<dyn Timer<AppState> + Sync + Send>;

#[derive(Debug, PartialEq, Copy, Clone)]
struct ProbeId(std::num::Wrapping<u16>);

impl ProbeId {
    fn new() -> Self {
        Self(std::num::Wrapping(1))
    }

    fn is_zero(&self) -> bool {
        self.0.0 == 0
    }

    fn as_u16(&self) -> u16 {
        self.0.0
    }
}

impl From<u16> for ProbeId {
    fn from(value: u16) -> Self {
        Self(std::num::Wrapping(value))
    }
}

impl std::ops::Add<u16> for ProbeId {
    type Output = Self;

    fn add(self, rhs: u16) -> Self {
        Self(self.0 + std::num::Wrapping(rhs))
    }
}

impl std::ops::AddAssign<u16> for ProbeId {
    fn add_assign(&mut self, rhs: u16) {
        self.0 += rhs
    }
}

impl std::ops::Sub<u16> for ProbeId {
    type Output = Self;

    fn sub(self, rhs: u16) -> Self {
        Self(self.0 - std::num::Wrapping(rhs))
    }
}

impl std::cmp::PartialEq<u16> for ProbeId {
    fn eq(&self, other: &u16) -> bool {
        &self.0.0 == other
    }
}

impl std::cmp::PartialEq<ProbeId> for u16 {
    fn eq(&self, other: &ProbeId) -> bool {
        other == self
    }
}

#[derive(Debug, PartialEq)]
struct PendingProbe {
    id: ProbeId,
    size: u16,
}

/// Return code indicating action to take
pub(crate) enum Action {
    /// Send a `Ping` of the given size with given id
    SendProbe {
        id: u16,
        size: u16,
    },
    None,
}

/// DPLPMTUD states as defined in the RFC.
enum State {
    Disabled,
    Base,
    Error,
    Searching,
    SearchComplete,
}

#[derive(Copy, Clone, Debug)]
enum StepSize {
    Small,
    Big,
}

/// DPLPMTUD manager
pub(crate) struct Dplpmtud<AppState> {
    /// The largest size of PLPMTU that DPLPMTUD will attempt to use. (`MAX_PLPMTU` in the RFC)
    max_plpmtu: u16,

    /// A size expected to work for most paths. (`BASE_PLPMTU` in the RFC)
    base_plpmtu: u16,

    /// Current state
    state: State,

    /// Timer. This covers both `PROBE_TIMER` and `PMTU_RAISE_TIMER`
    /// (since their use is mutually exclusive).
    timer: TimerArg<AppState>,

    /// Estimate of the largest size of a `wire::Data` frame (including
    /// protocol overhead and payload) which can be sent over the
    /// path.
    plpmtu: u16,

    probe_count: usize,
    next_probe_id: ProbeId,
    step_size: StepSize,

    pending_probe: Option<PendingProbe>,
}

impl<AppState> Dplpmtud<AppState> {
    pub(crate) fn new(base_plpmtu: u16, max_plpmtu: u16, timer: TimerArg<AppState>) -> Self {
        Self {
            max_plpmtu,
            base_plpmtu,
            state: State::Disabled,
            timer,
            plpmtu: base_plpmtu,
            probe_count: 0,
            next_probe_id: ProbeId::new(),
            step_size: StepSize::Big,
            pending_probe: None,
        }
    }

    /// Signal that lower layer connectivity has been established and begin PMTUD.
    pub(crate) fn online(&mut self, state: &mut AppState) -> Action {
        match self.state {
            State::Disabled => {
                tracing::debug!("Online, sending initial DPLPMTUD base probe");
                self.base_probe_start(state)
            }
            State::Base | State::Error | State::Searching | State::SearchComplete => Action::None,
        }
    }

    /// Signal that lower layer connectivity has been lost and return to disabled state.
    #[allow(dead_code)]
    pub(crate) fn offline(&mut self, state: &mut AppState) {
        self.end_probe(state);
        self.state = State::Disabled;
    }

    // Current best estimate of plpmtu
    fn current_plpmtu(&self) -> Option<usize> {
        match self.state {
            State::Searching | State::SearchComplete => Some(self.plpmtu as usize),
            _ => None,
        }
    }

    /// Maximum application data block (i.e. payload, not including
    /// protocol overhead frame) size for [`wire::Data`] and
    /// [`wire::DataFrag`] respectively.
    ///
    /// If the search is incomplete then no estimate is available and
    /// this function returns None
    pub(crate) fn maximum_packet_sizes(&self) -> Option<(usize, usize)> {
        self.current_plpmtu().map(|plpmtu| {
            (
                wire::Data::maximum_packet_size_for_plpmtu(plpmtu),
                wire::DataFrag::maximum_packet_size_for_plpmtu(plpmtu),
            )
        })
    }

    /// Current estimate of PMTU (includes all lower level overheads).
    ///
    /// If the search is incomplete then no estimate is available and
    /// this function returns None
    fn effective_pmtu(&self) -> Option<usize> {
        self.current_plpmtu()
            .map(|plpmtu| plpmtu + IPV4_HEADER_SIZE + UDP_HEADER_SIZE + MAX_DTLS_HEADER_SIZE)
    }

    fn next_probe_id(&mut self) -> ProbeId {
        let id = self.next_probe_id;
        self.next_probe_id += 1;

        // Avoid using id 0 since keepalives use that.
        if id.is_zero() {
            self.next_probe_id()
        } else {
            id
        }
    }

    fn end_probe(&mut self, state: &mut AppState) {
        self.pending_probe = None;
        self.probe_count = 0;
        self.timer.stop(state)
    }

    fn send_probe(&mut self, state: &mut AppState, size: u16) -> Action {
        let id = self.next_probe_id();
        self.probe_count += 1;
        self.pending_probe = Some(PendingProbe { id, size });
        self.timer.start(PROBE_TIME_TIMEOUT, state);
        Action::SendProbe {
            id: id.as_u16(),
            size: probe_payload_size_for_plpmtu(size),
        }
    }

    /// Transition to [`State::Base`] and begin base probes
    fn base_probe_start(&mut self, state: &mut AppState) -> Action {
        self.state = State::Base;
        self.probe_count = 0;
        self.send_probe(state, self.base_plpmtu)
    }

    /// Transition to [`State::Searching`] and begin search probes
    fn base_probe_confirmed(&mut self, state: &mut AppState, size: u16) -> Action {
        self.end_probe(state);
        self.plpmtu = size;
        self.search_start(state)
    }

    /// Handle base probe timeout
    fn base_probe_timeout(&mut self, state: &mut AppState) -> Action {
        if self.probe_count < MAX_PROBES {
            return self.send_probe(state, self.base_plpmtu);
        }
        self.error(state)
    }

    /// Either begin search phase, starting from the just confirmed
    /// BASE_PLPMTU with a big step or perform a RAISE by starting
    /// from current plpmtu
    fn search_start(&mut self, state: &mut AppState) -> Action {
        self.state = State::Searching;
        self.search_probe_start(state, StepSize::Big)
    }

    /// Search has converged, current self.plpmtu is the final value.
    fn search_complete(&mut self, state: &mut AppState) -> Action {
        self.end_probe(state);
        tracing::debug!(
            epmtu = self.effective_pmtu(),
            plpmtu = self.plpmtu,
            mps = self.maximum_packet_sizes().as_ref().map(|(mps, _)| mps),
            "PMTU discovery complete"
        );

        self.state = State::SearchComplete;
        // We have converged, set the raise timer to check for change
        self.timer.start(PMTU_RAISE_TIMER_TIMEOUT, state);
        Action::None
    }

    /// Start a new search probe using current step over current plpmtu
    fn search_probe_start(&mut self, state: &mut AppState, step_size: StepSize) -> Action {
        self.probe_count = 0;
        self.step_size = step_size;
        let step = match self.step_size {
            StepSize::Big => PROBE_BIG_STEP,
            StepSize::Small => PROBE_SMALL_STEP,
        };
        let next_plpmtu = std::cmp::min(self.plpmtu + step, self.max_plpmtu);
        tracing::info!(?next_plpmtu, plpmtu = ?self.plpmtu, ?step, "Starting new search");
        self.send_probe(state, next_plpmtu)
    }

    /// Transition to [`State::Searching`] and begin search probes
    fn search_probe_confirmed(&mut self, state: &mut AppState, size: u16) -> Action {
        self.plpmtu = size;

        if self.plpmtu < self.max_plpmtu {
            self.search_probe_start(state, self.step_size)
        } else {
            self.search_complete(state)
        }
    }

    /// Handle search probe timeout
    fn search_probe_timeout(&mut self, state: &mut AppState) -> Action {
        match self.pending_probe {
            Some(ref pending) if self.probe_count < MAX_PROBES => {
                self.send_probe(state, pending.size)
            }
            Some(ref pending)
                if self.probe_count == MAX_PROBES && matches!(self.step_size, StepSize::Big) =>
            {
                tracing::info!(
                    failed_size = pending.size,
                    "big step probe timeout, switch to small steps"
                );
                self.search_probe_start(state, StepSize::Small)
            }
            Some(_) => self.search_complete(state),
            None => self.error(state),
        }
    }

    /// Start a `CONFIRM` probe to validate current plpmtu
    fn search_complete_reconfirm(&mut self, state: &mut AppState) -> Action {
        self.send_probe(state, self.plpmtu)
    }

    /// Current plpmtu has been CONFIRMed, now RAISE by returning to `Search` state
    fn search_complete_probe_confirmed(&mut self, state: &mut AppState) -> Action {
        self.search_start(state)
    }

    /// Current plpmtu could not be CONFIRMed
    fn search_complete_probe_timeout(&mut self, state: &mut AppState) -> Action {
        match self.pending_probe {
            Some(ref pending) if self.probe_count < MAX_PROBES => {
                // Lost probe, retry
                self.send_probe(state, pending.size)
            }
            Some(_) => {
                // Black hole detected, return to `Base`
                self.base_probe_start(state)
            }
            None => {
                // CONFIRMATION_TIMER/PMTU_RAISE_TIMER expired, recheck MTU
                self.search_complete_reconfirm(state)
            }
        }
    }

    /// Transition to [`State::Error`]
    fn error(&mut self, state: &mut AppState) -> Action {
        self.end_probe(state);
        self.state = State::Error;

        // In error state keep trying the base until we find connectivity
        self.send_probe(state, self.base_plpmtu)
    }

    /// Handle probe timeout while in [`State::Error`]
    fn error_probe_timeout(&mut self, state: &mut AppState) -> Action {
        // In error state keep trying the base until we find connectivity
        self.send_probe(state, self.base_plpmtu)
    }

    /// Called, via `Connection::pmtud_tick`, in response to a call to a [`Timer::start`].
    pub(crate) fn tick(&mut self, state: &mut AppState) -> Action {
        match self.state {
            State::Disabled => Action::None,
            State::Base => {
                // PROBE_TIMER expired.
                //
                // self.pending_probe doesn't really matter here,
                // although it is expected to be Some.
                tracing::debug!(id = ?self.pending_probe, "DPLPMTUD Base probe timed out");
                self.base_probe_timeout(state)
            }
            State::Error => {
                // PROBE_TIMER expired.
                //
                // self.pending_probe doesn't really matter here,
                // although it is expected to be Some.
                tracing::debug!(id = ?self.pending_probe, "DPLPMTUD Error probe timed out");
                self.error_probe_timeout(state)
            }

            State::Searching => {
                // PROBE_TIMER expired.
                //
                // self.pending_probe doesn't really matter here,
                // although it is expected to be Some.
                tracing::debug!(id = ?self.pending_probe, "DPLPMTUD search probe timed out");
                self.search_probe_timeout(state)
            }
            State::SearchComplete => {
                tracing::debug!(id = ?self.pending_probe, "DPLPMTUD confirm probe timed out");
                self.search_complete_probe_timeout(state)
            }
        }
    }

    /// Called in response to receipt of a [`wire::Pong`] frame
    pub(crate) fn pong_received(&mut self, pong: &wire::Pong, state: &mut AppState) -> Action {
        // We never use id == 0, those are regular keepalive pings
        if pong.id == wire::Ping::KEEPALIVE_ID {
            return Action::None;
        }

        let id: ProbeId = pong.id.into();
        match self.state {
            State::Disabled => Action::None,
            State::Base | State::Error => {
                match self.pending_probe {
                    // Is this the reply we wanted
                    Some(ref expected) if id == expected.id => {
                        tracing::debug!(?id, "DPLPMTUD Base/Error probe succeeded");
                        self.base_probe_confirmed(state, expected.size)
                    }
                    // Not one we were expecting, ignore
                    None | Some(_) => {
                        tracing::debug!(id = pong.id, "DPLPMTUD unexpected pong received");
                        Action::None
                    }
                }
            }
            State::Searching => {
                match self.pending_probe {
                    // Is this the reply we wanted
                    Some(ref expected) if id == expected.id => {
                        tracing::debug!(?id, "DPLPMTUD search probe succeeded");
                        self.search_probe_confirmed(state, expected.size)
                    }
                    // Not one we were expecting, ignore
                    None | Some(_) => {
                        tracing::debug!(id = pong.id, "DPLPMTUD unexpected pong received");
                        Action::None
                    }
                }
            }
            State::SearchComplete => {
                match self.pending_probe {
                    // reply we wanted
                    Some(ref expected) if id == expected.id => {
                        tracing::debug!(?id, "DPLPMTUD CONFIRM probe succeeded");
                        self.search_complete_probe_confirmed(state)
                    }
                    // Not one we were expecting, ignore
                    None | Some(_) => {
                        tracing::debug!(id = pong.id, "DPLPMTUD unexpected pong received");
                        Action::None
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{MAX_OUTSIDE_MTU, max_dtls_mtu};

    use super::*;
    use std::sync::Mutex;
    use test_case::test_case;

    const TEST_MAX_PLPMTU: u16 = max_dtls_mtu(MAX_OUTSIDE_MTU) as u16;

    struct FakeTimer(Mutex<Option<Duration>>);

    impl FakeTimer {
        fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new(None)))
        }

        fn expect_pending(&self, expected: Duration) {
            let state = self.0.lock().unwrap();
            let pending = state.as_ref().unwrap();
            assert_eq!(pending, &expected)
        }

        fn expect_idle(&self) {
            assert!(self.0.lock().unwrap().is_none());
        }

        fn reset(&self) {
            *self.0.lock().unwrap() = None
        }
    }

    impl Timer<()> for FakeTimer {
        fn start(&self, d: Duration, _state: &mut ()) {
            *self.0.lock().unwrap() = Some(d)
        }

        fn stop(&self, _state: &mut ()) {
            self.reset()
        }
    }

    #[test]
    fn not_using_id_0() {
        let timer = FakeTimer::new();
        let mut pmtud = Dplpmtud::new(BASE_PLPMTU, TEST_MAX_PLPMTU, timer.clone());
        for id in (0..3 * u16::MAX as usize).map(|_| pmtud.next_probe_id()) {
            assert!(!id.is_zero());
        }
    }

    #[test_case(State::Base, 1250 => None)]
    #[test_case(State::Error, 1250 => None)]
    #[test_case(State::Searching, 1250 => Some((1315, 1247, 1240)))]
    #[test_case(State::SearchComplete, 1250 => Some((1315,  1247, 1240)))]
    fn test_effective_pmtu_and_maximum_packet_sizes(
        state: State,
        plpmtu: u16,
    ) -> Option<(usize, usize, usize)> {
        let timer = FakeTimer::new();
        let mut pmtud = Dplpmtud::new(BASE_PLPMTU, TEST_MAX_PLPMTU, timer.clone());

        pmtud.plpmtu = plpmtu;
        pmtud.state = state;

        let Some(epmtu) = pmtud.effective_pmtu() else {
            assert!(pmtud.maximum_packet_sizes().is_none());
            return None;
        };

        let (mps_data, mps_frag) = pmtud.maximum_packet_sizes().unwrap();
        Some((epmtu, mps_data, mps_frag))
    }

    #[test_case(1; "first attempt")]
    #[test_case(2; "second attempt")]
    #[test_case(3; "third attempt")]
    fn initial_base_probe_ok(n: u16) {
        let timer = FakeTimer::new();
        let mut pmtud = Dplpmtud::new(BASE_PLPMTU, TEST_MAX_PLPMTU, timer.clone());
        assert!(matches!(pmtud.state, State::Disabled));
        assert!(pmtud.pending_probe.is_none());
        assert!(pmtud.effective_pmtu().is_none());
        let base_id = pmtud.next_probe_id - 1;

        // online, 1st probe sent
        let expected_id = base_id + 1;
        let action = pmtud.online(&mut ());
        assert!(matches!(pmtud.state, State::Base));
        assert!(pmtud.effective_pmtu().is_none());
        assert_eq!(pmtud.probe_count, 1);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1250 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1250 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));

        // several attempts n-1 of which do not succeed (no `pong_received` here)
        for attempt in 2..=n {
            let expected_id = base_id + attempt;
            timer.reset();
            let action = pmtud.tick(&mut ());
            assert!(matches!(pmtud.state, State::Base));
            assert!(pmtud.effective_pmtu().is_none());
            assert_eq!(pmtud.probe_count, attempt as usize);
            assert!(
                matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1250 })
            );
            assert!(
                matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1250 - 1 - 4)
            );
            timer.expect_pending(Duration::from_secs(5));
        }

        // nth attempt succeeds
        timer.reset();
        let expected_id = base_id + n;
        let action = pmtud.pong_received(
            &wire::Pong {
                id: expected_id.as_u16(),
                payload: Default::default(),
            },
            &mut (),
        );
        let expected_id = base_id + n + 1;
        assert!(matches!(pmtud.state, State::Searching));
        assert!(pmtud.effective_pmtu().is_some());
        assert_eq!(pmtud.probe_count, 1);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1282 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1282 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));
    }

    #[test]
    fn initial_base_probe_delayed_then_ok() {
        let timer = FakeTimer::new();
        let mut pmtud = Dplpmtud::new(BASE_PLPMTU, TEST_MAX_PLPMTU, timer.clone());
        assert!(matches!(pmtud.state, State::Disabled));
        assert!(pmtud.pending_probe.is_none());
        assert!(pmtud.effective_pmtu().is_none());
        let base_id = pmtud.next_probe_id - 1;

        // online, 1st attempt sent
        let expected_id = base_id + 1;
        timer.reset();
        let action = pmtud.online(&mut ());
        assert!(matches!(pmtud.state, State::Base));
        assert_eq!(pmtud.probe_count, 1);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1250 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1250 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));

        // 2nd attempt
        let expected_id = base_id + 2;
        timer.reset();
        let action = pmtud.tick(&mut ());
        assert!(matches!(pmtud.state, State::Base));
        assert_eq!(pmtud.probe_count, 2);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1250 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1250 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));

        // 1st attempt completes, which is ignored since it is too late
        let completed_id = base_id + 1;
        // timer.reset(); -- not cancelling since pong_received should leave it pending.
        let action = pmtud.pong_received(
            &wire::Pong {
                id: completed_id.as_u16(),
                payload: Default::default(),
            },
            &mut (),
        );
        assert!(matches!(pmtud.state, State::Base));
        assert!(pmtud.effective_pmtu().is_none());
        assert_eq!(pmtud.probe_count, 2);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1250 })
        );
        assert!(matches!(action, Action::None));
        timer.expect_pending(Duration::from_secs(5));

        // 2nd attempt completes, which is accepted since it is the latest, search proper is started
        timer.reset();
        let action = pmtud.pong_received(
            &wire::Pong {
                id: expected_id.as_u16(),
                payload: Default::default(),
            },
            &mut (),
        );
        let expected_id = base_id + 3;
        assert!(matches!(pmtud.state, State::Searching));
        assert!(pmtud.effective_pmtu().is_some());
        assert_eq!(pmtud.probe_count, 1);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1282 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1282 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));
    }

    #[test]
    fn initial_base_probe_timeout() {
        let timer = FakeTimer::new();
        let mut pmtud = Dplpmtud::new(BASE_PLPMTU, TEST_MAX_PLPMTU, timer.clone());
        assert!(matches!(pmtud.state, State::Disabled));
        assert!(pmtud.pending_probe.is_none());
        let base_id = pmtud.next_probe_id - 1;

        // online, 1st attempt, no reply
        let expected_id = base_id + 1;
        timer.reset();
        let action = pmtud.online(&mut ());
        assert!(matches!(pmtud.state, State::Base));
        assert_eq!(pmtud.probe_count, expected_id.as_u16() as usize);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1250 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1250 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));

        // 2nd attempt, no reply
        let expected_id = base_id + 2;
        timer.reset();
        let action = pmtud.tick(&mut ());
        assert!(matches!(pmtud.state, State::Base));
        assert_eq!(pmtud.probe_count, expected_id.as_u16() as usize);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1250 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1250 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));

        // 3rd attempt, no reply
        let expected_id = base_id + 3;
        timer.reset();
        let action = pmtud.tick(&mut ());
        assert!(matches!(pmtud.state, State::Base));
        assert_eq!(pmtud.probe_count, expected_id.as_u16() as usize);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1250 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1250 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));

        // 4th attempt, transition to error
        let expected_id = base_id + 4;
        timer.reset();
        let action = pmtud.tick(&mut ());
        assert!(matches!(pmtud.state, State::Error));
        assert!(pmtud.effective_pmtu().is_none());
        assert_eq!(pmtud.probe_count, 1);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1250 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1250 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));

        // 5th attempt, still error
        let expected_id = base_id + 5;
        timer.reset();
        let action = pmtud.tick(&mut ());
        assert!(matches!(pmtud.state, State::Error));
        assert!(pmtud.effective_pmtu().is_none());
        assert_eq!(pmtud.probe_count, 2);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1250 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1250 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));
    }

    #[test]
    fn recover_from_error_state_on_probe_success() {
        let timer = FakeTimer::new();
        let mut pmtud = Dplpmtud::new(BASE_PLPMTU, TEST_MAX_PLPMTU, timer.clone());
        assert!(matches!(pmtud.state, State::Disabled));
        assert!(pmtud.pending_probe.is_none());
        let base_id = pmtud.next_probe_id - 1;

        // 3 missed probes => error state
        let _ = pmtud.online(&mut ()); // 1st probe sent
        let _ = pmtud.tick(&mut ()); // 2nd probe sent
        let _ = pmtud.tick(&mut ()); // 3rd probe sent
        let action = pmtud.tick(&mut ()); // 3rd timeout, enter error state
        assert!(matches!(pmtud.state, State::Error));
        assert!(pmtud.effective_pmtu().is_none());
        assert!(matches!(action, Action::SendProbe { .. }));
        assert!(pmtud.pending_probe.is_some());
        timer.expect_pending(Duration::from_secs(5));

        // the fourth probe succeeds and we move to searching
        timer.reset();
        let expected_id = base_id + 4;
        let action = pmtud.pong_received(
            &wire::Pong {
                id: expected_id.as_u16(),
                payload: Default::default(),
            },
            &mut (),
        );

        let expected_id = base_id + 5;
        assert!(matches!(pmtud.state, State::Searching));
        assert!(pmtud.effective_pmtu().is_some());
        assert_eq!(pmtud.probe_count, 1);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1282 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1282 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));
    }

    #[test]
    fn recover_from_error_state_on_delayed_success() {
        let timer = FakeTimer::new();
        let mut pmtud = Dplpmtud::new(BASE_PLPMTU, TEST_MAX_PLPMTU, timer.clone());
        assert!(matches!(pmtud.state, State::Disabled));
        assert!(pmtud.pending_probe.is_none());
        let base_id = pmtud.next_probe_id - 1;

        // 3 missed probes => error state
        let _ = pmtud.online(&mut ()); // 1st probe sent
        let _ = pmtud.tick(&mut ()); // 2nd probe sent
        let _ = pmtud.tick(&mut ()); // 3rd probe sent

        let _ = pmtud.tick(&mut ()); // 3rd timeout, enter error state, send 4th probe
        assert!(matches!(pmtud.state, State::Error));

        // the 4th probe also times out, 5th probe sent
        let expected_id = base_id + 5;
        let action = pmtud.tick(&mut ());
        assert!(matches!(pmtud.state, State::Error));
        assert!(pmtud.effective_pmtu().is_none());
        assert_eq!(pmtud.probe_count, 2);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1250 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1250 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));

        // 4th probe completes, which is ignored since it is too late
        let completed_id = base_id + 4;
        // timer.reset(); -- not cancelling since pong_received should leave it pending.
        let action = pmtud.pong_received(
            &wire::Pong {
                id: completed_id.as_u16(),
                payload: Default::default(),
            },
            &mut (),
        );
        assert!(matches!(pmtud.state, State::Error));
        assert!(pmtud.effective_pmtu().is_none());
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1250 })
        );
        assert!(matches!(action, Action::None));
        timer.expect_pending(Duration::from_secs(5));

        // 5th probe completes, which is accepted and search starts
        timer.reset();
        let action = pmtud.pong_received(
            &wire::Pong {
                id: expected_id.as_u16(),
                payload: Default::default(),
            },
            &mut (),
        );
        let expected_id = base_id + 6;
        assert!(matches!(pmtud.state, State::Searching));
        assert!(pmtud.effective_pmtu().is_some());
        assert_eq!(pmtud.probe_count, 1);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1282 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1282 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));
    }

    // Helper to construct a Dplpmtud in [`State::Searching`].
    //
    // Note that on return `timer` will have a pending timer for the
    // first search probe.
    fn start_search(timer: &Arc<FakeTimer>) -> (Action, Dplpmtud<()>) {
        let mut pmtud = Dplpmtud::new(BASE_PLPMTU, TEST_MAX_PLPMTU, timer.clone());

        // online, 1st base probe sent and succeeds
        pmtud.online(&mut ());
        let id = pmtud.pending_probe.as_ref().unwrap().id;
        let action = pmtud.pong_received(
            &wire::Pong {
                id: id.as_u16(),
                payload: Default::default(),
            },
            &mut (),
        );

        assert!(matches!(pmtud.state, State::Searching));
        (action, pmtud)
    }

    #[test_case(1; "first attempt")]
    #[test_case(2; "second attempt")]
    #[test_case(3; "third attempt")]
    fn search_probe_ok(n: u16) {
        let timer = FakeTimer::new();
        let (action, mut pmtud) = start_search(&timer);
        // id 1 was sent and acked (the base probe), id 2 is in flight
        // and so next_probe_id will id 3.
        //
        // subtract 1 for the base probe and another one so the
        // attempts and offsets line up below (since first probe is
        // really the zeroeth iteration).
        let base_id = pmtud.next_probe_id - 2;

        // 1st probe sent by start_search already
        let expected_id = base_id + 1;
        assert!(matches!(pmtud.state, State::Searching));
        assert!(pmtud.effective_pmtu().is_some());
        assert_eq!(pmtud.probe_count, 1);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1282 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1282 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));

        // several attempts n-1 of which do not succeed (no `pong_received` here)
        for attempt in 2..=n {
            let expected_id = base_id + attempt;
            timer.reset();
            let action = pmtud.tick(&mut ());
            assert!(matches!(pmtud.state, State::Searching));
            assert!(pmtud.effective_pmtu().is_some());
            assert_eq!(pmtud.probe_count, attempt as usize);
            assert!(
                matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1282 })
            );
            assert!(
                matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1282 - 1 - 4)
            );
            timer.expect_pending(Duration::from_secs(5));
        }

        // nth attempt succeeds
        timer.reset();
        let expected_id = base_id + n;
        let action = pmtud.pong_received(
            &wire::Pong {
                id: expected_id.as_u16(),
                payload: Default::default(),
            },
            &mut (),
        );
        let expected_id = base_id + n + 1;
        assert!(matches!(pmtud.state, State::Searching));
        assert!(pmtud.effective_pmtu().is_some());
        assert_eq!(pmtud.probe_count, 1);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1314 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1314 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));
    }

    #[test]
    fn search_probe_delayed_then_ok() {
        let timer = FakeTimer::new();
        let (action, mut pmtud) = start_search(&timer);
        // id 1 was sent and acked (the base probe), id 2 is in flight
        // and so next_probe_id will id 3.
        //
        // subtract 1 for the base probe and another one so the
        // attempts and offsets line up below (since first probe is
        // really the zeroeth iteration).
        let base_id = pmtud.next_probe_id - 2;

        // 1st probe sent by start_search already
        let expected_id = base_id + 1;
        assert!(matches!(pmtud.state, State::Searching));
        assert!(pmtud.effective_pmtu().is_some());
        assert_eq!(pmtud.probe_count, 1);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1282 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1282 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));

        // 2nd attempt
        let expected_id = base_id + 2;
        timer.reset();
        let action = pmtud.tick(&mut ());
        assert!(matches!(pmtud.state, State::Searching));
        assert!(pmtud.effective_pmtu().is_some());
        assert_eq!(pmtud.probe_count, 2);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1282 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1282 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));

        // 1st attempt completes, which is ignored since it is too late
        let completed_id = base_id + 1;
        // timer.reset(); -- not cancelling since pong_received should leave it pending.
        let action = pmtud.pong_received(
            &wire::Pong {
                id: completed_id.as_u16(),
                payload: Default::default(),
            },
            &mut (),
        );
        assert!(matches!(pmtud.state, State::Searching));
        assert!(pmtud.effective_pmtu().is_some());
        assert_eq!(pmtud.probe_count, 2);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1282 })
        );
        assert!(matches!(action, Action::None));
        timer.expect_pending(Duration::from_secs(5));

        // 2nd attempt completes, which is accepted since it is the latest, next search step started
        timer.reset();
        let action = pmtud.pong_received(
            &wire::Pong {
                id: expected_id.as_u16(),
                payload: Default::default(),
            },
            &mut (),
        );
        let expected_id = base_id + 3;
        assert!(matches!(pmtud.state, State::Searching));
        assert!(pmtud.effective_pmtu().is_some());
        assert_eq!(pmtud.probe_count, 1);
        assert!(
            matches!(pmtud.pending_probe, Some(ref pending) if pending == &PendingProbe{ id: expected_id, size: 1314 })
        );
        assert!(
            matches!(action, Action::SendProbe{id, size} if id == expected_id && size == 1314 - 1 - 4)
        );
        timer.expect_pending(Duration::from_secs(5));
    }

    #[test_case(1250 => 1250; "min")]
    #[test_case(1282 => 1282; "middle (exact multiple of big step)")]
    #[test_case(1284 => 1282; "middle (multiple of neither big nor small step)")]
    #[test_case(max_dtls_mtu(1500) as u16 => 1419; "max")]
    #[test_case(1500 => 1419; "max wire")]
    fn full_search(actual_plpmtu: u16) -> u16 {
        let timer = FakeTimer::new();
        let (mut action, mut pmtud) = start_search(&timer);

        let mut iterations = 0..;

        // Iterate until the search completes
        while !matches!(pmtud.state, State::SearchComplete | State::Error) {
            let pending = pmtud.pending_probe.as_ref().unwrap();

            matches!(action, Action::SendProbe{size, ..} if size == pending.size - 1 - 4);
            assert!(matches!(pmtud.state, State::Searching));
            assert!(pmtud.effective_pmtu().is_some());
            assert_le!(pmtud.probe_count, MAX_PROBES);
            timer.expect_pending(Duration::from_secs(5));

            timer.reset();

            action = if pending.size <= actual_plpmtu {
                pmtud.pong_received(
                    &wire::Pong {
                        id: pending.id.as_u16(),
                        payload: Default::default(),
                    },
                    &mut (),
                )
            } else {
                pmtud.tick(&mut ())
            };

            // BASE_PLPMTU (1250) .. 1500 is 250 bytes.
            //
            // 250 / PROBE_BIG_STEP = 7.8 and PROBE_BIG_STEP /
            // PROBE_SMALL_STEP = 4.
            //
            // Therefore we must converge in fewer than 7.8 + 4 = ~12
            // steps.
            assert_lt!(iterations.next().unwrap(), 12);
        }

        assert!(matches!(action, Action::None));
        assert!(matches!(pmtud.state, State::SearchComplete));
        assert!(pmtud.effective_pmtu().is_some());
        timer.expect_pending(Duration::from_secs(600));

        pmtud.plpmtu
    }

    // Helper to construct a Dplpmtud in [`State::SearchComplete`].
    //
    // Search with MTU 1250 + 32 = 1282 (timing out all probes except
    // the first) to shorten the initial search. It's important that
    // this != `BASE_PLPMTU` to properly exercise state transitions.
    //
    // Note that on return `timer` will have a pending timer for the
    // first RAISE probe.
    fn complete_search(timer: &Arc<FakeTimer>) -> (Action, Dplpmtud<()>) {
        let (_, mut pmtud) = start_search(timer);
        assert!(matches!(pmtud.state, State::Searching));

        // Complete the initial probe for 1282.
        let pending = pmtud.pending_probe.as_ref().unwrap();
        pmtud.pong_received(
            &wire::Pong {
                id: pending.id.as_u16(),
                payload: Default::default(),
            },
            &mut (),
        );
        assert_gt!(pmtud.plpmtu, pmtud.base_plpmtu);

        // Three more probes of big step timeout
        pmtud.tick(&mut ());
        pmtud.tick(&mut ());
        pmtud.tick(&mut ());

        assert!(matches!(pmtud.state, State::Searching));

        // Three more probes of small step also timeout
        pmtud.tick(&mut ());
        pmtud.tick(&mut ());
        let action = pmtud.tick(&mut ());

        // Search now complete with PMTU 1232 and PMTU_RAISE_TIMER pending
        assert!(matches!(pmtud.state, State::SearchComplete));
        assert_eq!(pmtud.plpmtu, 1282);
        timer.expect_pending(Duration::from_secs(600));

        (action, pmtud)
    }

    #[test_case(1282 => 1282; "no increase")]
    #[test_case(1314 => 1314; "middle (exact multiple of big step)")]
    #[test_case(1322 => 1322; "middle (exact multiple of small step)")]
    #[test_case(1324 => 1322; "middle (multiple of neither big nor small step)")]
    #[test_case(max_dtls_mtu(1500) as u16 => 1419; "max")]
    #[test_case(1500 => 1419; "max wire")]
    fn confirm_succeeds_then_raise(second_plpmtu: u16) -> u16 {
        let timer = FakeTimer::new();
        let (_, mut pmtud) = complete_search(&timer);

        // PMTU_RAISE_TIMER fires, CONFIRM is triggered
        let action = pmtud.tick(&mut ());
        assert!(matches!(action, Action::SendProbe{size, ..} if size == pmtud.plpmtu - 1 - 4));
        assert!(matches!(pmtud.state, State::SearchComplete));
        assert_eq!(pmtud.probe_count, 1);
        timer.expect_pending(Duration::from_secs(5));

        // Complete the CONFIRM probe succeeds, starting RAISE
        let pending = pmtud.pending_probe.as_ref().unwrap();
        let mut action = pmtud.pong_received(
            &wire::Pong {
                id: pending.id.as_u16(),
                payload: Default::default(),
            },
            &mut (),
        );

        let mut iterations = 0..;

        // Iterate until the search for new pmtu completes
        while !matches!(pmtud.state, State::SearchComplete | State::Error) {
            let pending = pmtud.pending_probe.as_ref().unwrap();

            assert!(matches!(action, Action::SendProbe{size, ..} if size == pending.size - 1 - 4));
            assert!(matches!(pmtud.state, State::Searching));
            assert_le!(pmtud.probe_count, MAX_PROBES);
            timer.expect_pending(Duration::from_secs(5));

            timer.reset();

            action = if pending.size <= second_plpmtu {
                pmtud.pong_received(
                    &wire::Pong {
                        id: pending.id.as_u16(),
                        payload: Default::default(),
                    },
                    &mut (),
                )
            } else {
                pmtud.tick(&mut ())
            };

            // BASE_PLPMTU (1250) .. 1500 is 250 bytes.
            //
            // 250 / PROBE_BIG_STEP = 7.8 and PROBE_BIG_STEP /
            // PROBE_SMALL_STEP = 4.
            //
            // Therefore we must converge in fewer than 7.8 + 4 = ~12
            // steps.
            assert_lt!(iterations.next().unwrap(), 12);
        }

        assert!(matches!(action, Action::None));
        assert!(matches!(pmtud.state, State::SearchComplete));
        timer.expect_pending(Duration::from_secs(600));

        pmtud.plpmtu
    }

    #[test]
    fn confirm_delayed_then_ok() {
        let timer = FakeTimer::new();
        let (_, mut pmtud) = complete_search(&timer);

        // PMTU_RAISE_TIMER fires, 1st CONFIRM probe is sent
        let action = pmtud.tick(&mut ());
        assert!(matches!(action, Action::SendProbe{size, ..} if size == pmtud.plpmtu - 1 - 4));
        assert!(matches!(pmtud.state, State::SearchComplete));
        assert_eq!(pmtud.probe_count, 1);
        timer.expect_pending(Duration::from_secs(5));

        let first_id = pmtud.pending_probe.as_ref().unwrap().id;

        // 1st CONFIRM probe fails, 2nd is sent
        let action = pmtud.tick(&mut ());
        assert!(matches!(action, Action::SendProbe{size, ..} if size == pmtud.plpmtu - 1 - 4));
        assert!(matches!(pmtud.state, State::SearchComplete));
        assert_eq!(pmtud.probe_count, 2);
        timer.expect_pending(Duration::from_secs(5));

        let second_id = pmtud.pending_probe.as_ref().unwrap().id;

        // 1st probe reply arrives, too late
        let action = pmtud.pong_received(
            &wire::Pong {
                id: first_id.as_u16(),
                payload: Default::default(),
            },
            &mut (),
        );
        assert!(matches!(action, Action::None));
        assert!(matches!(pmtud.state, State::SearchComplete));
        assert_eq!(pmtud.probe_count, 2);
        timer.expect_pending(Duration::from_secs(5));

        // 2nd probe reply arrives, RAISE
        let action = pmtud.pong_received(
            &wire::Pong {
                id: second_id.as_u16(),
                payload: Default::default(),
            },
            &mut (),
        );
        assert!(
            matches!(action, Action::SendProbe{size, ..} if dbg!(size) == pmtud.plpmtu + 32 - 1 - 4)
        );
        assert!(matches!(pmtud.state, State::Searching));
        assert_eq!(pmtud.probe_count, 1);
        timer.expect_pending(Duration::from_secs(5));
    }

    #[test]
    fn confirm_fails() {
        let timer = FakeTimer::new();
        let (_, mut pmtud) = complete_search(&timer);

        // PMTU_RAISE_TIMER fires, 1st CONFIRM is sent
        let action = pmtud.tick(&mut ());
        assert!(matches!(action, Action::SendProbe{size, ..} if size == pmtud.plpmtu - 1 - 4));
        assert!(matches!(pmtud.state, State::SearchComplete));
        assert_eq!(pmtud.probe_count, 1);
        timer.expect_pending(Duration::from_secs(5));

        // 1st CONFIRM probe fails, 2nd is sent
        let action = pmtud.tick(&mut ());
        assert!(matches!(action, Action::SendProbe{size, ..} if size == pmtud.plpmtu - 1 - 4));
        assert!(matches!(pmtud.state, State::SearchComplete));
        assert_eq!(pmtud.probe_count, 2);
        timer.expect_pending(Duration::from_secs(5));

        // 2nd CONFIRM probe fails, 3rd is sent
        let action = pmtud.tick(&mut ());
        assert!(matches!(action, Action::SendProbe{size, ..} if size == pmtud.plpmtu - 1 - 4));
        assert!(matches!(pmtud.state, State::SearchComplete));
        assert_eq!(pmtud.probe_count, 3);
        timer.expect_pending(Duration::from_secs(5));

        // 3rd and final CONFIRM probe fails, back to `Base`
        let action = pmtud.tick(&mut ());
        assert!(matches!(action, Action::SendProbe{size, ..} if size == 1250 - 1 - 4));
        assert!(matches!(pmtud.state, State::Base));
        assert_eq!(pmtud.probe_count, 1);
        timer.expect_pending(Duration::from_secs(5));
    }

    #[test]
    fn offline_from_offline() {
        let timer = FakeTimer::new();
        let mut pmtud = Dplpmtud::new(BASE_PLPMTU, TEST_MAX_PLPMTU, timer.clone());
        assert!(matches!(pmtud.state, State::Disabled));

        pmtud.offline(&mut ());
        assert!(matches!(pmtud.state, State::Disabled));
        assert!(pmtud.pending_probe.is_none());
        timer.expect_idle();
    }

    #[test]
    fn offline_from_online() {
        let timer = FakeTimer::new();
        let mut pmtud = Dplpmtud::new(BASE_PLPMTU, TEST_MAX_PLPMTU, timer.clone());
        assert!(matches!(pmtud.state, State::Disabled));

        // online
        let action = pmtud.online(&mut ());
        assert!(matches!(pmtud.state, State::Base));
        assert!(pmtud.pending_probe.is_some());
        assert!(matches!(action, Action::SendProbe { .. }));
        timer.expect_pending(Duration::from_secs(5));

        pmtud.offline(&mut ());
        assert!(matches!(pmtud.state, State::Disabled));
        assert!(pmtud.pending_probe.is_none());
        timer.expect_idle();
    }

    #[test]
    fn offline_from_error() {
        let timer = FakeTimer::new();
        let mut pmtud = Dplpmtud::new(BASE_PLPMTU, TEST_MAX_PLPMTU, timer.clone());
        assert!(matches!(pmtud.state, State::Disabled));

        // 3 missed probes => error state
        let _ = pmtud.online(&mut ());
        let _ = pmtud.tick(&mut ());
        let _ = pmtud.tick(&mut ());
        let action = pmtud.tick(&mut ());
        assert!(matches!(pmtud.state, State::Error));
        assert!(pmtud.pending_probe.is_some());
        assert!(matches!(action, Action::SendProbe { .. }));
        timer.expect_pending(Duration::from_secs(5));

        pmtud.offline(&mut ());
        assert!(matches!(pmtud.state, State::Disabled));
        assert!(pmtud.pending_probe.is_none());
        timer.expect_idle();
    }

    #[test]
    fn offline_from_searching() {
        let timer = FakeTimer::new();
        let (_, mut pmtud) = start_search(&timer);
        assert!(matches!(pmtud.state, State::Searching));

        pmtud.offline(&mut ());
        assert!(matches!(pmtud.state, State::Disabled));
        assert!(pmtud.pending_probe.is_none());
        timer.expect_idle();
    }

    #[test]
    fn offline_from_search_complete() {
        let timer = FakeTimer::new();
        let (_, mut pmtud) = start_search(&timer);
        assert!(matches!(pmtud.state, State::Searching));

        // Iterate until the search completes
        while !matches!(pmtud.state, State::SearchComplete | State::Error) {
            let pending = pmtud.pending_probe.as_ref().unwrap();

            pmtud.pong_received(
                &wire::Pong {
                    id: pending.id.as_u16(),
                    payload: Default::default(),
                },
                &mut (),
            );
        }

        assert!(matches!(pmtud.state, State::SearchComplete));
        timer.expect_pending(Duration::from_secs(600));

        pmtud.offline(&mut ());
        assert!(matches!(pmtud.state, State::Disabled));
        assert!(pmtud.pending_probe.is_none());
        timer.expect_idle();
    }
}
