//! Network path change monitor backed by Apple's Network framework.
//!
//! Wraps `NWPathMonitor`, which fires once at start with the current path and
//! then again on every change. Each satisfied callback after the initial one
//! pokes a trailing-edge debouncer; once the burst has been quiet for
//! [`DEBOUNCE`] the debouncer forwards a single `()` event on the supplied
//! `mpsc::Sender`, which the rest of the client treats as a generic "host
//! network changed" signal.
//!
//! Mirrors the iOS tunnel's `TRNetworkIdMonitor` debounce layer: the
//! framework emits multiple settled callbacks while the routing table catches
//! up after a Wi-Fi flap, and reconnecting against each one churns the
//! connected UDP socket. Coalescing them gives `sock.connect()` a single
//! re-bind against the *final* path.

use std::cell::Cell;
use std::ptr::NonNull;
use std::time::Duration;

use block2::RcBlock;
use dispatch2::{DispatchQoS, DispatchQueue, DispatchRetained, GlobalQueueIdentifier};
use objc2_network::{NWPath, NWPathMonitor, NWRetained, nw_interface_type_t, nw_path_status_t};
use tokio::sync::mpsc;
use tracing::{debug, trace};

/// Quiet period required after the last satisfied `NWPath` callback before
/// the debouncer forwards a network-change event downstream. Trailing-edge —
/// each event inside the window resets the timer, so the notification fires
/// only after the framework has stopped emitting updates.
const DEBOUNCE: Duration = Duration::from_millis(200);

/// Live `NWPathMonitor` plus its debouncing task.
///
/// Cancelling (via `Drop`) stops further framework callbacks and tears down
/// the debounce task. The block captured by the framework only holds an
/// internal `mpsc::Sender` and `Cell` state, so dropping the monitor releases
/// everything once the framework releases its block.
pub struct NetworkChangeMonitor {
    monitor: NWRetained<NWPathMonitor>,
    // Hold the queue alive for as long as the monitor is using it.
    _queue: DispatchRetained<DispatchQueue>,
    _debounce_task: tokio::task::JoinHandle<()>,
}

// SAFETY: `NWPathMonitor` is thread-safe in the sense that all callbacks are
// serialised onto the dispatch queue we install. We only manipulate the
// monitor handle from the owning thread (start in `new`, cancel in `Drop`).
#[allow(unsafe_code)]
// SAFETY: see above.
unsafe impl Send for NetworkChangeMonitor {}
#[allow(unsafe_code)]
// SAFETY: see above.
unsafe impl Sync for NetworkChangeMonitor {}

impl NetworkChangeMonitor {
    /// Start an `NWPathMonitor` that forwards debounced path-change events to
    /// `tx`.
    pub fn new(network_change_tx: mpsc::Sender<()>) -> Self {
        let monitor = NWPathMonitor::new();
        let queue = DispatchQueue::global_queue(GlobalQueueIdentifier::QualityOfService(
            DispatchQoS::UserInteractive,
        ));

        let (internal_tx, internal_rx) = mpsc::channel::<()>(1);
        let debounce_task = tokio::spawn(debounce(internal_rx, network_change_tx, DEBOUNCE));

        // Skip the first callback: `NWPathMonitor` fires it at `start()` with
        // the *current* path — i.e. the network we just established the VPN
        // on. Everything afterwards is a real path change.
        let initial_callback_seen = Cell::new(false);
        let handler = RcBlock::new(move |path: NonNull<NWPath>| {
            // SAFETY: NWPathMonitor passes a non-null NWPath that stays valid
            // for the duration of this callback (framework retains it across
            // the call).
            #[allow(unsafe_code)]
            let path: &NWPath = unsafe { path.as_ref() };

            let status = path.status();
            debug!(
                ?status,
                has_ipv4 = path.has_ipv4(),
                has_ipv6 = path.has_ipv6(),
                is_expensive = path.is_expensive(),
                is_constrained = path.is_constrained(),
                uses_wifi = path.uses_interface_type(nw_interface_type_t::wifi),
                uses_cellular = path.uses_interface_type(nw_interface_type_t::cellular),
                uses_wired = path.uses_interface_type(nw_interface_type_t::wired),
                "NWPath update",
            );

            // Only react when there is actually a usable path. `unsatisfied`
            // / `satisfiable` / `invalid` would just make `sock.connect()`
            // fail immediately, and the keepalive task already handles the
            // offline case via its existing timeouts.
            if status != nw_path_status_t::satisfied {
                return;
            }

            if !initial_callback_seen.replace(true) {
                tracing::debug!("skipping initial NWPath callback");
                return;
            }

            // Poke the debounce task. It will forward a single `()`
            // downstream `DEBOUNCE` after the *last* event in this burst.
            if let Err(e) = internal_tx.try_send(()) {
                tracing::trace!("debounce signal coalesced: {e}");
            }
        });
        monitor.set_update_handler(&handler);

        #[allow(unsafe_code)]
        // SAFETY: `queue` is a global concurrent dispatch queue with no
        // additional threading requirements, which is exactly what
        // `nw_path_monitor_set_queue` expects.
        unsafe {
            monitor.set_queue(&queue);
        }
        monitor.start();

        tracing::info!("Started macOS NWPathMonitor for network change events");

        Self {
            monitor,
            _queue: queue,
            _debounce_task: debounce_task,
        }
    }
}

/// Trailing-edge debounce: absorb a burst of network-change signals from the
/// path monitor and emit a single `()` once the burst has been quiet for
/// `quiet_period`. Each event arriving inside the window resets the timer.
async fn debounce(mut rx: mpsc::Receiver<()>, tx: mpsc::Sender<()>, quiet_period: Duration) {
    loop {
        // Wait for the first event of a new burst.
        if rx.recv().await.is_none() {
            return;
        }
        // Absorb further events; reset the timer on each one. Exits when the
        // channel has been quiet for `quiet_period`.
        loop {
            tokio::select! {
                e = rx.recv() => {
                    if e.is_none() {
                        return;
                    }
                    trace!("Absorbing one extra signal");
                }
                _ = tokio::time::sleep(quiet_period) => break,
            }
        }
        trace!("Passed quiet period, forwarding signal");
        // `try_send` matches the original behaviour: if the consumer is still
        // working through the previous change, dropping this one is fine —
        // they'll re-`connect`/keepalive against the latest state anyway.
        if let Err(e) = tx.try_send(()) {
            debug!("NWPathMonitor: dropped network change event: {e}");
        }
    }
}

impl Drop for NetworkChangeMonitor {
    fn drop(&mut self) {
        self.monitor.cancel();
        self._debounce_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::advance;

    fn rig() -> (
        mpsc::Sender<()>,
        mpsc::Receiver<()>,
        mpsc::Sender<()>,
        mpsc::Receiver<()>,
    ) {
        // Input capacity large enough that the test never blocks on `send`;
        // output capacity 1 mirrors how `NetworkChangeMonitor` uses it.
        let (in_tx, in_rx) = mpsc::channel::<()>(8);
        let (out_tx, out_rx) = mpsc::channel::<()>(1);
        (in_tx, in_rx, out_tx, out_rx)
    }

    #[tokio::test(start_paused = true)]
    async fn forwards_single_event_after_quiet_period() {
        let (in_tx, in_rx, out_tx, mut out_rx) = rig();
        let handle = tokio::spawn(debounce(in_rx, out_tx, DEBOUNCE));

        in_tx.send(()).await.unwrap();

        advance(DEBOUNCE - Duration::from_millis(1)).await;
        assert!(
            out_rx.try_recv().is_err(),
            "must not forward before quiet period elapses",
        );

        advance(Duration::from_millis(2)).await;
        assert_eq!(out_rx.recv().await, Some(()));

        drop(in_tx);
        handle.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn coalesces_burst_into_single_forward() {
        let (in_tx, in_rx, out_tx, mut out_rx) = rig();
        let handle = tokio::spawn(debounce(in_rx, out_tx, DEBOUNCE));

        // Five events spaced inside the quiet window.
        for _ in 0..5 {
            in_tx.send(()).await.unwrap();
            advance(Duration::from_millis(50)).await;
        }

        // Drain the post-burst quiet period.
        advance(DEBOUNCE).await;

        assert_eq!(out_rx.recv().await, Some(()));
        assert!(
            out_rx.try_recv().is_err(),
            "burst must collapse to exactly one event",
        );

        drop(in_tx);
        handle.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn event_inside_window_resets_timer() {
        let (in_tx, in_rx, out_tx, mut out_rx) = rig();
        let handle = tokio::spawn(debounce(in_rx, out_tx, DEBOUNCE));

        in_tx.send(()).await.unwrap();
        advance(DEBOUNCE - Duration::from_millis(1)).await;
        assert!(out_rx.try_recv().is_err());

        // Second event arrives 1ms before the original timer would have fired —
        // the quiet timer must restart from here, not from the first event.
        in_tx.send(()).await.unwrap();
        advance(DEBOUNCE - Duration::from_millis(1)).await;
        assert!(
            out_rx.try_recv().is_err(),
            "second event must reset the quiet timer",
        );

        advance(Duration::from_millis(2)).await;
        assert_eq!(out_rx.recv().await, Some(()));

        drop(in_tx);
        handle.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn separate_bursts_each_forward() {
        let (in_tx, in_rx, out_tx, mut out_rx) = rig();
        let handle = tokio::spawn(debounce(in_rx, out_tx, DEBOUNCE));

        in_tx.send(()).await.unwrap();
        advance(DEBOUNCE * 2).await;
        assert_eq!(out_rx.recv().await, Some(()));

        in_tx.send(()).await.unwrap();
        advance(DEBOUNCE * 2).await;
        assert_eq!(out_rx.recv().await, Some(()));

        drop(in_tx);
        handle.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn drops_event_when_downstream_full_but_keeps_running() {
        let (in_tx, in_rx, out_tx, mut out_rx) = rig();
        let handle = tokio::spawn(debounce(in_rx, out_tx, DEBOUNCE));

        // First burst fills the (capacity-1) downstream channel.
        in_tx.send(()).await.unwrap();
        advance(DEBOUNCE * 2).await;

        // Second burst — downstream is still full, so `try_send` drops it.
        in_tx.send(()).await.unwrap();
        advance(DEBOUNCE * 2).await;

        // Exactly one event was ever forwarded.
        assert_eq!(out_rx.recv().await, Some(()));
        assert!(out_rx.try_recv().is_err());

        // Third burst, downstream now drained — proves the task survived the
        // failed `try_send`.
        in_tx.send(()).await.unwrap();
        advance(DEBOUNCE * 2).await;
        assert_eq!(out_rx.recv().await, Some(()));

        drop(in_tx);
        handle.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn exits_when_input_closed_while_idle() {
        let (in_tx, in_rx, out_tx, _out_rx) = rig();
        let handle = tokio::spawn(debounce(in_rx, out_tx, DEBOUNCE));

        drop(in_tx);
        handle.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn exits_when_input_closed_during_absorb() {
        let (in_tx, in_rx, out_tx, mut out_rx) = rig();
        let handle = tokio::spawn(debounce(in_rx, out_tx, DEBOUNCE));

        // Get the task into the inner absorb loop, then close the channel
        // before the quiet period elapses.
        in_tx.send(()).await.unwrap();
        advance(Duration::from_millis(10)).await;
        drop(in_tx);
        handle.await.unwrap();

        assert!(
            out_rx.try_recv().is_err(),
            "in-flight burst must not be forwarded once input closes",
        );
    }
}
