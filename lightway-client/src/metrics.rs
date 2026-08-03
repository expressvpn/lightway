//! Client metrics.
//!
//! Naming and the `LazyLock<Counter>` registration style match
//! `lightway_core::metrics` and `lightway_app_utils::metrics`.
//!
//! The offload counters below exist because both offload paths shed load
//! by design — a full TUN write queue on receive, a full socket send
//! buffer on transmit — and both report success upstream so the inner
//! TCP flow drives recovery. That is deliberate, but it makes the sheds
//! invisible without explicit counters. Each shed records the number of
//! **segments** lost as well as the number of batches, because one
//! coalesced batch can carry ~48 segments: batch counts alone understate
//! the impact by more than an order of magnitude.

// Gated at the `mod metrics;` declaration in `lib.rs` (linux, android
// and host test builds), so no inner `#![cfg]` here — repeating it
// trips `duplicated_attributes`. Counters whose only call sites are
// narrower than that gate carry their own per-item `#[cfg]`.

use ::metrics::{Counter, counter};
use std::sync::LazyLock;

static METRIC_TUN_GRO_BATCH_DROPPED_WOULD_BLOCK: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_gro_batch_dropped_would_block"));
static METRIC_TUN_GRO_SEGMENTS_DROPPED_WOULD_BLOCK: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_gro_segments_dropped_would_block"));
static METRIC_TUN_GRO_BATCH_DROPPED_ERR: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_gro_batch_dropped_err"));
static METRIC_TUN_GRO_SEGMENTS_DROPPED_ERR: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_gro_segments_dropped_err"));

// The `UDP_SEGMENT` send path exists only on Linux.
#[cfg(linux)]
static METRIC_OUTSIDE_GSO_BATCH_SHED: LazyLock<Counter> =
    LazyLock::new(|| counter!("outside_gso_batch_shed"));
#[cfg(linux)]
static METRIC_OUTSIDE_GSO_SEGMENTS_SHED: LazyLock<Counter> =
    LazyLock::new(|| counter!("outside_gso_segments_shed"));

// The raw coalescer (`io::inside::raw_gro`) is compiled for Android
// and for host test builds.
#[cfg(any(android, test))]
static METRIC_TUN_RAW_GRO_PROBE_FAILED: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_raw_gro_probe_failed"));
#[cfg(any(android, test))]
static METRIC_TUN_RAW_GRO_PERMANENT_FALLBACK: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_raw_gro_permanent_fallback"));
#[cfg(any(android, test))]
static METRIC_TUN_RAW_GRO_RESPLIT_SEGMENT_DROPPED: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_raw_gro_resplit_segment_dropped"));

/// A coalesced superpacket was shed because the TUN write queue was
/// full. Load shedding, not a fault: sustained non-zero values mean
/// the inside device is the bottleneck, and the segment counter
/// gives the number of TCP segments actually lost.
pub(crate) fn tun_gro_batch_dropped_would_block(segments: u64) {
    METRIC_TUN_GRO_BATCH_DROPPED_WOULD_BLOCK.increment(1);
    METRIC_TUN_GRO_SEGMENTS_DROPPED_WOULD_BLOCK.increment(segments);
}

/// A coalesced superpacket was dropped because the TUN write
/// failed outright — a genuine device error, unlike the
/// would-block case above.
pub(crate) fn tun_gro_batch_dropped_err(segments: u64) {
    METRIC_TUN_GRO_BATCH_DROPPED_ERR.increment(1);
    METRIC_TUN_GRO_SEGMENTS_DROPPED_ERR.increment(segments);
}

/// A `sendmsg(UDP_SEGMENT)` batch failed with a transient error that
/// `Udp::map_send_result` deliberately swallows — `ENOBUFS`,
/// `ConnectionRefused`, `NetworkUnreachable`, `PermissionDenied` — and
/// was therefore reported upstream as fully sent.
///
/// Swallowing is intentional: reporting a short write would live-lock
/// TLS into resending the same record, and DTLS retransmits anyway. But
/// that contract was written for a single datagram, and here the whole
/// batch is discarded, so without this counter a saturated send path is
/// indistinguishable from a healthy one. `ENOBUFS` in particular is the
/// canonical signal that the socket cannot keep up, and large GSO
/// batches are what provoke it.
#[cfg(linux)]
pub(crate) fn outside_gso_batch_shed(segments: u64) {
    METRIC_OUTSIDE_GSO_BATCH_SHED.increment(1);
    METRIC_OUTSIDE_GSO_SEGMENTS_SHED.increment(segments);
}

/// The Android raw-write capability probe failed (`IFF_VNET_HDR`
/// framing present, `TUNGETIFF` refused, or the oversized write did
/// not return the full count): TCP coalescing stays disabled for the
/// life of the device. At most once per tunnel.
#[cfg(any(android, test))]
pub(crate) fn tun_raw_gro_probe_failed() {
    METRIC_TUN_RAW_GRO_PROBE_FAILED.increment(1);
}

/// An oversized raw TUN write was rejected (`EMSGSIZE`, `EINVAL` or a
/// short write) after the probe had succeeded — the kernel changed
/// its mind, e.g. a GKI that bounded the tun write path. The client
/// permanently reverted to per-packet writes. At most once per tunnel;
/// any occurrence in the field is worth investigating.
#[cfg(any(android, test))]
pub(crate) fn tun_raw_gro_permanent_fallback() {
    METRIC_TUN_RAW_GRO_PERMANENT_FALLBACK.increment(1);
}

/// A segment of a re-split run (the no-loss fallback after a rejected
/// oversized write) could not be rebuilt or written and was dropped —
/// the inner TCP flow must retransmit it.
#[cfg(any(android, test))]
pub(crate) fn tun_raw_gro_resplit_segment_dropped() {
    METRIC_TUN_RAW_GRO_RESPLIT_SEGMENT_DROPPED.increment(1);
}
