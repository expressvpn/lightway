//! Client metrics.
//!
//! Naming and the `LazyLock<Counter>` registration style match
//! `lightway_core::metrics` and `lightway_app_utils::metrics`.
//!
//! These counters cover the Android raw TCP coalescer
//! (`io::inside::raw_gro`), which sheds load by design — a full TUN
//! write queue drops the coalesced run and reports success upstream so
//! the inner TCP flow drives recovery. That is deliberate, but it makes
//! the sheds invisible without explicit counters. Each shed records the
//! number of **segments** lost as well as the number of runs, because
//! one coalesced run can carry many segments: run counts alone
//! understate the impact.

// Gated at the `mod metrics;` declaration in `lib.rs` (android and
// host test builds), so no inner `#![cfg]` here — repeating it trips
// `duplicated_attributes`.

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
static METRIC_TUN_RAW_GRO_PROBE_FAILED: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_raw_gro_probe_failed"));
static METRIC_TUN_RAW_GRO_PERMANENT_FALLBACK: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_raw_gro_permanent_fallback"));
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

/// The Android raw-write capability probe failed (`IFF_VNET_HDR`
/// framing present, `TUNGETIFF` refused, or the oversized write did
/// not return the full count): TCP coalescing stays disabled for the
/// life of the device. At most once per tunnel.
pub(crate) fn tun_raw_gro_probe_failed() {
    METRIC_TUN_RAW_GRO_PROBE_FAILED.increment(1);
}

/// An oversized raw TUN write was rejected (`EMSGSIZE`, `EINVAL` or a
/// short write) after the probe had succeeded — the kernel changed
/// its mind, e.g. a GKI that bounded the tun write path. The client
/// permanently reverted to per-packet writes. At most once per tunnel;
/// any occurrence in the field is worth investigating.
pub(crate) fn tun_raw_gro_permanent_fallback() {
    METRIC_TUN_RAW_GRO_PERMANENT_FALLBACK.increment(1);
}

/// A segment of a re-split run (the no-loss fallback after a rejected
/// oversized write) could not be rebuilt or written and was dropped —
/// the inner TCP flow must retransmit it.
pub(crate) fn tun_raw_gro_resplit_segment_dropped() {
    METRIC_TUN_RAW_GRO_RESPLIT_SEGMENT_DROPPED.increment(1);
}
