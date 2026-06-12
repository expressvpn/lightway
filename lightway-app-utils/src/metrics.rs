use metrics::{Counter, counter};
use std::sync::LazyLock;

#[cfg(feature = "io-uring")]
static METRIC_TUN_IOURING_RX_ERR: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_iouring_rx_err"));

#[cfg(target_os = "linux")]
static METRIC_TUN_RECV_GSO_SHORT_READ: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_recv_gso_short_read"));

/// Count iouring RX entries which complete with an error
#[cfg(feature = "io-uring")]
pub(crate) fn tun_iouring_rx_err() {
    METRIC_TUN_IOURING_RX_ERR.increment(1)
}

/// `Tun::recv_gso` returned a read shorter than a virtio header.
/// Treated as a no-op for the iteration; the kernel likely truncated.
#[cfg(target_os = "linux")]
pub(crate) fn tun_recv_gso_short_read() {
    METRIC_TUN_RECV_GSO_SHORT_READ.increment(1)
}
