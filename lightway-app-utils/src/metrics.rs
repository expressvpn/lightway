use metrics::{Counter, counter};
use std::sync::LazyLock;

static METRIC_TUN_IOURING_TX_ERR: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_iouring_tx_err"));
static METRIC_TUN_IOURING_RX_ERR: LazyLock<Counter> =
    LazyLock::new(|| counter!("tun_iouring_rx_err"));

/// Count iouring TX entries which complete with an error
pub(crate) fn tun_iouring_tx_err() {
    METRIC_TUN_IOURING_TX_ERR.increment(1)
}

/// Count iouring RX entries which complete with an error
pub(crate) fn tun_iouring_rx_err() {
    METRIC_TUN_IOURING_RX_ERR.increment(1)
}
