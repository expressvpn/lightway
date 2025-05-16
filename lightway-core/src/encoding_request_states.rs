use crate::wire::EncodingRequest;

use std::time::Duration;

/// States of encoding requests
#[derive(Default)]
pub(crate) struct EncodingRequestStates {
    /// Counter of the encoding requests from the client.
    /// Note: the wrapping should rarely, if ever, happen.
    /// The counter is a u64 and it takes 2^64 requests to wrap it.
    /// If one request is made each nanosecond, it takes ~584 years to wrap.
    pub id_counter: u64,

    /// The latest encoding request packet that has yet to be acknowledged by the server
    /// If Some(_), the latest encoding request is not acknowledged yet.
    /// If None, the latest encoding request has been acknowledged, or
    /// the number of retransmissions have reached the maximum limit.
    /// Used by Client only.
    pub pending_request_pkt: Option<EncodingRequest>,

    /// Number of retransmissions done with the latest pending encoding request packet
    /// Used by Client only.
    pub retransmissions_counter: u8,
}

impl EncodingRequestStates {
    pub(crate) fn retransmit_wait_time(&self) -> Duration {
        const INITIAL_WAIT_TIME: Duration = Duration::from_millis(500);

        // To begin with, wait for INITIAL_WAIT_TIME.
        // Then, linearly increase the wait time with the number of retransmission attempted.
        INITIAL_WAIT_TIME * ((1 + self.retransmissions_counter) as u32)
    }
}
