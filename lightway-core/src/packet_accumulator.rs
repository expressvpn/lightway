use bytes::BytesMut;

/// Packet Accumulator's trait function's return type
pub type PacketAccumulatorResult<T> =
    std::result::Result<T, Box<dyn std::error::Error + Sync + Send>>;

/// Packet Accumulator trait
pub trait PacketAccumulation {
    /// Store one packet to the accumulator
    fn store(&mut self, data: &BytesMut) -> PacketAccumulatorResult<AccumulatorState>;

    /// Retrieve the accumulated packets
    fn get_accumulated_pkts(&mut self) -> PacketAccumulatorResult<Vec<BytesMut>>;

    /// For cleaning up any internal stale states
    fn cleanup_stale_states(&mut self);

    /// Get the encoding status (enabled/disabled)
    fn get_encoding_status(&self) -> bool;

    /// Set the encoding status
    fn set_encoding_status(&mut self, enabled: bool);
}

/// Indicates whether the accumulator is ready to be flushed or not
pub enum AccumulatorState {
    /// Ready to flush
    ReadyToFlush,

    /// Not yet ready to flush
    #[allow(dead_code)]
    Pending,

    /// Accumulator does not accept the packet
    /// The packet should be sent directly
    /// Returning the packet altogether
    #[allow(dead_code)]
    Skip,
}

/// Type for Packet Accumulator
pub type PacketAccumulatorType = Box<dyn PacketAccumulation + Send>;

/// Factory to build `PacketAccumulatorType`
/// This will be used to build a new instance of `PacketAccumulatorType` for every connection.
pub trait PacketAccumulatorFactory {
    /// Build a new instance of `PacketAccumulatorType`
    fn build(&self) -> PacketAccumulatorType;

    /// Returns the accumulator name for debugging purpose
    fn get_accumulator_name(&self) -> String;
}

/// Factory to build `PacketAccumulatorType`
pub type PacketAccumulatorFactoryType = Box<dyn PacketAccumulatorFactory + Send + Sync>;
