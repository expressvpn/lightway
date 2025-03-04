use anyhow::Result;
use bytes::BytesMut;

/// Packet Accumulator trait
pub trait PacketAccumulation {
    /// Store one packet to the accumulator
    fn store(&mut self, data: BytesMut) -> Result<AccumulatorState>;

    /// Retrieve the accumulated packets
    fn get_accumulated_pkts(&mut self) -> Result<Vec<BytesMut>>;

    /// For cleaning up any internal stale states
    fn cleanup_stale_states(&mut self);
}

struct NoOpPacketAccumulator {
    pkts: Vec<BytesMut>,
}

/// Indicates whether the accumulator is ready to be flushed or not
pub enum AccumulatorState {
    /// Ready to flush
    ReadyToFlush,

    /// Not yet ready to flush
    #[allow(dead_code)]
    Pending,
}

impl NoOpPacketAccumulator {
    pub fn new() -> Self {
        NoOpPacketAccumulator {
            pkts: Vec::with_capacity(1),
        }
    }
}

impl PacketAccumulation for NoOpPacketAccumulator {
    fn store(&mut self, data: BytesMut) -> Result<AccumulatorState> {
        self.pkts.push(data);
        Ok(AccumulatorState::ReadyToFlush)
    }

    fn get_accumulated_pkts(&mut self) -> Result<Vec<BytesMut>> {
        let moved_pkts = std::mem::replace(&mut self.pkts, Vec::with_capacity(1));

        Ok(moved_pkts)
    }

    fn cleanup_stale_states(&mut self) {
        // Do nothing
    }
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

/// Factory to build `Box<NoOpPacketAccumulator>`
#[derive(Default)]
pub struct NoopPacketAccumulatorFactory {}

impl PacketAccumulatorFactory for NoopPacketAccumulatorFactory {
    fn build(&self) -> PacketAccumulatorType {
        Box::new(NoOpPacketAccumulator::new())
    }

    fn get_accumulator_name(&self) -> String {
        String::from("NoOpPacketAccumulator")
    }
}

/// Factory to build `PacketAccumulatorType`
pub type PacketAccumulatorFactoryType = Box<dyn PacketAccumulatorFactory + Send + Sync>;

impl Default for PacketAccumulatorFactoryType {
    fn default() -> Self {
        Box::new(NoopPacketAccumulatorFactory::default())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_noop_accumulator() {
        // Factory
        let no_op_accumulator_factory = PacketAccumulatorFactoryType::default();
        assert_eq!(
            no_op_accumulator_factory.get_accumulator_name(),
            String::from("NoOpPacketAccumulator")
        );

        let mut no_op_accumulator = no_op_accumulator_factory.build();

        // Accumulator

        // Initial state
        assert!(no_op_accumulator.get_accumulated_pkts().unwrap().is_empty());

        // Generating dummy packets
        let mut packet1 = BytesMut::zeroed(1350);
        packet1.fill(1);
        let packet1_clone = packet1.clone();

        let mut packet2 = BytesMut::zeroed(1350);
        packet2.fill(2);
        let packet2_clone = packet2.clone();

        // Adding packets
        assert!(matches!(
            no_op_accumulator.store(packet1).unwrap(),
            AccumulatorState::ReadyToFlush
        ));
        assert!(matches!(
            no_op_accumulator.store(packet2).unwrap(),
            AccumulatorState::ReadyToFlush
        ));

        let accumulated_pkts = no_op_accumulator.get_accumulated_pkts().unwrap();

        assert_eq!(accumulated_pkts[0], packet1_clone);
        assert_eq!(accumulated_pkts[1], packet2_clone);

        // Accumulator state should be reset after getting the packets
        assert!(no_op_accumulator.get_accumulated_pkts().unwrap().is_empty());
    }
}
