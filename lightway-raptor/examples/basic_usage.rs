use lightway_raptor::LightwayDataFrame;
use rand::seq::SliceRandom;
use raptorq::{Decoder, Encoder, EncodingPacket};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a LightwayDataFrame and add packets.
    let mut frame = LightwayDataFrame::new(Vec::new());
    frame.add_packet(vec![1, 2, 3]);
    frame.add_packet(vec![4, 5, 6, 7]);

    // Serialize the frame.
    let serialized = frame.serialize()?;
    println!("Serialized Frame: {:?}", serialized);

    // Deserialize the frame.
    let deserialized_frame = LightwayDataFrame::deserialize(&serialized)?;
    println!("Deserialized Frame: {:?}", deserialized_frame);

    // Retrieve and print individual packets.
    if let Some(packet) = deserialized_frame.get_packet(0) {
        println!("First Packet: {:?}", packet);
    }

    // Create an encooder
    let encoder = Encoder::with_defaults(&serialized, 10);

    // Perform the encoding, and serialize to Vec<u8> for transmission
    let mut packets: Vec<Vec<u8>> = encoder
        .get_encoded_packets(15)
        .iter()
        .map(|packet| packet.serialize())
        .collect();

    println!("Encoded packets: {:?}", packets);

    packets.shuffle(&mut rand::rng());
    // Erase 10 packets at random
    let length = packets.len();
    packets.truncate(length - 10);

    println!("Encoded packets after loss: {:?}", packets);

    println!("We have {} packets.", packets.len());
    let mut decoder = Decoder::new(encoder.get_config());

    let mut counter = 0;
    // Perform the decoding
    let mut result = None;
    while !packets.is_empty() {
        counter += 1;
        result = decoder.decode(EncodingPacket::deserialize(&packets.pop().unwrap()));
        if result.is_some() {
            break;
        }
    }

    println!("Packets needed to decode: {counter}");
    Ok(())
}
