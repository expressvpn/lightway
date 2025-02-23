// use anyhow::{Context, Result};
// use bytes::BytesMut;
// use lightway_app_utils::TunIoUring;
// use lightway_core::IOCallbackResult;
// use std::{env, process::Command, time::Duration};
// use tokio::{net::UdpSocket, time::sleep};
// use tracing::{debug, error, info, warn};
// use tun::{Configuration, Layer};

// struct NetNSSetup {
//     ns1_name: String,
//     ns2_name: String,
//     veth1_name: String,
//     veth2_name: String,
//     ns1_ip: String,
//     ns2_ip: String,
// }

// // Keep NetNSSetup struct as is, but add logging to its methods
// impl NetNSSetup {
//     fn new(prefix: &str) -> Self {
//         Self {
//             ns1_name: format!("{}_ns1", prefix),
//             ns2_name: format!("{}_ns2", prefix),
//             veth1_name: format!("{}_veth1", prefix),
//             veth2_name: format!("{}_veth2", prefix),
//             ns1_ip: "10.0.0.1/24".to_string(),
//             ns2_ip: "10.0.0.2/24".to_string(),
//         }
//     }

//     fn setup(&self) -> Result<()> {
//         info!("Creating network namespaces");

//         debug!("Creating namespace {}", self.ns1_name);
//         Command::new("ip")
//             .args(["netns", "add", &self.ns1_name])
//             .status()
//             .context("Failed to create ns1")?;

//         debug!("Creating namespace {}", self.ns2_name);
//         Command::new("ip")
//             .args(["netns", "add", &self.ns2_name])
//             .status()
//             .context("Failed to create ns2")?;

//         info!("Creating veth pair");
//         Command::new("ip")
//             .args([
//                 "link",
//                 "add",
//                 &self.veth1_name,
//                 "type",
//                 "veth",
//                 "peer",
//                 "name",
//                 &self.veth2_name,
//             ])
//             .status()
//             .context("Failed to create veth pair")?;

//         info!("Moving interfaces to namespaces");
//         Command::new("ip")
//             .args(["link", "set", &self.veth1_name, "netns", &self.ns1_name])
//             .status()
//             .context("Failed to move veth1")?;

//         Command::new("ip")
//             .args(["link", "set", &self.veth2_name, "netns", &self.ns2_name])
//             .status()
//             .context("Failed to move veth2")?;

//         info!("Configuring IP addresses");
//         Command::new("ip")
//             .args([
//                 "netns",
//                 "exec",
//                 &self.ns1_name,
//                 "ip",
//                 "addr",
//                 "add",
//                 &self.ns1_ip,
//                 "dev",
//                 &self.veth1_name,
//             ])
//             .status()
//             .context("Failed to set ns1 IP")?;

//         Command::new("ip")
//             .args([
//                 "netns",
//                 "exec",
//                 &self.ns2_name,
//                 "ip",
//                 "addr",
//                 "add",
//                 &self.ns2_ip,
//                 "dev",
//                 &self.veth2_name,
//             ])
//             .status()
//             .context("Failed to set ns2 IP")?;

//         info!("Bringing up interfaces");
//         Command::new("ip")
//             .args([
//                 "netns",
//                 "exec",
//                 &self.ns1_name,
//                 "ip",
//                 "link",
//                 "set",
//                 &self.veth1_name,
//                 "up",
//             ])
//             .status()
//             .context("Failed to bring up veth1")?;

//         Command::new("ip")
//             .args([
//                 "netns",
//                 "exec",
//                 &self.ns2_name,
//                 "ip",
//                 "link",
//                 "set",
//                 &self.veth2_name,
//                 "up",
//             ])
//             .status()
//             .context("Failed to bring up veth2")?;

//         Ok(())
//     }

//     fn cleanup(&self) -> Result<()> {
//         info!("Cleaning up network namespaces");

//         debug!("Deleting namespace {}", self.ns1_name);
//         Command::new("ip")
//             .args(["netns", "del", &self.ns1_name])
//             .status()
//             .context("Failed to delete ns1")?;

//         debug!("Deleting namespace {}", self.ns2_name);
//         Command::new("ip")
//             .args(["netns", "del", &self.ns2_name])
//             .status()
//             .context("Failed to delete ns2")?;

//         Ok(())
//     }
// }

// struct Tunnel {
//     io_uring: TunIoUring,
//     transport: UdpSocket,
//     client_endpoint: Option<std::net::SocketAddr>,
// }

// impl Tunnel {
//     async fn new() -> Result<()> {
//         info!("Initializing tunnel device");

//         // Setup TUN device
//         let mut config = Configuration::default();
//         config.tun_name("tun0");
//         config.layer(Layer::L3);
//         config.mtu(1500);
//         config.up();

//         debug!("Creating TUN device with config: {:?}", config);
//         let io_uring = TunIoUring::new(config, 1024, Duration::from_secs(1))
//             .await
//             .context("Failed to create TUN device")?;

//         // Configure TUN IP
//         info!("Configuring TUN device IP");
//         Command::new("ip")
//             .args(["addr", "add", "10.0.0.10/24", "dev", "tun0"])
//             .status()
//             .context("Failed to set TUN IP")?;

//         Command::new("ip")
//             .args(["link", "set", "dev", "tun0", "up"])
//             .status()
//             .context("Failed to bring up TUN")?;

//         // Create UDP transport
//         info!("Creating UDP transport socket");
//         let transport = UdpSocket::bind("0.0.0.0:4789")
//             .await
//             .context("Failed to bind UDP socket")?;
//         info!("UDP transport listening on port 4789");

//         let mut tunnel = Self {
//             io_uring,
//             transport,
//             client_endpoint: None,
//         };

//         info!("Starting tunnel operation");
//         tunnel.run().await
//     }

//     async fn run(&mut self) -> Result<()> {
//         let mut udp_buf = [0u8; 2000];

//         loop {
//             tokio::select! {
//                 tun_result = self.io_uring.recv_buf() => {
//                     match tun_result {
//                         IOCallbackResult::Ok(buf) => {
//                             if let Some(client) = self.client_endpoint {
//                                 debug!("Forwarding {} bytes from TUN to client {}", buf.len(), client);
//                                 if let Err(e) = self.transport.send_to(&buf, client).await {
//                                     error!("Failed to send to client {}: {}", client, e);
//                                 }
//                             }
//                         }
//                         IOCallbackResult::WouldBlock => {
//                             debug!("TUN receive would block");
//                             sleep(Duration::from_millis(10)).await;
//                         }
//                         IOCallbackResult::Err(e) => {
//                             error!("TUN receive error: {}", e);
//                         }
//                     }
//                 }

//                 udp_result = self.transport.recv_from(&mut udp_buf) => {
//                     match udp_result {
//                         Ok((size, addr)) => {
//                             if self.client_endpoint.is_none() {
//                                 info!("New client connected from {}", addr);
//                                 self.client_endpoint = Some(addr);
//                             }

//                             if Some(addr) == self.client_endpoint {
//                                 debug!("Received {} bytes from client {}", size, addr);
//                                 let packet = BytesMut::from(&udp_buf[..size]);
//                                 match self.io_uring.try_send(packet) {
//                                     IOCallbackResult::Ok(n) => {
//                                         debug!("Wrote {} bytes to TUN", n);
//                                     }
//                                     IOCallbackResult::WouldBlock => {
//                                         warn!("TUN send would block");
//                                         sleep(Duration::from_millis(10)).await;
//                                     }
//                                     IOCallbackResult::Err(e) => {
//                                         error!("TUN send error: {}", e);
//                                     }
//                                 }
//                             } else {
//                                 warn!("Ignored packet from unknown client {}", addr);
//                             }
//                         }
//                         Err(e) => {
//                             error!("UDP receive error: {}", e);
//                         }
//                     }
//                 }
//             }
//         }
//     }
// }

// #[tokio::main]
// async fn main() -> Result<()> {
//     // Initialize logging
//     tracing_subscriber::fmt()
//         .with_max_level(tracing::Level::DEBUG)
//         .init();

//     info!("Starting VPN tunnel server");

//     // Check if we're running inside namespace
//     if env::args().any(|arg| arg == "--in-namespace") {
//         info!("Running in namespace, initializing tunnel");
//         Tunnel::new().await
//     } else {
//         info!("Setting up network namespaces");

//         let ns_setup = NetNSSetup::new("test");
//         debug!(
//             "Created namespace setup with: ns1={}, ns2={}",
//             ns_setup.ns1_name, ns_setup.ns2_name
//         );

//         ns_setup
//             .setup()
//             .context("Failed to setup network namespaces")?;
//         info!("Network namespaces configured successfully");

//         info!("Starting tunnel in namespace test_ns1");
//         let status = Command::new("ip")
//             .args([
//                 "netns",
//                 "exec",
//                 "test_ns1",
//                 &env::current_exe()?.to_string_lossy(),
//                 "--in-namespace",
//             ])
//             .status()
//             .context("Failed to start tunnel in namespace")?;

//         info!("Tunnel exited with status: {}", status);

//         if !status.success() {
//             error!("Tunnel failed with status: {}", status);
//         }

//         info!("Cleaning up network namespaces");
//         ns_setup
//             .cleanup()
//             .context("Failed to cleanup network namespaces")?;
//         info!("Cleanup complete");

//         Ok(())
//     }
// }

use anyhow::Result;
use io_uring::{opcode, types, IoUring};
use libc::iovec;
use std::os::fd::AsRawFd;
use tun::{Configuration, Layer};

fn main() -> Result<()> {
    // Create TUN device
    let mut config = Configuration::default();
    config.tun_name("tun0");
    config.layer(Layer::L3);
    config.up();

    let tun = tun::create(&config)?;
    println!("Created TUN device: tun0");

    // Create a test IP packet (very basic IPv4)
    let packet = [
        0x45, 0x00, 0x00, 0x14, // IPv4, len=20
        0x00, 0x00, 0x40, 0x00, // DF flag
        0x40, 0x01, 0x00, 0x00, // TTL=64, proto=ICMP
        0x0a, 0x00, 0x00, 0x0a, // src: 10.0.0.10
        0x0a, 0x00, 0x00, 0x02, // dst: 10.0.0.2
    ];

    let iov = iovec {
        iov_base: packet.as_ptr() as *mut libc::c_void,
        iov_len: packet.len(),
    };

    // Setup ring
    let mut ring = IoUring::new(8)?;
    println!("Created IO_URING");

    // Register buffer and file
    #[allow(unsafe_code)]
    // Safety: we manage buffer lifecycle
    unsafe {
        ring.submitter()
            .register_buffers(std::slice::from_ref(&iov))?;
        println!("Registered buffer");
        ring.submitter().register_files(&[tun.as_raw_fd()])?;
        println!("Registered TUN fd");
    }

    // Create WriteFixed operation
    let write_op = opcode::WriteFixed::new(
        types::Fixed(0),   // registered file index
        packet.as_ptr(),   // buffer pointer
        packet.len() as _, // length
        0,                 // registered buffer index
    )
    .build()
    .user_data(100);

    println!("Created write operation");

    // Queue operation
    #[allow(unsafe_code)]
    // Safety: io_uring crate works
    unsafe {
        ring.submission().push(&write_op)?;
    }
    println!("Queued operation");

    // Submit and wait for completion
    ring.submit_and_wait(1)?;
    println!("Submitted and waiting");

    // Check completion
    let cqe = ring.completion().next().expect("completion queue empty");
    println!("Write result: {}", cqe.result());

    Ok(())
}
