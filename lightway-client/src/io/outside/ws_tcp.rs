use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use rand::Rng;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use super::OutsideIO;
use lightway_core::{IOCallbackResult, OutsideIOSendCallback, OutsideIOSendCallbackArg};

struct WsState {
    read_buf: BytesMut,
    write_pending: BytesMut,
}

pub struct WsTcp {
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    state: Mutex<WsState>,
}

impl WsTcp {
    pub async fn new(
        remote_addr: SocketAddr,
        ws_host: &str,
        ws_path: &str,
    ) -> Result<Arc<Self>> {
        let stream = tokio::net::TcpStream::connect(remote_addr).await?;
        stream.set_nodelay(true)?;
        let peer_addr = stream.peer_addr()?;

        Self::ws_handshake(&stream, ws_host, ws_path).await?;

        Ok(Arc::new(Self {
            stream,
            peer_addr,
            state: Mutex::new(WsState {
                read_buf: BytesMut::with_capacity(32 * 1024),
                write_pending: BytesMut::new(),
            }),
        }))
    }

    async fn ws_handshake(
        stream: &tokio::net::TcpStream,
        host: &str,
        path: &str,
    ) -> Result<()> {
        let key = Self::generate_ws_key();
        let request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        );

        let request_bytes = request.as_bytes();
        let mut written = 0;
        while written < request_bytes.len() {
            stream.writable().await?;
            match stream.try_write(&request_bytes[written..]) {
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }

        let mut response = Vec::with_capacity(512);
        loop {
            stream.readable().await?;
            let mut tmp = [0u8; 1024];
            match stream.try_read(&mut tmp) {
                Ok(0) => return Err(anyhow!("Connection closed during WebSocket handshake")),
                Ok(n) => {
                    response.extend_from_slice(&tmp[..n]);
                    if response.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if response.len() > 4096 {
                        return Err(anyhow!("WebSocket handshake response too large"));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        if !response_str.starts_with("HTTP/1.1 101") {
            return Err(anyhow!(
                "WebSocket handshake failed: {}",
                response_str.lines().next().unwrap_or("empty response")
            ));
        }

        tracing::info!("WebSocket handshake completed");
        Ok(())
    }

    fn generate_ws_key() -> String {
        let key: [u8; 16] = rand::rng().random();
        base64_encode(&key)
    }

    fn try_flush_pending(
        stream: &tokio::net::TcpStream,
        pending: &mut BytesMut,
    ) {
        while !pending.is_empty() {
            match stream.try_write(pending) {
                Ok(n) => {
                    pending.advance(n);
                }
                Err(_) => break,
            }
        }
    }
}

#[async_trait]
impl OutsideIO for WsTcp {
    fn set_send_buffer_size(&self, size: usize) -> Result<()> {
        let socket = socket2::SockRef::from(&self.stream);
        socket.set_send_buffer_size(size)?;
        Ok(())
    }

    fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        let socket = socket2::SockRef::from(&self.stream);
        socket.set_recv_buffer_size(size)?;
        Ok(())
    }

    async fn poll(&self, interest: tokio::io::Interest) -> Result<tokio::io::Ready> {
        let r = self.stream.ready(interest).await?;
        Ok(r)
    }

    fn recv_buf(&self, buf: &mut bytes::BytesMut) -> IOCallbackResult<usize> {
        let mut state = self.state.lock().unwrap();

        // Opportunistically flush pending writes (e.g. Pong responses)
        if !state.write_pending.is_empty() {
            Self::try_flush_pending(&self.stream, &mut state.write_pending);
        }

        // Read raw TCP data into internal buffer
        match self.stream.try_read_buf(&mut state.read_buf) {
            Ok(0) => {
                use std::io::{Error, ErrorKind::ConnectionAborted};
                return IOCallbackResult::Err(Error::new(ConnectionAborted, "End of stream"));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if state.read_buf.is_empty() {
                    return IOCallbackResult::WouldBlock;
                }
            }
            Err(e) => return IOCallbackResult::Err(e),
        }

        // Decode all complete WebSocket frames
        let mut total_decoded = 0;
        loop {
            match decode_ws_frame(&mut state.read_buf) {
                WsFrameResult::Frame { opcode, payload } => match opcode {
                    0x0 | 0x1 | 0x2 => {
                        total_decoded += payload.len();
                        buf.extend_from_slice(&payload);
                    }
                    0x8 => {
                        use std::io::{Error, ErrorKind::ConnectionAborted};
                        return IOCallbackResult::Err(Error::new(
                            ConnectionAborted,
                            "WebSocket close",
                        ));
                    }
                    0x9 => {
                        let pong = encode_ws_control_frame(0xA, &payload);
                        state.write_pending.extend_from_slice(&pong);
                    }
                    _ => {} // 0xA (Pong) and others: ignore
                },
                WsFrameResult::Incomplete => break,
            }
        }

        if total_decoded > 0 {
            IOCallbackResult::Ok(total_decoded)
        } else {
            IOCallbackResult::WouldBlock
        }
    }

    fn into_io_send_callback(self: Arc<Self>) -> OutsideIOSendCallbackArg {
        self
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

impl OutsideIOSendCallback for WsTcp {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        let mut state = self.state.lock().unwrap();

        // Flush pending data from previous partial writes
        while !state.write_pending.is_empty() {
            match self.stream.try_write(&state.write_pending) {
                Ok(n) => {
                    state.write_pending.advance(n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return IOCallbackResult::WouldBlock;
                }
                Err(e) => return IOCallbackResult::Err(e),
            }
        }

        let frame = encode_ws_binary_frame(buf);

        match self.stream.try_write(&frame) {
            Ok(n) if n == frame.len() => IOCallbackResult::Ok(buf.len()),
            Ok(n) => {
                // Partial write: buffer the remainder, report full consumption
                // since we've committed to sending this frame
                state.write_pending.extend_from_slice(&frame[n..]);
                IOCallbackResult::Ok(buf.len())
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => IOCallbackResult::WouldBlock,
            Err(e) => IOCallbackResult::Err(e),
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

// --- WebSocket frame codec ---

enum WsFrameResult {
    Frame { opcode: u8, payload: BytesMut },
    Incomplete,
}

/// Decode one server→client WebSocket frame (typically unmasked).
fn decode_ws_frame(buf: &mut BytesMut) -> WsFrameResult {
    if buf.len() < 2 {
        return WsFrameResult::Incomplete;
    }

    let first = buf[0];
    let second = buf[1];
    let opcode = first & 0x0F;
    let masked = (second & 0x80) != 0;
    let len_indicator = (second & 0x7F) as usize;

    let (payload_len, header_size) = match len_indicator {
        0..=125 => (len_indicator, 2),
        126 => {
            if buf.len() < 4 {
                return WsFrameResult::Incomplete;
            }
            (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4)
        }
        _ => {
            if buf.len() < 10 {
                return WsFrameResult::Incomplete;
            }
            let len = u64::from_be_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            ]) as usize;
            (len, 10)
        }
    };

    let mask_size = if masked { 4 } else { 0 };
    let total = header_size + mask_size + payload_len;

    if buf.len() < total {
        return WsFrameResult::Incomplete;
    }

    buf.advance(header_size);

    let mask = if masked {
        let m = [buf[0], buf[1], buf[2], buf[3]];
        buf.advance(4);
        Some(m)
    } else {
        None
    };

    let mut payload = buf.split_to(payload_len);

    if let Some(m) = mask {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= m[i % 4];
        }
    }

    WsFrameResult::Frame { opcode, payload }
}

/// Encode a client→server binary data frame (masked, opcode 0x2).
fn encode_ws_binary_frame(data: &[u8]) -> BytesMut {
    encode_ws_frame_inner(0x2, data)
}

/// Encode a client→server control frame (Pong=0xA, Close=0x8, etc.).
fn encode_ws_control_frame(opcode: u8, data: &[u8]) -> BytesMut {
    encode_ws_frame_inner(opcode, data)
}

fn encode_ws_frame_inner(opcode: u8, data: &[u8]) -> BytesMut {
    let payload_len = data.len();
    let header_size = match payload_len {
        0..=125 => 2 + 4,
        126..=65535 => 2 + 2 + 4,
        _ => 2 + 8 + 4,
    };

    let mut frame = BytesMut::with_capacity(header_size + payload_len);

    // FIN=1 + opcode
    frame.put_u8(0x80 | opcode);

    // MASK=1 + payload length
    match payload_len {
        0..=125 => frame.put_u8(0x80 | payload_len as u8),
        126..=65535 => {
            frame.put_u8(0x80 | 126);
            frame.put_u16(payload_len as u16);
        }
        _ => {
            frame.put_u8(0x80 | 127);
            frame.put_u64(payload_len as u64);
        }
    }

    let mask: [u8; 4] = rand::rng().random();
    frame.extend_from_slice(&mask);

    for (i, &byte) in data.iter().enumerate() {
        frame.put_u8(byte ^ mask[i % 4]);
    }

    frame
}

// --- Minimal base64 encoder (only used for 16-byte WebSocket key) ---

fn base64_encode(data: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARSET[((n >> 18) & 0x3F) as usize] as char);
        result.push(CHARSET[((n >> 12) & 0x3F) as usize] as char);
        result.push(if chunk.len() > 1 {
            CHARSET[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            CHARSET[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    result
}
