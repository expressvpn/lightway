use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, BytesMut};
use lightway_core::{IOCallbackResult, OutsideIOSendCallback};
use tracing::info;

struct WsState {
    read_buf: BytesMut,
    write_pending: BytesMut,
}

pub(crate) struct WsTcpStream {
    sock: Arc<tokio::net::TcpStream>,
    peer_addr: SocketAddr,
    state: Mutex<WsState>,
}

impl WsTcpStream {
    /// Accept a WebSocket connection: read the HTTP Upgrade request,
    /// validate the path, and send back 101 Switching Protocols.
    pub(crate) async fn accept(
        sock: Arc<tokio::net::TcpStream>,
        peer_addr: SocketAddr,
        ws_path: &str,
    ) -> Result<Self> {
        Self::ws_accept_handshake(&sock, ws_path).await?;
        info!(%peer_addr, "WebSocket handshake accepted");
        Ok(Self {
            sock,
            peer_addr,
            state: Mutex::new(WsState {
                read_buf: BytesMut::with_capacity(32 * 1024),
                write_pending: BytesMut::new(),
            }),
        })
    }

    async fn ws_accept_handshake(
        sock: &tokio::net::TcpStream,
        expected_path: &str,
    ) -> Result<()> {
        let mut request = Vec::with_capacity(4096);
        loop {
            sock.readable().await?;
            let mut tmp = [0u8; 1024];
            match sock.try_read(&mut tmp) {
                Ok(0) => return Err(anyhow!("Connection closed during WebSocket handshake")),
                Ok(n) => {
                    request.extend_from_slice(&tmp[..n]);
                    if request.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if request.len() > 8192 {
                        return Err(anyhow!("WebSocket handshake request too large"));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }

        let request_str = String::from_utf8_lossy(&request);
        let first_line = request_str.lines().next().unwrap_or("");

        // Validate: "GET /ws HTTP/1.1"
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 3 || parts[0] != "GET" {
            send_http_response(sock, 400, "Bad Request").await?;
            return Err(anyhow!("Invalid HTTP request: {first_line}"));
        }
        if parts[1] != expected_path {
            send_http_response(sock, 404, "Not Found").await?;
            return Err(anyhow!("Wrong path: {} (expected {})", parts[1], expected_path));
        }

        // Extract Sec-WebSocket-Key
        let ws_key = request_str
            .lines()
            .find_map(|line| {
                let lower = line.to_ascii_lowercase();
                if lower.starts_with("sec-websocket-key:") {
                    Some(line.split_once(':')?.1.trim().to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow!("Missing Sec-WebSocket-Key header"))?;

        // Compute Sec-WebSocket-Accept = base64(SHA1(key + GUID))
        let accept_key = compute_ws_accept_key(&ws_key);

        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept_key}\r\n\
             \r\n"
        );

        let response_bytes = response.as_bytes();
        let mut written = 0;
        while written < response_bytes.len() {
            sock.writable().await?;
            match sock.try_write(&response_bytes[written..]) {
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(())
    }

    pub(crate) async fn readable(&self) -> std::io::Result<()> {
        self.sock.readable().await?;
        Ok(())
    }

    /// Read raw TCP data, decode WebSocket frames, and return payload bytes.
    pub(crate) fn recv_buf(&self, buf: &mut BytesMut) -> IOCallbackResult<usize> {
        let mut state = self.state.lock().unwrap();

        // Flush pending writes (e.g. Pong responses)
        if !state.write_pending.is_empty() {
            flush_pending(&self.sock, &mut state.write_pending);
        }

        match self.sock.try_read_buf(&mut state.read_buf) {
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
                        // Ping → queue Pong (server sends unmasked)
                        let pong = encode_ws_frame_server(0xA, &payload);
                        state.write_pending.extend_from_slice(&pong);
                    }
                    _ => {}
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
}

impl OutsideIOSendCallback for WsTcpStream {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        let mut state = self.state.lock().unwrap();

        while !state.write_pending.is_empty() {
            match self.sock.try_write(&state.write_pending) {
                Ok(n) => {
                    state.write_pending.advance(n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return IOCallbackResult::WouldBlock;
                }
                Err(e) => return IOCallbackResult::Err(e),
            }
        }

        let frame = encode_ws_frame_server(0x2, buf);

        match self.sock.try_write(&frame) {
            Ok(n) if n == frame.len() => IOCallbackResult::Ok(buf.len()),
            Ok(n) => {
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

// --- Helpers ---

fn flush_pending(sock: &tokio::net::TcpStream, pending: &mut BytesMut) {
    while !pending.is_empty() {
        match sock.try_write(pending) {
            Ok(n) => {
                pending.advance(n);
            }
            Err(_) => break,
        }
    }
}

async fn send_http_response(
    sock: &tokio::net::TcpStream,
    status: u16,
    reason: &str,
) -> Result<()> {
    let body = format!("{status} {reason}");
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        body.len()
    );
    let bytes = resp.as_bytes();
    let mut written = 0;
    while written < bytes.len() {
        sock.writable().await?;
        match sock.try_write(&bytes[written..]) {
            Ok(n) => written += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

// --- WebSocket frame codec ---

enum WsFrameResult {
    Frame { opcode: u8, payload: BytesMut },
    Incomplete,
}

/// Decode one WebSocket frame (handles both masked and unmasked).
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

/// Encode a server→client WebSocket frame (UNMASKED per RFC 6455).
fn encode_ws_frame_server(opcode: u8, data: &[u8]) -> BytesMut {
    let payload_len = data.len();
    let header_size = match payload_len {
        0..=125 => 2,
        126..=65535 => 4,
        _ => 10,
    };

    let mut frame = BytesMut::with_capacity(header_size + payload_len);

    frame.put_u8(0x80 | opcode);

    // MASK=0 (server frames are unmasked)
    match payload_len {
        0..=125 => frame.put_u8(payload_len as u8),
        126..=65535 => {
            frame.put_u8(126);
            frame.put_u16(payload_len as u16);
        }
        _ => {
            frame.put_u8(127);
            frame.put_u64(payload_len as u64);
        }
    }

    frame.extend_from_slice(data);
    frame
}

// --- WebSocket accept key computation ---

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-5AB9FB669B5A";

fn compute_ws_accept_key(client_key: &str) -> String {
    let mut input = String::with_capacity(client_key.len() + WS_GUID.len());
    input.push_str(client_key);
    input.push_str(WS_GUID);
    let hash = sha1(input.as_bytes());
    base64_encode(&hash)
}

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

/// Minimal SHA-1 implementation (RFC 3174) for WebSocket accept key only.
fn sha1(data: &[u8]) -> [u8; 20] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (
        0x6745_2301u32,
        0xEFCD_AB89u32,
        0x98BA_DCFEu32,
        0x1032_5476u32,
        0xC3D2_E1F0u32,
    );

    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}
