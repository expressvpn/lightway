use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use rand::Rng;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use super::OutsideIO;
use lightway_core::{IOCallbackResult, OutsideIOSendCallback, OutsideIOSendCallbackArg};

struct WsState {
    read_buf: BytesMut,
    write_pending: BytesMut,
}

pub struct WsTcp {
    tcp: tokio::net::TcpStream,
    tls: Option<Mutex<rustls::ClientConnection>>,
    peer_addr: SocketAddr,
    state: Mutex<WsState>,
}

/// Adapter: non-blocking read from tokio TcpStream via std::io::Read.
/// Used by rustls::ClientConnection::read_tls().
struct TcpReader<'a>(&'a tokio::net::TcpStream);

impl Read for TcpReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.try_read(buf)
    }
}

/// Adapter: non-blocking write to tokio TcpStream via std::io::Write.
/// Used by rustls::ClientConnection::write_tls().
struct TcpWriter<'a>(&'a tokio::net::TcpStream);

impl Write for TcpWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.try_write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl WsTcp {
    pub async fn new(
        remote_addr: SocketAddr,
        ws_host: &str,
        ws_path: &str,
        use_tls: bool,
    ) -> Result<Arc<Self>> {
        let tcp = tokio::net::TcpStream::connect(remote_addr).await?;
        tcp.set_nodelay(true)?;
        let peer_addr = tcp.peer_addr()?;

        let tls = if use_tls {
            tracing::info!("Establishing outer TLS to {ws_host}");
            let tls_config = Self::make_tls_config()?;
            let server_name: rustls::pki_types::ServerName<'static> = ws_host
                .to_owned()
                .try_into()
                .map_err(|e| anyhow!("Invalid server name for TLS: {e}"))?;
            let mut tls_conn = rustls::ClientConnection::new(Arc::new(tls_config), server_name)
                .map_err(|e| anyhow!("Failed to create TLS session: {e}"))?;

            Self::complete_tls_handshake(&tcp, &mut tls_conn).await?;
            Self::ws_handshake_tls(&tcp, &mut tls_conn, ws_host, ws_path).await?;

            Some(Mutex::new(tls_conn))
        } else {
            Self::ws_handshake_plain(&tcp, ws_host, ws_path).await?;
            None
        };

        Ok(Arc::new(Self {
            tcp,
            tls,
            peer_addr,
            state: Mutex::new(WsState {
                read_buf: BytesMut::with_capacity(32 * 1024),
                write_pending: BytesMut::new(),
            }),
        }))
    }

    fn make_tls_config() -> Result<rustls::ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let provider = rustls::crypto::ring::default_provider();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow!("TLS protocol version error: {e}"))?
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(config)
    }

    async fn complete_tls_handshake(
        tcp: &tokio::net::TcpStream,
        tls: &mut rustls::ClientConnection,
    ) -> Result<()> {
        loop {
            if !tls.is_handshaking() {
                return Ok(());
            }

            while tls.wants_write() {
                tcp.writable().await?;
                match tls.write_tls(&mut TcpWriter(tcp)) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
            }

            if tls.wants_read() {
                tcp.readable().await?;
                match tls.read_tls(&mut TcpReader(tcp)) {
                    Ok(0) => return Err(anyhow!("Connection closed during TLS handshake")),
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e.into()),
                }
                tls.process_new_packets()
                    .map_err(|e| anyhow!("TLS handshake error: {e}"))?;
            }
        }
    }

    async fn ws_handshake_tls(
        tcp: &tokio::net::TcpStream,
        tls: &mut rustls::ClientConnection,
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

        tls.writer()
            .write_all(request.as_bytes())
            .map_err(|e| anyhow!("Failed to buffer WS request in TLS: {e}"))?;

        while tls.wants_write() {
            tcp.writable().await?;
            match tls.write_tls(&mut TcpWriter(tcp)) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }

        let mut response = Vec::with_capacity(512);
        loop {
            tcp.readable().await?;
            match tls.read_tls(&mut TcpReader(tcp)) {
                Ok(0) => return Err(anyhow!("Connection closed during WebSocket handshake")),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
            tls.process_new_packets()
                .map_err(|e| anyhow!("TLS error during WebSocket handshake: {e}"))?;

            let mut tmp = [0u8; 1024];
            loop {
                match tls.reader().read(&mut tmp) {
                    Ok(n) if n > 0 => response.extend_from_slice(&tmp[..n]),
                    _ => break,
                }
            }

            if response.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if response.len() > 4096 {
                return Err(anyhow!("WebSocket handshake response too large"));
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        if !response_str.starts_with("HTTP/1.1 101") {
            return Err(anyhow!(
                "WebSocket handshake failed: {}",
                response_str.lines().next().unwrap_or("empty response")
            ));
        }

        tracing::info!("WebSocket handshake completed (TLS)");
        Ok(())
    }

    async fn ws_handshake_plain(
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
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
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
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
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

    fn try_read_data(&self, buf: &mut BytesMut) -> io::Result<usize> {
        if let Some(ref tls_mutex) = self.tls {
            let mut tls = tls_mutex.lock().unwrap();

            // Single read_tls + process + reader.read — no loop.
            // Keeps sync time minimal so the write path, keepalive,
            // and Ctrl+C handler can run between iterations.
            // Throughput comes from rapid outer-loop iterations
            // (poll with yield → recv_buf → poll → …), not from
            // draining everything in one call.
            match tls.read_tls(&mut TcpReader(&self.tcp)) {
                Ok(0) => return Ok(0),
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Err(e) => return Err(e),
            }

            tls.process_new_packets()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // Drain ALL available plaintext. A single read_tls +
            // process_new_packets may produce more than 16KB of plaintext
            // (multiple TLS records in one TCP segment). If we only read
            // 16KB, the remainder accumulates across iterations until
            // "received plaintext buffer full".
            let mut tmp = [0u8; 16 * 1024];
            let mut total = 0;
            let mut tls_closed = false;
            loop {
                match tls.reader().read(&mut tmp) {
                    Ok(n) if n > 0 => {
                        buf.extend_from_slice(&tmp[..n]);
                        total += n;
                    }
                    Ok(_) => {
                        tls_closed = true;
                        break;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }

            if total > 0 {
                Ok(total)
            } else if tls_closed {
                Ok(0)
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            }
        } else {
            self.tcp.try_read_buf(buf)
        }
    }

    fn try_write_data(&self, buf: &[u8]) -> io::Result<usize> {
        if let Some(ref tls_mutex) = self.tls {
            let mut tls = tls_mutex.lock().unwrap();

            // Flush previously buffered TLS encrypted data first
            while tls.wants_write() {
                match tls.write_tls(&mut TcpWriter(&self.tcp)) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }

            // Backpressure: if prior encrypted data hasn't fully flushed
            // (TCP send buffer full), return Ok(0) so the caller saves buf
            // into write_pending instead of growing rustls's internal buffer
            // without bound. This matches the semantics of plain TCP's
            // try_write returning a partial/zero count when the socket is full.
            if tls.wants_write() {
                return Ok(0);
            }

            let n = tls.writer().write(buf)?;
            while tls.wants_write() {
                match tls.write_tls(&mut TcpWriter(&self.tcp)) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
            Ok(n)
        } else {
            self.tcp.try_write(buf)
        }
    }

    fn try_flush_pending(&self, pending: &mut BytesMut) {
        while !pending.is_empty() {
            match self.try_write_data(pending) {
                Ok(0) => break,
                Ok(n) => pending.advance(n),
                Err(_) => break,
            }
        }
    }

    fn generate_ws_key() -> String {
        let key: [u8; 16] = rand::rng().random();
        base64_encode(&key)
    }
}

#[async_trait]
impl OutsideIO for WsTcp {
    fn set_send_buffer_size(&self, size: usize) -> Result<()> {
        let socket = socket2::SockRef::from(&self.tcp);
        socket.set_send_buffer_size(size)?;
        Ok(())
    }

    fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        let socket = socket2::SockRef::from(&self.tcp);
        socket.set_recv_buffer_size(size)?;
        Ok(())
    }

    async fn poll(&self, interest: tokio::io::Interest) -> Result<tokio::io::Ready> {
        if let Some(ref tls_mutex) = self.tls {
            let (has_plaintext, has_pending_writes) = {
                let mut tls = tls_mutex.lock().unwrap();

                // Flush any pending TLS encrypted data to TCP
                while tls.wants_write() {
                    match tls.write_tls(&mut TcpWriter(&self.tcp)) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }

                let plaintext = interest.is_readable()
                    && tls
                        .process_new_packets()
                        .map_or(false, |s| s.plaintext_bytes_to_read() > 0);

                (plaintext, tls.wants_write())
            };
            // MutexGuard is dropped here — safe to .await below

            // Always yield in TLS mode so that other tasks (Ctrl+C handler,
            // inside IO, keepalive) get scheduled on the single-threaded runtime.
            tokio::task::yield_now().await;

            if has_plaintext {
                return Ok(tokio::io::Ready::READABLE);
            }

            // If TLS has unflushed encrypted data, also watch for WRITABLE
            // so we can retry the flush. Without this, after a burst of writes
            // (e.g. speed test), pending data stays stuck in the rustls buffer
            // while we block on READABLE, killing keepalive and stalling the
            // connection.
            let effective_interest = if has_pending_writes {
                interest | tokio::io::Interest::WRITABLE
            } else {
                interest
            };
            let r = self.tcp.ready(effective_interest).await?;
            return Ok(r);
        }
        let r = self.tcp.ready(interest).await?;
        Ok(r)
    }

    fn recv_buf(&self, buf: &mut bytes::BytesMut) -> IOCallbackResult<usize> {
        let mut state = self.state.lock().unwrap();

        if !state.write_pending.is_empty() {
            self.try_flush_pending(&mut state.write_pending);
        }

        match self.try_read_data(&mut state.read_buf) {
            Ok(0) => {
                return IOCallbackResult::Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "End of stream",
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
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
                        return IOCallbackResult::Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "WebSocket close",
                        ));
                    }
                    0x9 => {
                        let pong = encode_ws_control_frame(0xA, &payload);
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

        while !state.write_pending.is_empty() {
            match self.try_write_data(&state.write_pending) {
                Ok(0) => return IOCallbackResult::WouldBlock,
                Ok(n) => {
                    state.write_pending.advance(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return IOCallbackResult::WouldBlock;
                }
                Err(e) => return IOCallbackResult::Err(e),
            }
        }

        let frame = encode_ws_binary_frame(buf);

        match self.try_write_data(&frame) {
            Ok(n) if n == frame.len() => IOCallbackResult::Ok(buf.len()),
            Ok(n) => {
                state.write_pending.extend_from_slice(&frame[n..]);
                IOCallbackResult::Ok(buf.len())
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => IOCallbackResult::WouldBlock,
            Err(e) => return IOCallbackResult::Err(e),
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

/// Decode one server->client WebSocket frame (typically unmasked).
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

/// Encode a client->server binary data frame (masked, opcode 0x2).
fn encode_ws_binary_frame(data: &[u8]) -> BytesMut {
    encode_ws_frame_inner(0x2, data)
}

/// Encode a client->server control frame (Pong=0xA, Close=0x8, etc.).
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

    frame.put_u8(0x80 | opcode);

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
