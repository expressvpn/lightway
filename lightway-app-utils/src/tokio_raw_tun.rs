use std::{
    io::Read,
    os::fd::{AsRawFd, RawFd},
    task::Poll,
};

use tokio::io::{unix::AsyncFd, AsyncRead};

pub struct TokioRawTun {
    io: AsyncFd<RawTunIo>,
}

impl TokioRawTun {
    pub fn new(fd: RawFd) -> Self {
        let io = AsyncFd::new(RawTunIo::new(fd)).unwrap();
        Self { io }
    }

    pub fn try_send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.io.get_ref().send(buf)
    }

    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.io.readable().await?;
            match guard.try_io(|inner| inner.get_ref().recv(buf)) {
                Ok(res) => return res,
                Err(_) => continue,
            }
        }
    }
}

impl AsyncRead for TokioRawTun {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let self_mut = self.get_mut();

        loop {
            let mut guard = match self_mut.io.poll_read_ready_mut(cx) {
                Poll::Ready(g) => g.unwrap(),
                Poll::Pending => return Poll::Pending,
            };

            match guard.try_io(|inner| inner.get_mut().read(buf.initialize_unfilled())) {
                Ok(Ok(n)) => {
                    buf.set_filled(buf.filled().len() + n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_) => continue,
            }
        }
    }
}

impl AsRawFd for TokioRawTun {
    fn as_raw_fd(&self) -> RawFd {
        self.io.as_raw_fd()
    }
}

pub struct RawTunIo {
    fd: RawFd,
}

impl RawTunIo {
    pub fn new(fd: RawFd) -> Self {
        Self { fd }
    }

    // taken from tokio-tun/src/linux/io.rs
    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::read(self.fd, buf.as_ptr() as *mut _, buf.len() as _) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as _)
    }

    // taken from tokio-tun/src/linux/io.rs
    pub fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const _, buf.len() as _) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as _)
    }
}

impl AsRawFd for RawTunIo {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Read for RawTunIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.recv(buf)
    }
}
