use std::{
    io,
    io::ErrorKind,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BufMut, BytesMut};
use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, error};

use crate::{proxy::AnyStream, session::SocksAddr};

const VLESS_VERSION: u8 = 0;
const VLESS_COMMAND_TCP: u8 = 1;
const VLESS_COMMAND_UDP: u8 = 2;

pub struct VlessStream {
    inner: AnyStream,
    handshake_done: bool,
    handshake_sent: bool,
    response_received: bool,
    uuid: uuid::Uuid,
    destination: SocksAddr,
    is_udp: bool,
    handshake_write_buf: BytesMut,
    handshake_write_pos: usize,
    first_write_len: usize,
    response_header: [u8; 2],
    response_header_read: usize,
    response_additional: Vec<u8>,
    response_additional_read: usize,
}

impl VlessStream {
    pub fn new(
        stream: AnyStream,
        uuid: &str,
        destination: &SocksAddr,
        is_udp: bool,
    ) -> io::Result<Self> {
        let uuid = uuid::Uuid::parse_str(uuid).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid UUID format")
        })?;

        debug!("VLESS stream created for destination: {}", destination);

        Ok(Self {
            inner: stream,
            handshake_done: false,
            handshake_sent: false,
            response_received: false,
            uuid,
            destination: destination.clone(),
            is_udp,
            handshake_write_buf: BytesMut::new(),
            handshake_write_pos: 0,
            first_write_len: 0,
            response_header: [0; 2],
            response_header_read: 0,
            response_additional: Vec::new(),
            response_additional_read: 0,
        })
    }

    fn build_handshake_header(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        // VLESS request header:
        // Version (1 byte) + UUID (16 bytes) + Additional info length (1 byte)
        // + Command (1 byte) + Port (2 bytes) + Address type + Address + Additional
        //   info
        buf.put_u8(VLESS_VERSION);
        buf.put_slice(self.uuid.as_bytes());
        buf.put_u8(0); // Additional info length (0 for simplicity)

        if self.is_udp {
            buf.put_u8(VLESS_COMMAND_UDP);
        } else {
            buf.put_u8(VLESS_COMMAND_TCP);
        }

        self.destination.write_to_buf_vmess(&mut buf);
        buf
    }

    fn poll_send_handshake(
        &mut self,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.handshake_sent {
            return Poll::Ready(Ok(0));
        }

        if self.handshake_write_buf.is_empty() && self.handshake_write_pos == 0 {
            debug!(
                "VLESS handshake starting for destination: {}",
                self.destination
            );
            self.handshake_write_buf = self.build_handshake_header();
            self.handshake_write_buf.put_slice(data);
            self.first_write_len = data.len();
        }

        while self.handshake_write_pos < self.handshake_write_buf.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(
                cx,
                &self.handshake_write_buf[self.handshake_write_pos..],
            ))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "failed to write VLESS handshake",
                )));
            }
            self.handshake_write_pos += n;
        }

        self.handshake_sent = true;
        self.handshake_write_buf.clear();
        self.handshake_write_pos = 0;
        debug!(
            "VLESS handshake sent with {} bytes of data",
            self.first_write_len
        );

        Poll::Ready(Ok(self.first_write_len))
    }

    fn poll_receive_response(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.response_received {
            return Poll::Ready(Ok(()));
        }

        while self.response_header_read < self.response_header.len() {
            let mut read_buf =
                ReadBuf::new(&mut self.response_header[self.response_header_read..]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf))?;
            let n = read_buf.filled().len();
            if n == 0 {
                error!("Failed to read VLESS response: unexpected EOF");
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "unexpected EOF while reading VLESS response header",
                )));
            }
            self.response_header_read += n;
        }

        if self.response_header[0] != VLESS_VERSION {
            error!(
                "Invalid VLESS response version: {}",
                self.response_header[0]
            );
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "invalid VLESS response version: {}",
                    self.response_header[0]
                ),
            )));
        }

        let additional_info_len = self.response_header[1] as usize;
        if self.response_additional.len() != additional_info_len {
            self.response_additional.resize(additional_info_len, 0);
            self.response_additional_read = 0;
        }

        while self.response_additional_read < additional_info_len {
            let mut read_buf = ReadBuf::new(
                &mut self.response_additional[self.response_additional_read..],
            );
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf))?;
            let n = read_buf.filled().len();
            if n == 0 {
                error!("Failed to read VLESS additional info: unexpected EOF");
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "unexpected EOF while reading VLESS additional info",
                )));
            }
            self.response_additional_read += n;
        }

        self.response_received = true;
        self.handshake_done = true;
        if additional_info_len > 0 {
            debug!(
                "VLESS additional info received: {} bytes",
                additional_info_len
            );
        }
        debug!("VLESS handshake completed successfully");

        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Must receive response before reading
        if self.handshake_sent && !self.response_received {
            ready!(self.poll_receive_response(cx))?;
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        // Send handshake with first write
        if !self.handshake_sent {
            return self.poll_send_handshake(cx, buf);
        }

        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
