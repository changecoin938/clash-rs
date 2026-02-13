use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    pin::Pin,
    task::Poll,
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{Future, Sink, Stream, pin_mut, ready};
use tracing::{debug, trace};

use tokio::io::{AsyncReadExt, AsyncWrite};

use crate::{
    proxy::{AnyStream, datagram::UdpPacket},
    session::{SocksAddr, SocksAddrType},
};

pub struct OutboundDatagramTrojan {
    inner: AnyStream,
    remote_addr: SocksAddr,

    state: ReadState,
    read_buf: BytesMut,

    flushed: bool,
    write_buf: BytesMut,
    write_pos: usize,
}

impl OutboundDatagramTrojan {
    pub fn new(inner: AnyStream, remote_addr: SocksAddr) -> Self {
        Self {
            inner,
            remote_addr,

            read_buf: BytesMut::new(),
            state: ReadState::Atyp,

            flushed: true,
            write_buf: BytesMut::new(),
            write_pos: 0,
        }
    }
}

impl Sink<UdpPacket> for OutboundDatagramTrojan {
    type Error = std::io::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(
        self: std::pin::Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.write_buf.clear();
        item.dst_addr.write_buf(&mut pin.write_buf);
        pin.write_buf.put_u16(item.data.len() as u16);
        pin.write_buf.put_slice(b"\r\n");
        pin.write_buf.put_slice(&item.data);
        pin.write_pos = 0;
        pin.flushed = false;
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();
        while this.write_pos < this.write_buf.len() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(
                cx,
                &this.write_buf[this.write_pos..],
            ))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write trojan datagram",
                )));
            }
            this.write_pos += n;
            trace!(
                "written {} bytes to trojan stream, remaining {} bytes",
                n,
                this.write_buf.len().saturating_sub(this.write_pos)
            );
        }
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        this.flushed = true;
        this.write_buf.clear();
        this.write_pos = 0;
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

enum Addr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Domain(String),
}
enum ReadState {
    Atyp,
    Addr(u8),
    Port(Addr),
    DataLen(SocksAddr),
    Data(SocksAddr, usize),
}

impl Stream for OutboundDatagramTrojan {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut read_buf,
            ref mut inner,
            ref remote_addr,
            ref mut state,
            ..
        } = *self;

        let mut pin = Pin::new(inner.as_mut());

        loop {
            match state {
                ReadState::Atyp => {
                    let fut = pin.read_u8();
                    pin_mut!(fut);
                    match ready!(fut.poll(cx)) {
                        Ok(atyp) => {
                            *state = ReadState::Addr(atyp);
                        }
                        Err(err) => {
                            debug!(
                                "failed to read socks addr from Trojan stream: {}",
                                err
                            );
                            return Poll::Ready(None);
                        }
                    }
                }
                ReadState::Addr(atyp) => match *atyp {
                    SocksAddrType::V4 => {
                        let fut = pin.read_u32();
                        pin_mut!(fut);
                        match ready!(fut.poll(cx)) {
                            Ok(ip) => {
                                let ip = Ipv4Addr::from(ip);
                                *state = ReadState::Port(Addr::V4(ip));
                            }
                            Err(err) => {
                                debug!(
                                    "failed to read socks addr from Trojan stream: \
                                     {}",
                                    err
                                );
                                return Poll::Ready(None);
                            }
                        }
                    }
                    SocksAddrType::V6 => {
                        let fut = pin.read_u128();
                        pin_mut!(fut);
                        match ready!(fut.poll(cx)) {
                            Ok(ip) => {
                                let ip = Ipv6Addr::from(ip);
                                *state = ReadState::Port(Addr::V6(ip));
                            }
                            Err(err) => {
                                debug!(
                                    "failed to read socks addr from Trojan stream: \
                                     {}",
                                    err
                                );
                                return Poll::Ready(None);
                            }
                        }
                    }
                    SocksAddrType::DOMAIN => {
                        let fut = pin.read_u8();
                        pin_mut!(fut);
                        match ready!(fut.poll(cx)) {
                            Ok(domain_len) => {
                                let mut buf = vec![0u8; domain_len as usize];
                                let fut = pin.read_exact(&mut buf);
                                pin_mut!(fut);
                                let n = match ready!(fut.poll(cx)) {
                                    Ok(n) => n,
                                    Err(err) => {
                                        debug!(
                                            "failed to read socks addr from Trojan \
                                             stream: {}",
                                            err
                                        );
                                        return Poll::Ready(None);
                                    }
                                };
                                if n != domain_len as usize {
                                    return Poll::Ready(None);
                                }
                                let domain = String::from_utf8(buf);
                                let domain = match domain {
                                    Ok(domain) => domain,
                                    Err(err) => {
                                        debug!(
                                            "failed to read socks addr from Trojan \
                                             stream: {}",
                                            err
                                        );
                                        return Poll::Ready(None);
                                    }
                                };
                                *state = ReadState::Port(Addr::Domain(domain));
                            }
                            Err(err) => {
                                debug!(
                                    "failed to read socks addr from Trojan stream: \
                                     {}",
                                    err
                                );
                                return Poll::Ready(None);
                            }
                        }
                    }
                    _ => {
                        debug!("invalid socks addr type: {:?}", atyp);
                        return Poll::Ready(None);
                    }
                },
                ReadState::Port(addr) => {
                    let fut = pin.read_u16();
                    pin_mut!(fut);
                    match ready!(fut.poll(cx)) {
                        Ok(port) => {
                            let addr = match addr {
                                Addr::V4(ip) => SocksAddr::from((*ip, port)),
                                Addr::V6(ip) => SocksAddr::from((*ip, port)),
                                Addr::Domain(domain) => {
                                    match SocksAddr::try_from((
                                        domain.to_owned(),
                                        port,
                                    )) {
                                        Ok(addr) => addr,
                                        Err(err) => {
                                            debug!(
                                                "failed to read socks addr from \
                                                 Trojan stream: {}",
                                                err
                                            );
                                            return Poll::Ready(None);
                                        }
                                    }
                                }
                            };
                            *state = ReadState::DataLen(addr);
                        }
                        Err(err) => {
                            debug!(
                                "failed to read socks addr from Trojan stream: {}",
                                err
                            );
                            return Poll::Ready(None);
                        }
                    }
                }
                ReadState::DataLen(addr) => {
                    // TODO: this is error prone, make this a more accurate
                    // state machine
                    let fut = pin.read_u16();
                    pin_mut!(fut);
                    let data_len = match ready!(fut.poll(cx)) {
                        Ok(data_len) => data_len,
                        Err(err) => {
                            debug!(
                                "failed to read socks addr from Trojan stream: {}",
                                err
                            );
                            return Poll::Ready(None);
                        }
                    };
                    read_buf.resize(2, 0);
                    let fut = pin.read_exact(read_buf);
                    pin_mut!(fut);
                    match ready!(fut.poll(cx)) {
                        Ok(_) => {
                            if &read_buf[..2] != b"\r\n" {
                                debug!("invalid trojan data");
                                return Poll::Ready(None);
                            }
                        }
                        Err(err) => {
                            debug!(
                                "failed to read socks addr from Trojan stream: {}",
                                err
                            );
                            return Poll::Ready(None);
                        }
                    };

                    read_buf.resize(data_len as usize, 0);
                    *state = ReadState::Data(addr.to_owned(), data_len as usize);
                }
                ReadState::Data(addr, len) => {
                    let fut = pin.read_exact(read_buf);
                    pin_mut!(fut);
                    match ready!(fut.poll(cx)) {
                        Ok(n) => {
                            if n != *len {
                                debug!("invalid trojan data");
                                return Poll::Ready(None);
                            }

                            let addr = addr.to_owned();
                            let len = len.to_owned();

                            *state = ReadState::Atyp;

                            let data = read_buf.split_to(len);

                            return Poll::Ready(Some(UdpPacket {
                                data: data.to_vec(),
                                src_addr: remote_addr.clone(),
                                dst_addr: addr,
                            }));
                        }
                        Err(err) => {
                            debug!(
                                "failed to read socks addr from Trojan stream: {}",
                                err
                            );
                            return Poll::Ready(None);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        io,
        net::Ipv4Addr,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use futures::SinkExt;
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[derive(Clone, Default)]
    struct FlakyStream {
        written: Arc<Mutex<Vec<u8>>>,
        pending_next: bool,
        max_write: usize,
    }

    impl FlakyStream {
        fn new(written: Arc<Mutex<Vec<u8>>>, max_write: usize) -> Self {
            Self {
                written,
                pending_next: false,
                max_write,
            }
        }
    }

    impl AsyncRead for FlakyStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for FlakyStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            if self.pending_next {
                self.pending_next = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.pending_next = true;

            let n = buf.len().min(self.max_write);
            self.written.lock().unwrap().extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn trojan_datagram_sink_handles_pending_writes() -> io::Result<()> {
        let written = Arc::new(Mutex::new(Vec::new()));
        let inner: AnyStream = Box::new(FlakyStream::new(written.clone(), 3));

        let mut sink = OutboundDatagramTrojan::new(inner, SocksAddr::any_ipv4());

        let pkt = UdpPacket {
            data: b"hello-world".to_vec(),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: SocksAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53)),
        };

        sink.send(pkt.clone()).await?;

        let mut expected = BytesMut::new();
        pkt.dst_addr.write_buf(&mut expected);
        expected.put_u16(pkt.data.len() as u16);
        expected.put_slice(b"\r\n");
        expected.put_slice(&pkt.data);

        assert_eq!(*written.lock().unwrap(), expected.to_vec());
        Ok(())
    }

    #[tokio::test]
    async fn trojan_datagram_stream_reads_multiple_packets_correctly() -> io::Result<()> {
        let (mut writer, reader) = tokio::io::duplex(1024);

        let mut encoded = BytesMut::new();
        // Packet 1: 1.2.3.4:53 "hello"
        encoded.put_u8(SocksAddrType::V4);
        encoded.put_u32(u32::from(Ipv4Addr::new(1, 2, 3, 4)));
        encoded.put_u16(53);
        encoded.put_u16(5);
        encoded.put_slice(b"\r\n");
        encoded.put_slice(b"hello");
        // Packet 2: 8.8.8.8:1234 "abc"
        encoded.put_u8(SocksAddrType::V4);
        encoded.put_u32(u32::from(Ipv4Addr::new(8, 8, 8, 8)));
        encoded.put_u16(1234);
        encoded.put_u16(3);
        encoded.put_slice(b"\r\n");
        encoded.put_slice(b"abc");

        tokio::spawn(async move {
            let _ = writer.write_all(&encoded).await;
            let _ = writer.shutdown().await;
        });

        let inner: AnyStream = Box::new(reader);
        let mut stream = OutboundDatagramTrojan::new(inner, SocksAddr::any_ipv4());

        let p1 = stream
            .next()
            .await
            .ok_or_else(|| io::Error::other("missing packet 1"))?;
        assert_eq!(p1.data, b"hello".to_vec());
        assert_eq!(p1.dst_addr.to_string(), "1.2.3.4:53");

        let p2 = stream
            .next()
            .await
            .ok_or_else(|| io::Error::other("missing packet 2"))?;
        assert_eq!(p2.data, b"abc".to_vec());
        assert_eq!(p2.dst_addr.to_string(), "8.8.8.8:1234");

        Ok(())
    }
}
