use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::ready;
use h2::{RecvStream, SendStream};
use http::Request;
use rand::Rng;
use std::{collections::HashMap, fmt::Debug, io, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{error, warn};

use super::Transport;
use crate::{common::errors::map_io_error, proxy::AnyStream};

// Keep flow-control enabled to avoid bufferbloat on shared HTTP/2 connections.
const H2_STREAM_WINDOW_SIZE: u32 = 2 * 1024 * 1024; // 2 MiB
const H2_CONNECTION_WINDOW_SIZE: u32 = 4 * 1024 * 1024; // 4 MiB
const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

pub struct Client {
    pub hosts: Vec<String>,
    pub headers: HashMap<String, String>,
    pub method: http::Method,
    pub path: http::uri::PathAndQuery,
}

impl Client {
    pub fn new(
        hosts: Vec<String>,
        headers: HashMap<String, String>,
        method: http::Method,
        path: http::uri::PathAndQuery,
    ) -> Self {
        Self {
            hosts,
            headers,
            method,
            path,
        }
    }

    fn req(&self) -> std::io::Result<Request<()>> {
        let uri_idx = rand::rng().random_range(0..self.hosts.len());
        let uri = {
            http::Uri::builder()
                .scheme("https")
                .authority(self.hosts[uri_idx].as_str())
                .path_and_query(self.path.clone())
                .build()
                .map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                })?
        };
        let mut request = Request::builder()
            .uri(uri)
            .method(self.method.clone())
            .version(http::Version::HTTP_2);
        for (k, v) in self.headers.iter() {
            if k != "Host" {
                request = request.header(k, v);
            }
        }

        request.body(()).map_err(map_io_error)
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        let (mut client, mut h2) = h2::client::Builder::new()
            .initial_connection_window_size(H2_CONNECTION_WINDOW_SIZE)
            .initial_window_size(H2_STREAM_WINDOW_SIZE)
            .initial_max_send_streams(1024)
            .enable_push(false)
            .handshake(stream)
            .await
            .map_err(map_io_error)?;

        let ping_pong = h2.ping_pong();
        let req = self.req()?;

        tokio::spawn(async move {
            if let Err(e) = h2.await {
                error!("h2 error: {}", e);
            }
        });

        if let Some(mut ping_pong) = ping_pong {
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(H2_KEEPALIVE_INTERVAL);
                interval.tick().await;
                loop {
                    interval.tick().await;
                    if let Err(e) = ping_pong.ping(h2::Ping::opaque()).await {
                        warn!("h2 ping error: {e}");
                        break;
                    }
                }
            });
        }

        client = client.ready().await.map_err(map_io_error)?;
        let (resp, send_stream) =
            client.send_request(req, false).map_err(map_io_error)?;

        let recv_stream = resp.await.map_err(map_io_error)?.into_body();

        Ok(Box::new(Http2Stream::new(recv_stream, send_stream)))
    }
}

pub struct Http2Stream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    buffer: BytesMut,
    pending_release: usize,
    shutdown_sent: bool,
}

impl Debug for Http2Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http2Stream")
            .field("recv", &self.recv)
            .field("send", &self.send)
            .field("buffer", &self.buffer)
            .finish()
    }
}

impl Http2Stream {
    pub fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            buffer: BytesMut::with_capacity(1024 * 4),
            pending_release: 0,
            shutdown_sent: false,
        }
    }
}

impl AsyncRead for Http2Stream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.buffer.is_empty() {
            let to_read = std::cmp::min(self.buffer.len(), buf.remaining());
            let data = self.buffer.split_to(to_read);
            buf.put_slice(&data[..to_read]);
            if self.pending_release > 0 {
                let release = to_read.min(self.pending_release);
                if release > 0 {
                    if let Err(e) =
                        self.recv.flow_control().release_capacity(release)
                    {
                        return std::task::Poll::Ready(Err(
                            std::io::Error::new(
                                std::io::ErrorKind::ConnectionReset,
                                e,
                            ),
                        ));
                    }
                    self.pending_release -= release;
                }
            }
            return std::task::Poll::Ready(Ok(()));
        }
        std::task::Poll::Ready(match ready!(self.recv.poll_data(cx)) {
            Some(Ok(data)) => {
                let to_read = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_read]);
                if to_read < data.len() {
                    self.buffer.extend_from_slice(&data[to_read..]);
                    self.pending_release += data.len() - to_read;
                }
                if to_read == 0 {
                    Ok(())
                } else {
                    self.recv
                        .flow_control()
                        .release_capacity(to_read)
                        .map_or_else(
                            |e| {
                                Err(std::io::Error::new(
                                    std::io::ErrorKind::ConnectionReset,
                                    e,
                                ))
                            },
                            |_| Ok(()),
                        )
                }
            }
            Some(Err(e)) => Err(io::Error::new(io::ErrorKind::ConnectionReset, e)),
            None => Ok(()),
        })
    }
}

impl AsyncWrite for Http2Stream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.send.reserve_capacity(buf.len());
        std::task::Poll::Ready(match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(to_write)) => {
                let to_write = std::cmp::min(to_write, buf.len());
                self
                .send
                .send_data(Bytes::from(buf[..to_write].to_owned()), false)
                .map_or_else(
                    |e| Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)),
                    |_| Ok(to_write),
                )
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "broken pipe",
            )),
        })
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        if self.shutdown_sent {
            return std::task::Poll::Ready(Ok(()));
        }
        self.shutdown_sent = true;
        std::task::Poll::Ready(
            self.send
                .send_data(Bytes::new(), true)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)),
        )
    }
}
