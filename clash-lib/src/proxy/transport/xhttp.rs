use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::ready;
use h2::{RecvStream, SendStream};
use http::{Request, StatusCode};
use rand::Rng;
use std::{collections::HashMap, fmt::Debug, io};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::error;

use super::Transport;
use crate::{common::errors::map_io_error, proxy::AnyStream};

pub struct Client {
    pub host: String,
    pub headers: HashMap<String, String>,
    pub method: http::Method,
    pub path: http::uri::PathAndQuery,
}

impl Client {
    pub fn new(
        host: String,
        headers: HashMap<String, String>,
        method: http::Method,
        path: http::uri::PathAndQuery,
    ) -> Self {
        Self {
            host,
            headers,
            method,
            path,
        }
    }

    fn req(&self) -> std::io::Result<Request<()>> {
        // Xray SplitHTTP (XHTTP) validates "x_padding" by default. For stream-one
        // mode, it is carried in the `Referer` header as a query param.
        let mut rng = rand::rng();
        let padding_len: usize = rng.random_range(100..1000);
        let x_padding = "X".repeat(padding_len);
        let referer = format!(
            "https://{}{}?x_padding={}",
            self.host,
            self.path.path(),
            x_padding
        );

        let uri = http::Uri::builder()
            .scheme("https")
            .authority(self.host.as_str())
            .path_and_query(self.path.clone())
            .build()
            .map_err(map_io_error)?;

        let mut request = Request::builder()
            .uri(uri)
            .method(self.method.clone())
            .version(http::Version::HTTP_2);

        let has_user_agent = self
            .headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("user-agent"));
        let has_content_type = self
            .headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("content-type"));

        for (k, v) in self.headers.iter() {
            if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("referer") {
                continue;
            }
            request = request.header(k, v);
        }

        request = request.header(http::header::REFERER, referer);

        if !has_user_agent {
            request = request.header(
                http::header::USER_AGENT,
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            );
        }
        if self.method == http::Method::POST && !has_content_type {
            request =
                request.header(http::header::CONTENT_TYPE, "application/grpc");
        }

        Ok(request.body(()).expect("must build request"))
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        let (mut client, h2) =
            h2::client::handshake(stream).await.map_err(map_io_error)?;

        let req = self.req()?;
        let (resp, send_stream) =
            client.send_request(req, false).map_err(map_io_error)?;

        tokio::spawn(async move {
            if let Err(e) = h2.await {
                error!("xhttp h2 error: {}", e);
            }
        });

        let resp = resp.await.map_err(map_io_error)?;
        if resp.status() != StatusCode::OK {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("xhttp unexpected response status: {}", resp.status()),
            ));
        }
        let recv_stream = resp.into_body();

        Ok(Box::new(XHttpStream::new(recv_stream, send_stream)))
    }
}

pub struct XHttpStream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    buffer: BytesMut,
}

impl Debug for XHttpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XHttpStream")
            .field("recv", &self.recv)
            .field("send", &self.send)
            .field("buffer", &self.buffer)
            .finish()
    }
}

impl XHttpStream {
    pub fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            buffer: BytesMut::with_capacity(1024 * 4),
        }
    }
}

impl AsyncRead for XHttpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.buffer.is_empty() {
            let to_read = std::cmp::min(self.buffer.len(), buf.remaining());
            let data = self.buffer.split_to(to_read);
            buf.put_slice(&data[..to_read]);
            return std::task::Poll::Ready(Ok(()));
        }
        std::task::Poll::Ready(match ready!(self.recv.poll_data(cx)) {
            Some(Ok(data)) => {
                let to_read = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_read]);
                if to_read < data.len() {
                    self.buffer.extend_from_slice(&data[to_read..]);
                }
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
            Some(Err(e)) => Err(io::Error::new(io::ErrorKind::ConnectionReset, e)),
            None => Ok(()),
        })
    }
}

impl AsyncWrite for XHttpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.send.reserve_capacity(buf.len());
        std::task::Poll::Ready(match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(to_write)) => self
                .send
                .send_data(Bytes::from(buf[..to_write].to_owned()), false)
                .map_or_else(
                    |e| Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)),
                    |_| Ok(to_write),
                ),
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
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.send.reserve_capacity(0);
        std::task::Poll::Ready(ready!(self.send.poll_capacity(cx)).map_or(
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "broken pipe",
            )),
            |_| {
                self.send.send_data(Bytes::new(), true).map_or_else(
                    |e| Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)),
                    |_| Ok(()),
                )
            },
        ))
    }
}
