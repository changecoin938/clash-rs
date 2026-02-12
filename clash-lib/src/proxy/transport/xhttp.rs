use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::ready;
use h2::{RecvStream, SendStream};
use http::{Request, StatusCode};
use rand::Rng;
use std::{
    collections::HashMap,
    fmt::Debug,
    future::Future,
    io,
    pin::Pin,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::error;
use uuid::Uuid;

use super::Transport;
use crate::{common::errors::map_io_error, proxy::AnyStream};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    PacketUp,
    StreamUp,
    StreamOne,
}

pub struct Client {
    pub host: String,
    pub headers: HashMap<String, String>,
    pub path: http::uri::PathAndQuery,
    mode: Mode,
    packet_up_interval: Duration,
}

impl Client {
    pub fn new(
        host: String,
        headers: HashMap<String, String>,
        mode: Option<String>,
        path: http::uri::PathAndQuery,
    ) -> Self {
        let mode = mode.unwrap_or_else(|| "auto".to_owned());
        let mode = mode.to_ascii_lowercase();
        let mode = match mode.as_str() {
            "" | "auto" | "packet" | "packet-up" | "packet_up" => Mode::PacketUp,
            "stream" | "stream-up" | "stream_up" => Mode::StreamUp,
            "stream-one" | "stream_one" => Mode::StreamOne,
            // Assume the caller already validated. Default to packet-up.
            _ => Mode::PacketUp,
        };
        Self {
            host,
            headers,
            path,
            mode,
            packet_up_interval: Duration::from_millis(30),
        }
    }

    fn build_request(
        &self,
        method: http::Method,
        path: &str,
        query: Option<&str>,
        content_length: Option<usize>,
    ) -> std::io::Result<Request<()>> {
        // Xray SplitHTTP (XHTTP) validates "x_padding" by default. For stream-one
        // mode, it is carried in both URI query and the `Referer` header.
        let mut rng = rand::rng();
        let padding_len: usize = rng.random_range(100..=1000);
        let x_padding = "X".repeat(padding_len);

        let mut path_and_query = path.to_owned();
        match query {
            Some(q) if !q.is_empty() => {
                path_and_query.push('?');
                path_and_query.push_str(q);
                path_and_query.push('&');
            }
            _ => {
                path_and_query.push('?');
            }
        }
        path_and_query.push_str("x_padding=");
        path_and_query.push_str(&x_padding);

        let referer = format!("https://{}{}?x_padding={}", self.host, path, x_padding);

        let uri = http::Uri::builder()
            .scheme("https")
            .authority(self.host.as_str())
            .path_and_query(path_and_query.as_str())
            .build()
            .map_err(map_io_error)?;

        let mut request = Request::builder()
            .uri(uri)
            .method(method.clone())
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

        request = request.header(http::header::HOST, self.host.as_str());
        request = request.header(http::header::REFERER, referer);
        request = request.header("Accept-Encoding", "gzip");

        if !has_user_agent {
            request = request.header(
                http::header::USER_AGENT,
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            );
        }
        if let Some(content_length) = content_length {
            request = request.header(http::header::CONTENT_LENGTH, content_length);
        }
        if method == http::Method::POST && !has_content_type {
            request =
                request.header(http::header::CONTENT_TYPE, "application/grpc");
        }

        request.body(()).map_err(map_io_error)
    }

    fn split_path_and_query(&self) -> (String, Option<String>) {
        let base = self.path.to_string();
        let (path, query) = base
            .split_once('?')
            .map(|(p, q)| (p, Some(q.to_owned())))
            .unwrap_or((base.as_str(), None));
        (path.to_owned(), query.filter(|q| !q.is_empty()))
    }

    fn path_with_segments(
        &self,
        keep_trailing_slash: bool,
        session_id: Option<&str>,
        seq: Option<u64>,
    ) -> String {
        let (path, _) = self.split_path_and_query();

        let mut out = if keep_trailing_slash {
            path
        } else {
            let trimmed = path.trim_end_matches('/').to_owned();
            if trimmed.is_empty() {
                "/".to_owned()
            } else {
                trimmed
            }
        };

        if let Some(session_id) = session_id {
            if !out.ends_with('/') {
                out.push('/');
            }
            out.push_str(session_id);
        }
        if let Some(seq) = seq {
            if !out.ends_with('/') {
                out.push('/');
            }
            out.push_str(seq.to_string().as_str());
        }

        if keep_trailing_slash && !out.ends_with('/') && session_id.is_none() && seq.is_none() {
            out.push('/');
        }

        out
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        let (mut client, h2) =
            h2::client::handshake(stream).await.map_err(map_io_error)?;

        tokio::spawn(async move {
            if let Err(e) = h2.await {
                error!("xhttp h2 error: {}", e);
            }
        });

        match self.mode {
            Mode::StreamOne => {
                let (path, query) = self.split_path_and_query();
                let req = self.build_request(
                    http::Method::POST,
                    &path,
                    query.as_deref(),
                    None,
                )?;
                let (resp, send_stream) =
                    client.send_request(req, false).map_err(map_io_error)?;

                let resp = resp.await.map_err(map_io_error)?;
                if resp.status() != StatusCode::OK {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "xhttp unexpected response status: {}",
                            resp.status()
                        ),
                    ));
                }
                let recv_stream = resp.into_body();
                Ok(Box::new(XHttpStream::new(recv_stream, send_stream)))
            }
            Mode::StreamUp => {
                let session_id = Uuid::new_v4().to_string();
                let (_, base_query) = self.split_path_and_query();

                let down_path =
                    self.path_with_segments(false, Some(&session_id), None);
                let down_req = self.build_request(
                    http::Method::GET,
                    &down_path,
                    base_query.as_deref(),
                    None,
                )?;
                let (down_resp, _down_send) =
                    client.send_request(down_req, true).map_err(map_io_error)?;
                let down_resp = down_resp.await.map_err(map_io_error)?;
                if down_resp.status() != StatusCode::OK {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "xhttp download unexpected response status: {}",
                            down_resp.status()
                        ),
                    ));
                }
                let recv_stream = down_resp.into_body();

                let up_path =
                    self.path_with_segments(false, Some(&session_id), None);
                let up_req = self.build_request(
                    http::Method::POST,
                    &up_path,
                    base_query.as_deref(),
                    None,
                )?;
                let (up_resp, send_stream) =
                    client.send_request(up_req, false).map_err(map_io_error)?;

                tokio::spawn(async move {
                    match up_resp.await {
                        Ok(resp) if resp.status() == StatusCode::OK => {}
                        Ok(resp) => {
                            error!(
                                "xhttp upload unexpected response status: {}",
                                resp.status()
                            );
                        }
                        Err(e) => {
                            error!("xhttp upload response error: {e}");
                        }
                    }
                });

                Ok(Box::new(XHttpStream::new(recv_stream, send_stream)))
            }
            Mode::PacketUp => {
                let session_id = Uuid::new_v4().to_string();
                let (_, base_query) = self.split_path_and_query();

                let down_path =
                    self.path_with_segments(false, Some(&session_id), None);
                let down_req = self.build_request(
                    http::Method::GET,
                    &down_path,
                    base_query.as_deref(),
                    None,
                )?;
                let (down_resp, _down_send) =
                    client.send_request(down_req, true).map_err(map_io_error)?;
                let down_resp = down_resp.await.map_err(map_io_error)?;
                if down_resp.status() != StatusCode::OK {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "xhttp download unexpected response status: {}",
                            down_resp.status()
                        ),
                    ));
                }
                let recv_stream = down_resp.into_body();

                let (upload_tx, mut upload_rx) = mpsc::channel::<Bytes>(16);

                let host = self.host.clone();
                let headers = self.headers.clone();
                let packet_up_interval = self.packet_up_interval;
                let base_path = self.path_with_segments(false, Some(&session_id), None);
                tokio::spawn(async move {
                    let mut seq: u64 = 0;
                    let mut next_send_at = tokio::time::Instant::now();
                    while let Some(chunk) = upload_rx.recv().await {
                        if chunk.is_empty() {
                            break;
                        }

                        let path = format!("{}/{}", base_path, seq);
                        seq = seq.saturating_add(1);

                        let now = tokio::time::Instant::now();
                        if now < next_send_at {
                            tokio::time::sleep_until(next_send_at).await;
                        }
                        next_send_at = tokio::time::Instant::now() + packet_up_interval;

                        // Build request (mirrors `build_request` but avoids borrowing `self`).
                        let mut rng = rand::rng();
                        let padding_len: usize = rng.random_range(100..=1000);
                        let x_padding = "X".repeat(padding_len);

                        let mut path_and_query = path.clone();
                        if let Some(q) = base_query.as_ref().filter(|q| !q.is_empty()) {
                            path_and_query.push('?');
                            path_and_query.push_str(q);
                            path_and_query.push('&');
                        } else {
                            path_and_query.push('?');
                        }
                        path_and_query.push_str("x_padding=");
                        path_and_query.push_str(&x_padding);

                        let referer =
                            format!("https://{}{}?x_padding={}", host, path, x_padding);

                        let uri = match http::Uri::builder()
                            .scheme("https")
                            .authority(host.as_str())
                            .path_and_query(path_and_query.as_str())
                            .build()
                        {
                            Ok(uri) => uri,
                            Err(e) => {
                                error!("xhttp packet build uri error: {e}");
                                continue;
                            }
                        };

                        let mut request = Request::builder()
                            .uri(uri)
                            .method(http::Method::POST)
                            .version(http::Version::HTTP_2);

                        let has_user_agent = headers
                            .keys()
                            .any(|k| k.eq_ignore_ascii_case("user-agent"));
                        let has_content_type = headers
                            .keys()
                            .any(|k| k.eq_ignore_ascii_case("content-type"));

                        for (k, v) in headers.iter() {
                            if k.eq_ignore_ascii_case("host")
                                || k.eq_ignore_ascii_case("referer")
                            {
                                continue;
                            }
                            request = request.header(k, v);
                        }

                        request = request
                            .header(http::header::HOST, host.as_str())
                            .header(http::header::REFERER, referer)
                            .header("Accept-Encoding", "gzip")
                            .header(http::header::CONTENT_LENGTH, chunk.len());

                        if !has_user_agent {
                            request = request.header(
                                http::header::USER_AGENT,
                                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                            );
                        }
                        if !has_content_type {
                            request = request.header(
                                http::header::CONTENT_TYPE,
                                "application/grpc",
                            );
                        }

                        let req = match request.body(()) {
                            Ok(req) => req,
                            Err(e) => {
                                error!("xhttp packet build request error: {e}");
                                continue;
                            }
                        };

                        let (resp, mut send_stream) = match client
                            .send_request(req, false)
                        {
                            Ok(rv) => rv,
                            Err(e) => {
                                error!("xhttp packet send_request error: {e}");
                                continue;
                            }
                        };

                        if let Err(e) = send_stream.send_data(chunk, true) {
                            error!("xhttp packet send_data error: {e}");
                            continue;
                        }

                        tokio::spawn(async move {
                            match resp.await {
                                Ok(resp) if resp.status() == StatusCode::OK => {}
                                Ok(resp) => {
                                    error!(
                                        "xhttp packet unexpected response status: {}",
                                        resp.status()
                                    );
                                }
                                Err(e) => {
                                    error!("xhttp packet response error: {e}");
                                }
                            }
                        });
                    }
                });

                Ok(Box::new(XHttpPacketStream::new(recv_stream, upload_tx)))
            }
        }
    }
}

pub struct XHttpStream {
    recv: RecvStream,
    send: SendStream<Bytes>,
    buffer: BytesMut,
    shutdown_sent: bool,
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
            shutdown_sent: false,
        }
    }
}

pub struct XHttpPacketStream {
    recv: RecvStream,
    upload: mpsc::Sender<Bytes>,
    buffer: BytesMut,
    future_write: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
}

impl Debug for XHttpPacketStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XHttpPacketStream")
            .field("recv", &self.recv)
            .field("buffer", &self.buffer)
            .finish()
    }
}

impl XHttpPacketStream {
    pub fn new(recv: RecvStream, upload: mpsc::Sender<Bytes>) -> Self {
        Self {
            recv,
            upload,
            buffer: BytesMut::with_capacity(1024 * 4),
            future_write: None,
        }
    }
}

impl AsyncRead for XHttpPacketStream {
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

impl AsyncWrite for XHttpPacketStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        if self.future_write.is_none() {
            let upload = self.upload.clone();
            let chunk = Bytes::copy_from_slice(buf);
            self.future_write = Some(Box::pin(async move {
                upload
                    .send(chunk)
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe"))
            }));
        }

        let future = self
            .future_write
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "future write not set"))?;
        std::task::ready!(Pin::new(future).poll(cx))?;
        self.future_write = None;
        std::task::Poll::Ready(Ok(buf.len()))
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
        // Signal EOF to the packet sender.
        if self.future_write.is_none() {
            let upload = self.upload.clone();
            self.future_write = Some(Box::pin(async move {
                upload.send(Bytes::new()).await.map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe")
                })
            }));
        }
        let future = self
            .future_write
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "future write not set"))?;
        std::task::ready!(Pin::new(future).poll(cx))?;
        self.future_write = None;
        std::task::Poll::Ready(Ok(()))
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
            Some(Ok(to_write)) => {
                let to_write = std::cmp::min(to_write, buf.len());
                self.send
                    .send_data(Bytes::from(buf[..to_write].to_owned()), false)
                    .map_or_else(
                        |e| {
                            Err(std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                e,
                            ))
                        },
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

#[cfg(test)]
mod tests {
    use super::{Client as XHttpClient, Transport};
    use bytes::{Bytes, BytesMut};
    use futures::future::poll_fn;
    use h2::RecvStream;
    use http::Response;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};
    use uuid::Uuid;

    use crate::proxy::AnyStream;

    #[derive(Debug)]
    struct CapturedRequest {
        method: http::Method,
        path_and_query: String,
        headers: http::HeaderMap,
        body: Vec<u8>,
    }

    async fn read_h2_body(mut body: RecvStream) -> Vec<u8> {
        let mut out = BytesMut::new();
        while let Some(chunk) = poll_fn(|cx| body.poll_data(cx)).await {
            let chunk = chunk.expect("body chunk");
            out.extend_from_slice(&chunk);
            body.flow_control()
                .release_capacity(chunk.len())
                .expect("release capacity");
        }
        out.to_vec()
    }

    async fn start_h2_server(
        expected_requests: usize,
        respond_body: fn(&http::Method) -> Option<Bytes>,
    ) -> (SocketAddr, mpsc::Receiver<CapturedRequest>) {
        let (addr_tx, addr_rx) = oneshot::channel();
        let (req_tx, req_rx) = mpsc::channel::<CapturedRequest>(expected_requests);

        tokio::spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local addr");
            addr_tx.send(addr).ok();

            let (socket, _) = listener.accept().await.expect("accept");
            let mut conn = h2::server::handshake(socket).await.expect("h2 handshake");

            let mut accepted = 0usize;
            while let Some(result) = conn.accept().await {
                let (req, mut respond) = match result {
                    Ok(rv) => rv,
                    Err(_) => continue,
                };

                if accepted >= expected_requests {
                    continue;
                }
                accepted += 1;

                let req_tx = req_tx.clone();
                tokio::spawn(async move {
                    let (parts, body) = req.into_parts();

                    let method = parts.method;
                    let uri = parts.uri;
                    let headers = parts.headers;
                    let path_and_query = uri
                        .path_and_query()
                        .expect("path and query")
                        .as_str()
                        .to_owned();

                    let body_to_send = respond_body(&method);
                    let end_of_stream = body_to_send.is_none();
                    let response = Response::builder()
                        .status(200)
                        .body(())
                        .expect("build response");
                    let mut send = respond
                        .send_response(response, end_of_stream)
                        .expect("send response");
                    if let Some(bytes) = body_to_send {
                        send.send_data(bytes, true).expect("send data");
                    }

                    let body = read_h2_body(body).await;
                    req_tx
                        .send(CapturedRequest {
                            method,
                            path_and_query,
                            headers,
                            body,
                        })
                        .await
                        .expect("send captured request");
                });
            }
        });

        let addr = addr_rx.await.expect("server addr");
        (addr, req_rx)
    }

    async fn recv_req(rx: &mut mpsc::Receiver<CapturedRequest>) -> CapturedRequest {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout waiting for request")
            .expect("request channel closed")
    }

    fn extract_path_only(path_and_query: &str) -> &str {
        path_and_query
            .split_once('?')
            .map(|(p, _)| p)
            .unwrap_or(path_and_query)
    }

    fn extract_x_padding(path_and_query: &str) -> String {
        let query = path_and_query
            .split_once('?')
            .map(|(_, q)| q)
            .unwrap_or_default();
        query
            .split('&')
            .find_map(|kv| kv.strip_prefix("x_padding="))
            .expect("x_padding not found")
            .to_owned()
    }

    fn extract_x_padding_from_referer(referer: &str) -> String {
        referer
            .split_once("?x_padding=")
            .map(|(_, p)| p)
            .expect("referer missing x_padding")
            .to_owned()
    }

    fn assert_padding(path_and_query: &str, headers: &http::HeaderMap) {
        let qp = extract_x_padding(path_and_query);
        assert!(
            (100..=1000).contains(&qp.len()),
            "unexpected x_padding length: {}",
            qp.len()
        );
        assert!(qp.chars().all(|c| c == 'X'), "x_padding not all X");

        let referer = headers
            .get(http::header::REFERER)
            .expect("missing Referer")
            .to_str()
            .expect("referer utf-8");
        let rp = extract_x_padding_from_referer(referer);
        assert_eq!(qp, rp, "x_padding mismatch between uri and referer");
    }

    #[tokio::test]
    async fn xhttp_stream_one_sends_post_and_reads_response() {
        fn respond_body(method: &http::Method) -> Option<Bytes> {
            (method == http::Method::POST).then(|| Bytes::from_static(b"DOWN"))
        }
        let (addr, mut rx) = start_h2_server(1, respond_body).await;

        let path: http::uri::PathAndQuery = "/xhttp/?foo=bar".try_into().unwrap();
        let client = XHttpClient::new(
            "example.com".to_owned(),
            HashMap::new(),
            Some("stream-one".to_owned()),
            path,
        );

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            client.proxy_stream(Box::new(tcp) as AnyStream),
        )
        .await
        .expect("timeout waiting for xhttp stream-one connect")
        .unwrap();

        tokio::time::timeout(Duration::from_secs(5), stream.write_all(b"PING"))
            .await
            .expect("timeout writing PING")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), stream.shutdown())
            .await
            .expect("timeout shutting down stream")
            .unwrap();

        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
            .await
            .expect("timeout reading response")
            .unwrap();
        assert_eq!(out, b"DOWN");

        let req = recv_req(&mut rx).await;
        assert_eq!(req.method, http::Method::POST);
        assert!(req.path_and_query.starts_with("/xhttp/?foo=bar&x_padding="));
        assert_padding(&req.path_and_query, &req.headers);
        assert_eq!(req.body, b"PING");
    }

    #[tokio::test]
    async fn xhttp_stream_up_sends_get_then_post_with_same_session() {
        fn respond_body(method: &http::Method) -> Option<Bytes> {
            (method == http::Method::GET).then(|| Bytes::from_static(b"DOWN"))
        }
        let (addr, mut rx) = start_h2_server(2, respond_body).await;

        let path: http::uri::PathAndQuery = "/xhttp/?foo=bar".try_into().unwrap();
        let client = XHttpClient::new(
            "example.com".to_owned(),
            HashMap::new(),
            Some("stream".to_owned()),
            path,
        );

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            client.proxy_stream(Box::new(tcp) as AnyStream),
        )
        .await
        .expect("timeout waiting for xhttp stream-up connect")
        .unwrap();

        tokio::time::timeout(Duration::from_secs(5), stream.write_all(b"PING"))
            .await
            .expect("timeout writing PING")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), stream.shutdown())
            .await
            .expect("timeout shutting down stream")
            .unwrap();

        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
            .await
            .expect("timeout reading response")
            .unwrap();
        assert_eq!(out, b"DOWN");

        let down = recv_req(&mut rx).await;
        assert_eq!(down.method, http::Method::GET);
        assert!(down.path_and_query.contains("foo=bar"));
        assert_padding(&down.path_and_query, &down.headers);

        let down_path = extract_path_only(&down.path_and_query);
        let uuid_str = down_path.rsplit('/').next().expect("uuid segment");
        let uuid = Uuid::parse_str(uuid_str).expect("uuid parse");

        let up = recv_req(&mut rx).await;
        assert_eq!(up.method, http::Method::POST);
        assert!(up.path_and_query.contains("foo=bar"));
        assert_padding(&up.path_and_query, &up.headers);
        assert_eq!(up.body, b"PING");

        let up_path = extract_path_only(&up.path_and_query);
        assert!(
            up_path.ends_with(uuid.to_string().as_str()),
            "upload path does not end with session uuid"
        );
    }

    #[tokio::test]
    async fn xhttp_packet_up_opens_post_packets_with_seq_paths() {
        fn respond_body(method: &http::Method) -> Option<Bytes> {
            (method == http::Method::GET).then(|| Bytes::from_static(b"DOWN"))
        }
        let (addr, mut rx) = start_h2_server(4, respond_body).await;

        let path: http::uri::PathAndQuery = "/xhttp/?foo=bar".try_into().unwrap();
        let client = XHttpClient::new(
            "example.com".to_owned(),
            HashMap::new(),
            Some("auto".to_owned()),
            path,
        );

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            client.proxy_stream(Box::new(tcp) as AnyStream),
        )
        .await
        .expect("timeout waiting for xhttp packet-up connect")
        .unwrap();

        tokio::time::timeout(Duration::from_secs(5), stream.write_all(b"A"))
            .await
            .expect("timeout writing A")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), stream.write_all(b"BB"))
            .await
            .expect("timeout writing BB")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), stream.write_all(b"CCC"))
            .await
            .expect("timeout writing CCC")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), stream.shutdown())
            .await
            .expect("timeout shutting down stream")
            .unwrap();

        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
            .await
            .expect("timeout reading response")
            .unwrap();
        assert_eq!(out, b"DOWN");

        let down = recv_req(&mut rx).await;
        assert_eq!(down.method, http::Method::GET);
        assert!(down.path_and_query.contains("foo=bar"));
        assert_padding(&down.path_and_query, &down.headers);

        let down_path = extract_path_only(&down.path_and_query);
        let uuid_str = down_path.rsplit('/').next().expect("uuid segment");
        let uuid = Uuid::parse_str(uuid_str).expect("uuid parse");

        for (seq, expected_body) in [(0u64, b"A".as_slice()), (1, b"BB"), (2, b"CCC")] {
            let up = recv_req(&mut rx).await;
            assert_eq!(up.method, http::Method::POST);
            assert!(up.path_and_query.contains("foo=bar"));
            assert_padding(&up.path_and_query, &up.headers);
            assert_eq!(up.body, expected_body);

            let content_len = up
                .headers
                .get(http::header::CONTENT_LENGTH)
                .expect("missing content-length")
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap();
            assert_eq!(content_len, expected_body.len());

            let up_path = extract_path_only(&up.path_and_query);
            let segments: Vec<_> = up_path.trim_start_matches('/').split('/').collect();
            assert_eq!(segments.len(), 3);
            assert_eq!(segments[0], "xhttp");
            assert_eq!(segments[1], uuid.to_string());
            assert_eq!(segments[2], seq.to_string());
        }
    }
}
