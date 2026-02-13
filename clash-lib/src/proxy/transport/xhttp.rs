use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::{future::poll_fn, ready};
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
use tracing::{error, warn};
use uuid::Uuid;

use super::Transport;
use crate::{common::errors::map_io_error, proxy::AnyStream};

// Keep flow-control enabled to avoid bufferbloat on shared HTTP/2 connections.
const XHTTP_STREAM_WINDOW_SIZE: u32 = 2 * 1024 * 1024; // 2 MiB
const XHTTP_CONNECTION_WINDOW_SIZE: u32 = 4 * 1024 * 1024; // 4 MiB
const XHTTP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

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
    packet_up_min_interval: Duration,
    packet_up_max_each_post_bytes: usize,
    packet_up_max_buffered_posts: usize,
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
            // Align with Xray SplitHTTP defaults:
            // - scMinPostsIntervalMs: 30ms
            // - scMaxEachPostBytes: 1_000_000 bytes
            // - scMaxBufferedPosts: 30
            packet_up_min_interval: Duration::from_millis(30),
            packet_up_max_each_post_bytes: 1_000_000,
            packet_up_max_buffered_posts: 30,
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
        let (mut client, mut h2) = h2::client::Builder::new()
            .initial_connection_window_size(XHTTP_CONNECTION_WINDOW_SIZE)
            .initial_window_size(XHTTP_STREAM_WINDOW_SIZE)
            .initial_max_send_streams(1024)
            .enable_push(false)
            .handshake(stream)
            .await
            .map_err(map_io_error)?;

        let ping_pong = h2.ping_pong();

        tokio::spawn(async move {
            if let Err(e) = h2.await {
                error!("xhttp h2 error: {}", e);
            }
        });

        if let Some(mut ping_pong) = ping_pong {
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(XHTTP_KEEPALIVE_INTERVAL);
                interval.tick().await;
                loop {
                    interval.tick().await;
                    if let Err(e) = ping_pong.ping(h2::Ping::opaque()).await {
                        warn!("xhttp h2 ping error: {e}");
                        break;
                    }
                }
            });
        }

        match self.mode {
            Mode::StreamOne => {
                let (path, query) = self.split_path_and_query();
                let req = self.build_request(
                    http::Method::POST,
                    &path,
                    query.as_deref(),
                    None,
                )?;
                client = client.ready().await.map_err(map_io_error)?;
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
                client = client.ready().await.map_err(map_io_error)?;
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
                client = client.ready().await.map_err(map_io_error)?;
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
                client = client.ready().await.map_err(map_io_error)?;
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

                let (upload_tx, mut upload_rx) = mpsc::channel::<Bytes>(
                    self.packet_up_max_buffered_posts,
                );

                let host = self.host.clone();
                let headers = self.headers.clone();
                let packet_up_min_interval = self.packet_up_min_interval;
                let max_each_post_bytes = self.packet_up_max_each_post_bytes;
                let base_path = self.path_with_segments(false, Some(&session_id), None);
                tokio::spawn(async move {
                    let mut client = client;
                    let mut seq: u64 = 0;
                    let mut flush_at = tokio::time::Instant::now();
                    let mut pending = BytesMut::with_capacity(32 * 1024);
                    let mut closing = false;

                    'packet_up: loop {
                        if closing && pending.is_empty() {
                            break;
                        }

                        tokio::select! {
                            chunk = upload_rx.recv(), if !closing => {
                                match chunk {
                                    Some(chunk) if chunk.is_empty() => {
                                        // EOF: flush whatever is pending immediately.
                                        closing = true;
                                        flush_at = tokio::time::Instant::now();
                                    }
                                    Some(chunk) => {
                                        // Enqueue data and let the timer / max_each_post_bytes decide batching.
                                        pending.extend_from_slice(&chunk);
                                    }
                                    None => {
                                        closing = true;
                                        flush_at = tokio::time::Instant::now();
                                    }
                                }
                            }
                            _ = tokio::time::sleep_until(flush_at), if !pending.is_empty() => {
                                let to_send_len = std::cmp::min(pending.len(), max_each_post_bytes);
                                let chunk = pending.split_to(to_send_len).freeze();

                                let path = format!("{}/{}", base_path, seq);
                                seq = seq.saturating_add(1);

                                // Build request (mirrors `build_request` but avoids borrowing `self`).
                                let padding_len: usize = rand::rng().random_range(100..=1000);
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
                                        flush_at = tokio::time::Instant::now()
                                            + if closing { Duration::from_millis(0) } else { packet_up_min_interval };
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
                                        break 'packet_up;
                                    }
                                };

                                client = match client.ready().await {
                                    Ok(client) => client,
                                    Err(e) => {
                                        error!("xhttp packet client ready error: {e}");
                                        break 'packet_up;
                                    }
                                };
                                let (resp, mut send_stream) = match client.send_request(req, false) {
                                    Ok(rv) => rv,
                                    Err(e) => {
                                        error!("xhttp packet send_request error: {e}");
                                        break 'packet_up;
                                    }
                                };

                                // Respect HTTP/2 flow control; `send_data` can fail when `chunk` is larger
                                // than the currently-available window. Split into DATA frames as needed.
                                let mut remaining = chunk;
                                while !remaining.is_empty() {
                                    send_stream.reserve_capacity(remaining.len());
                                    let capacity = match poll_fn(|cx| send_stream.poll_capacity(cx)).await {
                                        Some(Ok(capacity)) => capacity,
                                        Some(Err(e)) => {
                                            error!("xhttp packet poll_capacity error: {e}");
                                            break 'packet_up;
                                        }
                                        None => {
                                            error!("xhttp packet poll_capacity: broken pipe");
                                            break 'packet_up;
                                        }
                                    };
                                    if capacity == 0 {
                                        continue;
                                    }

                                    let to_write = std::cmp::min(capacity, remaining.len());
                                    let data = remaining.split_to(to_write);
                                    let end_stream = remaining.is_empty();
                                    if let Err(e) = send_stream.send_data(data, end_stream) {
                                        error!("xhttp packet send_data error: {e}");
                                        break 'packet_up;
                                    }
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

                                flush_at = tokio::time::Instant::now()
                                    + if closing { Duration::from_millis(0) } else { packet_up_min_interval };
                            }
                        }
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
    pending_release: usize,
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
            pending_release: 0,
            shutdown_sent: false,
        }
    }
}

pub struct XHttpPacketStream {
    recv: RecvStream,
    upload: mpsc::Sender<Bytes>,
    buffer: BytesMut,
    pending_release: usize,
    future_write: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
    shutdown_sent: bool,
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
            pending_release: 0,
            future_write: None,
            shutdown_sent: false,
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

impl AsyncWrite for XHttpPacketStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        if buf.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }
        if self.shutdown_sent {
            return std::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "xhttp packet stream is shut down",
            )));
        }
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
        loop {
            if let Some(future) = self.future_write.as_mut() {
                std::task::ready!(Pin::new(future).poll(cx))?;
                self.future_write = None;
                continue;
            }

            if self.shutdown_sent {
                return std::task::Poll::Ready(Ok(()));
            }

            self.shutdown_sent = true;
            let upload = self.upload.clone();
            self.future_write = Some(Box::pin(async move {
                upload.send(Bytes::new()).await.map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe")
                })
            }));
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

        let mut uploaded = Vec::new();
        let mut expected_seq: u64 = 0;
        while uploaded.len() < 6 {
            let up = recv_req(&mut rx).await;
            assert_eq!(up.method, http::Method::POST);
            assert!(up.path_and_query.contains("foo=bar"));
            assert_padding(&up.path_and_query, &up.headers);

            let content_len = up
                .headers
                .get(http::header::CONTENT_LENGTH)
                .expect("missing content-length")
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap();
            assert_eq!(content_len, up.body.len());

            let up_path = extract_path_only(&up.path_and_query);
            let segments: Vec<_> = up_path.trim_start_matches('/').split('/').collect();
            assert_eq!(segments.len(), 3);
            assert_eq!(segments[0], "xhttp");
            assert_eq!(segments[1], uuid.to_string());
            assert_eq!(segments[2], expected_seq.to_string());
            expected_seq = expected_seq.saturating_add(1);

            uploaded.extend_from_slice(&up.body);
        }
        assert_eq!(uploaded, b"ABBCCC");
    }

    #[tokio::test]
    async fn xhttp_packet_up_sends_large_payload() {
        fn respond_body(method: &http::Method) -> Option<Bytes> {
            (method == http::Method::GET).then(|| Bytes::from_static(b"DOWN"))
        }
        let (addr, mut rx) = start_h2_server(10, respond_body).await;

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

        // > 64KiB ensures the implementation respects HTTP/2 flow control and
        // does not rely on `send_data` accepting the full body in one go.
        let payload = vec![b'Z'; 150_000];
        tokio::time::timeout(Duration::from_secs(10), stream.write_all(&payload))
            .await
            .expect("timeout writing payload")
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

        let mut uploaded = Vec::new();
        let mut expected_seq: u64 = 0;
        while uploaded.len() < payload.len() {
            let up = recv_req(&mut rx).await;
            assert_eq!(up.method, http::Method::POST);
            assert!(up.path_and_query.contains("foo=bar"));
            assert_padding(&up.path_and_query, &up.headers);

            let content_len = up
                .headers
                .get(http::header::CONTENT_LENGTH)
                .expect("missing content-length")
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap();
            assert_eq!(content_len, up.body.len());

            let up_path = extract_path_only(&up.path_and_query);
            let segments: Vec<_> = up_path.trim_start_matches('/').split('/').collect();
            assert_eq!(segments.len(), 3);
            assert_eq!(segments[0], "xhttp");
            assert_eq!(segments[1], uuid.to_string());
            assert_eq!(segments[2], expected_seq.to_string());
            expected_seq = expected_seq.saturating_add(1);

            uploaded.extend_from_slice(&up.body);
        }

        assert_eq!(uploaded.len(), payload.len());
        assert_eq!(uploaded, payload);
    }
}
