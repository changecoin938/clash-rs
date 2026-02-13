use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::ready;
use h2::{RecvStream, SendStream};
use http::{Request, Uri, Version};
use prost::encoding::encode_varint;
use std::{
    fmt::Debug,
    future::Future,
    io,
    io::{Error, ErrorKind},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, mpsc},
};
use tracing::warn;

use super::Transport;
use crate::{common::errors::map_io_error, proxy::AnyStream};

const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
// NOTE: `0x7FFFFFFF` effectively disables HTTP/2 flow control and can cause
// severe bufferbloat / unfairness when many gRPC streams share a single
// connection (e.g. one large download starving other interactive streams).
//
// These sizes keep good throughput while preserving backpressure.
const GRPC_STREAM_WINDOW_SIZE: u32 = 2 * 1024 * 1024; // 2 MiB
const GRPC_CONNECTION_WINDOW_SIZE: u32 = 4 * 1024 * 1024; // 4 MiB
const GRPC_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrpcMode {
    Tun,
    TunMulti,
}

impl GrpcMode {
    fn from_opt(mode: Option<&str>) -> Self {
        match mode
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "multi" | "multimode" | "multi_mode" | "multi-mode" => Self::TunMulti,
            _ => Self::Tun,
        }
    }
}

#[derive(Debug, Clone)]
struct ParsedGrpcServiceName {
    service_name: String,
    tun_stream_name: String,
    tun_multi_stream_name: String,
}

fn is_go_path_segment_unescaped(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9')
        || matches!(b, b'-' | b'_' | b'.' | b'~')
        // Go's net/url.PathEscape (encodePathSegment) allows a small subset of
        // reserved characters unescaped.
        || matches!(b, b'$' | b'&' | b'+' | b':' | b'=' | b'@')
}

fn go_path_escape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if is_go_path_segment_unescaped(b) {
            out.push(b as char);
            continue;
        }

        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        out.push('%');
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

fn parse_grpc_service_name(raw: &str) -> ParsedGrpcServiceName {
    // Strip any query string; gRPC service names live in the path.
    let raw = raw.split_once('?').map(|(p, _)| p).unwrap_or(raw);

    // Normal old-school config: service name is a single segment (not starting with '/').
    if !raw.starts_with('/') {
        return ParsedGrpcServiceName {
            service_name: go_path_escape(raw),
            tun_stream_name: "Tun".to_owned(),
            tun_multi_stream_name: "TunMulti".to_owned(),
        };
    }

    // Custom path mode: `/service/name/tun|tunMulti` (server side) or
    // `/service/name/tunMulti` (client side multi only).
    let mut last_index = raw.rfind('/').unwrap_or(0);
    if last_index < 1 {
        last_index = 1;
    }

    let raw_service_name = &raw[1..last_index];
    let service_name = raw_service_name
        .split('/')
        .filter(|p| !p.is_empty())
        .map(go_path_escape)
        .collect::<Vec<_>>()
        .join("/");

    let ending_path = raw
        .rsplit_once('/')
        .map(|(_, end)| end)
        .unwrap_or_default();
    let stream_names: Vec<&str> = ending_path.split('|').collect();
    let tun_stream_name = go_path_escape(stream_names.first().copied().unwrap_or("Tun"));
    let tun_multi_stream_name = if stream_names.len() == 1 {
        // Client-side: service name is the full path to multi-tun.
        go_path_escape(stream_names.first().copied().unwrap_or("TunMulti"))
    } else {
        // Server-side: second part is the path to multi-tun.
        go_path_escape(stream_names.get(1).copied().unwrap_or("TunMulti"))
    };

    ParsedGrpcServiceName {
        service_name,
        tun_stream_name,
        tun_multi_stream_name,
    }
}

fn build_grpc_path(service_name: &str, mode: GrpcMode) -> String {
    let parsed = parse_grpc_service_name(service_name);
    let stream_name = match mode {
        GrpcMode::Tun => parsed.tun_stream_name,
        GrpcMode::TunMulti => parsed.tun_multi_stream_name,
    };

    if parsed.service_name.is_empty() {
        format!("//{stream_name}")
    } else {
        format!("/{}/{}", parsed.service_name, stream_name)
    }
}

#[derive(Clone)]
pub struct PooledClient {
    pub host: String,
    mode: GrpcMode,
    scheme: http::uri::Scheme,
    service_name: String,
    pool: Arc<Mutex<Option<h2::client::SendRequest<Bytes>>>>,
}

impl PooledClient {
    pub fn new(
        host: String,
        service_name: String,
        mode: Option<String>,
        use_tls: bool,
    ) -> Self {
        Self {
            host,
            mode: GrpcMode::from_opt(mode.as_deref()),
            scheme: if use_tls {
                http::uri::Scheme::HTTPS
            } else {
                http::uri::Scheme::HTTP
            },
            service_name,
            pool: Arc::new(Mutex::new(None)),
        }
    }

    fn req(&self) -> io::Result<Request<()>> {
        let path = build_grpc_path(&self.service_name, self.mode);
        let uri: Uri = Uri::builder()
            .scheme(self.scheme.clone())
            .authority(self.host.as_str())
            .path_and_query(path)
            .build()
            .map_err(map_io_error)?;

        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .version(Version::HTTP_2)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header(
                "user-agent",
                // Xray sets this to a Chrome-like UA by default for better
                // compatibility with some middleboxes.
                DEFAULT_USER_AGENT,
            );
        request.body(()).map_err(map_io_error)
    }

    async fn get_or_init_sender<C, Fut>(
        &self,
        connect: &C,
    ) -> io::Result<h2::client::SendRequest<Bytes>>
    where
        C: Fn() -> Fut,
        Fut: Future<Output = io::Result<AnyStream>> + Send,
    {
        let mut guard = self.pool.lock().await;
        if let Some(sender) = guard.as_ref() {
            return Ok(sender.clone());
        }

        let stream = connect().await?;
        let (sender, mut connection) = h2::client::Builder::new()
            .initial_connection_window_size(GRPC_CONNECTION_WINDOW_SIZE)
            .initial_window_size(GRPC_STREAM_WINDOW_SIZE)
            .initial_max_send_streams(1024)
            .enable_push(false)
            .handshake(stream)
            .await
            .map_err(map_io_error)?;

        let ping_pong = connection.ping_pong();
        let sender = sender.ready().await.map_err(map_io_error)?;

        let pool = self.pool.clone();
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                warn!("grpc pooled h2 got err:{:?}", e);
            }
            *pool.lock().await = None;
        });

        if let Some(mut ping_pong) = ping_pong {
            tokio::spawn(async move {
                // `interval.tick()` is immediate; skip the first tick.
                let mut interval = tokio::time::interval(GRPC_KEEPALIVE_INTERVAL);
                interval.tick().await;
                loop {
                    interval.tick().await;
                    if let Err(e) = ping_pong.ping(h2::Ping::opaque()).await {
                        warn!("grpc pooled h2 ping error: {e}");
                        break;
                    }
                }
            });
        }

        guard.replace(sender);
        Ok(guard.as_ref().unwrap().clone())
    }

    async fn invalidate_sender(&self) {
        *self.pool.lock().await = None;
    }

    pub async fn open_stream<C, Fut>(
        &self,
        connect: C,
    ) -> io::Result<AnyStream>
    where
        C: Fn() -> Fut,
        Fut: Future<Output = io::Result<AnyStream>> + Send,
    {
        let req = self.req()?;

        for attempt in 0..2 {
            let sender = self.get_or_init_sender(&connect).await?;
            let mut sender = sender.ready().await.map_err(map_io_error)?;

            match sender.send_request(req.clone(), false) {
                Ok((resp, send_stream)) => {
                    let (init_sender, init_ready) = mpsc::channel(1);
                    let recv_stream = Arc::new(Mutex::new(None));

                    let recv_stream_task = recv_stream.clone();
                    tokio::spawn(async move {
                        match resp.await {
                            Ok(resp) => {
                                if resp.status() != http::StatusCode::OK {
                                    warn!(
                                        "grpc handshake resp err: {:?}",
                                        resp.into_body().data().await
                                    );
                                } else {
                                    recv_stream_task
                                        .lock()
                                        .await
                                        .replace(resp.into_body());
                                }
                            }
                            Err(e) => {
                                warn!("grpc resp err: {:?}", e);
                            }
                        }
                        let _ = init_sender.send(()).await;
                    });

                    return Ok(Box::new(GrpcStream::new(
                        init_ready,
                        recv_stream,
                        send_stream,
                    )));
                }
                Err(e) => {
                    warn!("grpc send_request error: {e}");
                    self.invalidate_sender().await;
                    if attempt == 0 {
                        continue;
                    }
                    return Err(map_io_error(e));
                }
            }
        }

        Err(Error::new(ErrorKind::Other, "grpc open stream failed"))
    }
}

#[derive(Clone)]
pub struct Client {
    pub host: String,
    pub service_name: String,
    mode: GrpcMode,
    scheme: http::uri::Scheme,
}

impl Client {
    pub fn new(host: String, service_name: String) -> Self {
        Self {
            host,
            service_name,
            mode: GrpcMode::Tun,
            scheme: http::uri::Scheme::HTTPS,
        }
    }

    pub fn set_mode(&mut self, mode: Option<String>) {
        self.mode = GrpcMode::from_opt(mode.as_deref());
    }

    pub fn set_scheme(&mut self, use_tls: bool) {
        self.scheme = if use_tls {
            http::uri::Scheme::HTTPS
        } else {
            http::uri::Scheme::HTTP
        };
    }

    fn req(&self) -> io::Result<Request<()>> {
        let path = build_grpc_path(&self.service_name, self.mode);
        let uri: Uri = {
            Uri::builder()
                .scheme(self.scheme.clone())
                .authority(self.host.as_str())
                .path_and_query(path)
                .build()
                .map_err(map_io_error)?
        };
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .version(Version::HTTP_2)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("user-agent", DEFAULT_USER_AGENT);
        request.body(()).map_err(map_io_error)
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        let (client, h2) = h2::client::Builder::new()
            .initial_connection_window_size(GRPC_CONNECTION_WINDOW_SIZE)
            .initial_window_size(GRPC_STREAM_WINDOW_SIZE)
            .initial_max_send_streams(1024)
            .enable_push(false)
            .handshake(stream)
            .await
            .map_err(map_io_error)?;
        let mut client = client.ready().await.map_err(map_io_error)?;

        let req = self.req()?;
        let (resp, send_stream) =
            client.send_request(req, false).map_err(map_io_error)?;
        tokio::spawn(async move {
            if let Err(e) = h2.await {
                // TODO: collect this somewhere?
                warn!("http2 got err:{:?}", e);
            }
        });

        let (init_sender, init_ready) = mpsc::channel(1);
        let recv_stream = Arc::new(Mutex::new(None));

        {
            let recv_stream = recv_stream.clone();
            tokio::spawn(async move {
                match resp.await {
                    Ok(resp) => {
                        match resp.status() {
                            http::StatusCode::OK => {}
                            _ => {
                                warn!(
                                    "grpc handshake resp err: {:?}",
                                    resp.into_body().data().await
                                );
                                return;
                            }
                        }
                        let stream = resp.into_body();
                        recv_stream.lock().await.replace(stream);
                    }
                    Err(e) => {
                        warn!("grpc resp err: {:?}", e);
                    }
                }
                let _ = init_sender.send(()).await;
            });
        }

        Ok(Box::new(GrpcStream::new(
            init_ready,
            recv_stream,
            send_stream,
        )))
    }
}

pub struct GrpcStream {
    init_ready: mpsc::Receiver<()>,
    recv: Arc<Mutex<Option<RecvStream>>>,
    send: SendStream<Bytes>,
    raw_buffer: BytesMut,
    decoded_buffer: BytesMut,
    shutdown_sent: bool,
}

impl Debug for GrpcStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcStream")
            .field("send", &self.send)
            .field("raw_buffer", &self.raw_buffer)
            .field("decoded_buffer", &self.decoded_buffer)
            .finish()
    }
}

impl GrpcStream {
    const MAX_PAYLOAD_LEN: usize = 64 * 1024;
    const GRPC_HEADER_LEN: usize = 5;
    const PROTOBUF_TAG_LEN: usize = 1;
    const MIN_VARINT_LEN: usize = 1;
    const MIN_ENCODED_LEN: usize = Self::GRPC_HEADER_LEN
        + Self::PROTOBUF_TAG_LEN
        + Self::MIN_VARINT_LEN
        + 1;

    pub fn new(
        init_ready: mpsc::Receiver<()>,
        recv: Arc<Mutex<Option<RecvStream>>>,
        send: SendStream<Bytes>,
    ) -> Self {
        Self {
            init_ready,
            recv,
            send,
            raw_buffer: BytesMut::with_capacity(1024 * 4),
            decoded_buffer: BytesMut::with_capacity(1024 * 4),
            shutdown_sent: false,
        }
    }

    // encode data to grpc + protobuf format
    fn encode_buf(&self, data: &[u8]) -> Bytes {
        let mut protobuf_header = BytesMut::with_capacity(10 + 1);
        protobuf_header.put_u8(0x0a);
        encode_varint(data.len() as u64, &mut protobuf_header);
        let mut grpc_header = [0u8; 5];
        let grpc_payload_len = (protobuf_header.len() + data.len()) as u32;
        grpc_header[1..5].copy_from_slice(&grpc_payload_len.to_be_bytes());

        let mut buf = BytesMut::with_capacity(
            grpc_header.len() + protobuf_header.len() + data.len(),
        );
        buf.put_slice(&grpc_header[..]);
        buf.put_slice(&protobuf_header.freeze()[..]);
        buf.put_slice(data);
        buf.freeze()
    }

    fn varint_len(mut value: usize) -> usize {
        let mut len = 1;
        while value >= 0x80 {
            value >>= 7;
            len += 1;
        }
        len
    }

    fn encoded_len(payload_len: usize) -> usize {
        // 5 bytes gRPC header + 1 byte protobuf tag + varint(length) + payload.
        Self::GRPC_HEADER_LEN
            + Self::PROTOBUF_TAG_LEN
            + Self::varint_len(payload_len)
            + payload_len
    }

    fn max_payload_for_capacity(capacity: usize, requested: usize) -> usize {
        if requested == 0 || capacity < Self::MIN_ENCODED_LEN {
            return 0;
        }

        let requested = requested.min(Self::MAX_PAYLOAD_LEN);
        let mut payload =
            requested.min(capacity.saturating_sub(Self::MIN_ENCODED_LEN - 1));
        if payload == 0 {
            return 0;
        }

        for _ in 0..3 {
            let encoded_len = Self::encoded_len(payload);
            if encoded_len <= capacity {
                return payload;
            }

            let overhead = encoded_len.saturating_sub(payload);
            payload = capacity.saturating_sub(overhead).min(requested);
            if payload == 0 {
                return 0;
            }
        }

        0
    }

    fn decode_varint_from_slice(bytes: &[u8]) -> io::Result<(u64, usize)> {
        let mut value: u64 = 0;
        for i in 0..std::cmp::min(10, bytes.len()) {
            let byte = bytes[i];
            value |= u64::from(byte & 0x7F) << (i * 7);
            if byte & 0x80 == 0 {
                return Ok((value, i + 1));
            }
        }

        Err(Error::new(
            ErrorKind::InvalidData,
            "invalid protobuf varint",
        ))
    }

    fn decode_protobuf_bytes_fields(
        out: &mut BytesMut,
        mut message: &[u8],
    ) -> io::Result<()> {
        // Both Hunk and MultiHunk messages are encoded as one or more occurrences of:
        //   (tag=0x0a) + (len varint) + (bytes)
        while !message.is_empty() {
            if message[0] != 0x0a {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "invalid protobuf payload tag",
                ));
            }
            message = &message[1..];

            let (payload_len, varint_len) = Self::decode_varint_from_slice(message)?;
            let payload_len: usize = payload_len.try_into().map_err(|_| {
                Error::new(
                    ErrorKind::InvalidData,
                    "protobuf payload length overflow",
                )
            })?;

            let start = varint_len;
            let end = start.saturating_add(payload_len);
            if message.len() < end {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "grpc frame underflow",
                ));
            }

            out.extend_from_slice(&message[start..end]);
            message = &message[end..];
        }
        Ok(())
    }

    fn decode_frames(&mut self) -> io::Result<()> {
        loop {
            // gRPC frame header: 1 byte compression flag + 4 bytes message length (big endian)
            if self.raw_buffer.len() < 5 {
                return Ok(());
            }

            let msg_len = u32::from_be_bytes([
                self.raw_buffer[1],
                self.raw_buffer[2],
                self.raw_buffer[3],
                self.raw_buffer[4],
            ]) as usize;
            let frame_len = 5usize.saturating_add(msg_len);

            if self.raw_buffer.len() < frame_len {
                return Ok(());
            }

            let mut frame = self.raw_buffer.split_to(frame_len);

            let compression_flag = frame[0];
            if compression_flag != 0 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "grpc compressed frames are not supported",
                ));
            }

            frame.advance(5);
            if frame.is_empty() {
                continue;
            }

            Self::decode_protobuf_bytes_fields(&mut self.decoded_buffer, &frame)?;
        }
    }
}

impl AsyncRead for GrpcStream {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.init_ready.poll_recv(cx));

        if !self.decoded_buffer.is_empty() {
            let to_read =
                std::cmp::min(self.decoded_buffer.len(), buf.remaining());
            buf.put_slice(&self.decoded_buffer.split_to(to_read));
            return Poll::Ready(Ok(()));
        }

        let recv = self.recv.clone();

        let mut recv = match recv.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        if recv.is_none() {
            warn!("grpc initialization error");
            return Poll::Ready(Err(Error::new(
                ErrorKind::ConnectionReset,
                "initialization error",
            )));
        }

        match ready!(Pin::new(&mut recv.as_mut().unwrap()).poll_data(cx)) {
            Some(Ok(b)) => {
                self.raw_buffer.reserve(b.len());
                self.raw_buffer.extend_from_slice(&b[..]);

                self.decode_frames()?;

                if let Err(e) = recv
                    .as_mut()
                    .unwrap()
                    .flow_control()
                    .release_capacity(b.len())
                {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::ConnectionReset,
                        e,
                    )));
                }

                // We successfully consumed inbound bytes. If we managed to decode any payload,
                // return it immediately. Otherwise, schedule another poll to register the
                // waker with the underlying h2 stream.
                if !self.decoded_buffer.is_empty() {
                    let to_read =
                        std::cmp::min(self.decoded_buffer.len(), buf.remaining());
                    buf.put_slice(&self.decoded_buffer.split_to(to_read));
                    return Poll::Ready(Ok(()));
                }

                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Some(Err(e)) => Poll::Ready(Err(Error::new(
                ErrorKind::ConnectionReset,
                e,
            ))),
            _ => {
                if recv.as_mut().unwrap().is_end_stream() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let desired = buf.len().min(Self::MAX_PAYLOAD_LEN);
        loop {
            let capacity = self.send.capacity();
            let payload_len = Self::max_payload_for_capacity(capacity, desired);
            if payload_len > 0 {
                let encoded_buf = self.encode_buf(&buf[..payload_len]);
                return Poll::Ready(
                    self.send
                        .send_data(encoded_buf, false)
                        .map_or_else(
                            |e| {
                                warn!("grpc write error: {}", e);
                                Err(Error::new(ErrorKind::BrokenPipe, e))
                            },
                            |_| Ok(payload_len),
                        ),
                );
            }

            self.send
                .reserve_capacity(Self::encoded_len(desired.max(1)));

            match ready!(self.send.poll_capacity(cx)) {
                Some(Ok(_)) => {}
                Some(Err(e)) => {
                    warn!("grpc poll_capacity error: {}", e);
                    return Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, e)));
                }
                None => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::BrokenPipe,
                        "broken pipe",
                    )));
                }
            }
        }
    }

    #[inline]
    fn poll_flush(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.shutdown_sent {
            return Poll::Ready(Ok(()));
        }
        self.shutdown_sent = true;
        Poll::Ready(
            self.send
                .send_data(Bytes::new(), true)
                .map_err(|e| Error::new(ErrorKind::BrokenPipe, e)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn grpc_path_defaults_match_xray() {
        assert_eq!(build_grpc_path("", GrpcMode::Tun), "//Tun");
        assert_eq!(build_grpc_path("", GrpcMode::TunMulti), "//TunMulti");
        assert_eq!(build_grpc_path("example", GrpcMode::Tun), "/example/Tun");
        assert_eq!(
            build_grpc_path("example!", GrpcMode::TunMulti),
            "/example%21/TunMulti"
        );
    }

    #[test]
    fn protobuf_repeated_bytes_fields_are_concatenated() -> io::Result<()> {
        let mut msg = BytesMut::new();
        msg.extend_from_slice(&[0x0a, 0x03, b'a', b'b', b'c']);
        msg.extend_from_slice(&[0x0a, 0x02, b'd', b'e']);

        let mut out = BytesMut::new();
        GrpcStream::decode_protobuf_bytes_fields(&mut out, &msg)?;
        assert_eq!(&out[..], b"abcde");
        Ok(())
    }

    #[tokio::test]
    async fn pooled_client_reuses_single_h2_connection() -> io::Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;

        let accepted = Arc::new(AtomicUsize::new(0));
        let seen_paths: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        let accepted_task = accepted.clone();
        let seen_paths_task = seen_paths.clone();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            accepted_task.fetch_add(1, Ordering::SeqCst);

            let mut conn = h2::server::handshake(socket).await.map_err(map_io_error)?;
            for _ in 0..2 {
                let (req, mut respond) = conn
                    .accept()
                    .await
                    .ok_or_else(|| io::Error::other("h2 accept ended"))?
                    .map_err(map_io_error)?;
                seen_paths_task
                    .lock()
                    .await
                    .push(req.uri().path().to_owned());

                let response = http::Response::builder()
                    .status(http::StatusCode::OK)
                    .version(Version::HTTP_2)
                    .body(())
                    .map_err(map_io_error)?;
                respond.send_response(response, true).map_err(map_io_error)?;
            }

            Ok::<(), io::Error>(())
        });

        let authority = format!("127.0.0.1:{}", addr.port());
        let pool = PooledClient::new(authority.clone(), "".to_owned(), Some("multi".to_owned()), false);

        let dial_calls = Arc::new(AtomicUsize::new(0));
        for _ in 0..2 {
            let dial_calls = dial_calls.clone();
            let authority = authority.clone();
            let stream = pool
                .open_stream(move || {
                    dial_calls.fetch_add(1, Ordering::SeqCst);
                    let authority = authority.clone();
                    async move {
                        let tcp = TcpStream::connect(authority)
                            .await
                            .map_err(map_io_error)?;
                        Ok(Box::new(tcp) as AnyStream)
                    }
                })
                .await?;
            drop(stream);
        }

        server.await.map_err(map_io_error)??;

        assert_eq!(dial_calls.load(Ordering::SeqCst), 1);
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        assert_eq!(
            seen_paths.lock().await.as_slice(),
            ["//TunMulti", "//TunMulti"]
        );
        Ok(())
    }
}
