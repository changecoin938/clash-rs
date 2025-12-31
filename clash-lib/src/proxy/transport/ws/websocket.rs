use std::{
    fmt::Debug,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::{
    channel::{mpsc, oneshot},
    ready,
    Sink, SinkExt, Stream, StreamExt,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

use crate::proxy::AnyStream;

// Keep frames reasonably sized; large frames are more likely to trigger instability.
const MAX_WS_CHUNK_SIZE: usize = 16 * 1024; // 16KB
// Batch flush threshold in the driver to reduce overhead.
const FLUSH_THRESHOLD: usize = 64 * 1024; // 64KB

fn ws_err_to_io(err: impl std::fmt::Display) -> std::io::Error {
    let msg = err.to_string();
    if msg.contains("Sending after closing") {
        // treat as clean disconnect
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, msg)
    } else {
        std::io::Error::new(std::io::ErrorKind::Other, msg)
    }
}

fn clone_io_error(e: &std::io::Error) -> std::io::Error {
    std::io::Error::new(e.kind(), e.to_string())
}

enum WsCmd {
    Data(Bytes),
    Flush(oneshot::Sender<std::io::Result<()>>),
    Close(oneshot::Sender<std::io::Result<()>>),
}

pub struct WebsocketConn {
    write_tx: mpsc::Sender<WsCmd>,
    read_rx: mpsc::Receiver<std::io::Result<Bytes>>,
    read_buffer: BytesMut,
    pending_flush: Option<oneshot::Receiver<std::io::Result<()>>>,
    pending_close: Option<oneshot::Receiver<std::io::Result<()>>>,
    closed: bool,
    last_error: Arc<Mutex<Option<std::io::Error>>>,
}

impl Debug for WebsocketConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebsocketConn")
            .field("closed", &self.closed)
            .field("read_buffer_len", &self.read_buffer.len())
            .finish()
    }
}

impl WebsocketConn {
    pub fn from_websocket(stream: WebSocketStream<AnyStream>) -> Self {
        let (write_tx, write_rx) = mpsc::channel::<WsCmd>(256);
        let (read_tx, read_rx) = mpsc::channel::<std::io::Result<Bytes>>(256);
        let last_error: Arc<Mutex<Option<std::io::Error>>> = Arc::new(Mutex::new(None));

        Self::spawn_driver(stream, write_rx, read_tx, last_error.clone());

        Self {
            write_tx,
            read_rx,
            read_buffer: BytesMut::new(),
            pending_flush: None,
            pending_close: None,
            closed: false,
            last_error,
        }
    }

    fn take_error(&mut self) -> Option<std::io::Error> {
        self.last_error.lock().unwrap().take()
    }

    fn spawn_driver(
        stream: WebSocketStream<AnyStream>,
        mut write_rx: mpsc::Receiver<WsCmd>,
        mut read_tx: mpsc::Sender<std::io::Result<Bytes>>,
        last_error: Arc<Mutex<Option<std::io::Error>>>,
    ) {
        tokio::spawn(async move {
            let (mut sink, mut ws_stream) = stream.split();
            let mut pending_bytes: usize = 0;
            let mut closing = false;

            loop {
                tokio::select! {
                    biased;

                    // Always prioritize reading control frames so we can respond to Ping
                    // during write-heavy uploads.
                    msg = ws_stream.next(), if !closing => {
                        match msg {
                            None => break,
                            Some(Err(e)) => {
                                *last_error.lock().unwrap() = Some(ws_err_to_io(e));
                                break;
                            }
                            Some(Ok(Message::Ping(data))) => {
                                if let Err(e) = sink.send(Message::Pong(data)).await {
                                    *last_error.lock().unwrap() = Some(ws_err_to_io(e));
                                    break;
                                }
                            }
                            Some(Ok(Message::Pong(_))) => {}
                            Some(Ok(Message::Close(_))) => {
                                closing = true;
                                // best-effort close reply
                                let _ = sink.send(Message::Close(None)).await;
                                break;
                            }
                            Some(Ok(Message::Binary(data))) => {
                                if read_tx.send(Ok(data)).await.is_err() {
                                    break;
                                }
                            }
                            Some(Ok(_)) => {}
                        }
                    }

                    cmd = write_rx.next() => {
                        match cmd {
                            None => break,
                            Some(WsCmd::Data(bytes)) => {
                                if closing {
                                    *last_error.lock().unwrap() = Some(std::io::Error::new(
                                        std::io::ErrorKind::BrokenPipe,
                                        "websocket is closing",
                                    ));
                                    break;
                                }
                                if let Err(e) = sink.feed(Message::Binary(bytes.clone())).await {
                                    *last_error.lock().unwrap() = Some(ws_err_to_io(e));
                                    break;
                                }
                                pending_bytes = pending_bytes.saturating_add(bytes.len());
                                if pending_bytes >= FLUSH_THRESHOLD {
                                    if let Err(e) = sink.flush().await {
                                        *last_error.lock().unwrap() = Some(ws_err_to_io(e));
                                        break;
                                    }
                                    pending_bytes = 0;
                                }
                            }
                            Some(WsCmd::Flush(done)) => {
                                let res = sink.flush().await.map_err(ws_err_to_io);
                                if res.is_err() {
                                    *last_error.lock().unwrap() =
                                        Some(clone_io_error(res.as_ref().err().unwrap()));
                                }
                                pending_bytes = 0;
                                let _ = done.send(res);
                                if last_error.lock().unwrap().is_some() {
                                    break;
                                }
                            }
                            Some(WsCmd::Close(done)) => {
                                closing = true;
                                let _ = sink.flush().await;
                                let res = sink.send(Message::Close(None)).await.map_err(ws_err_to_io);
                                if res.is_err() {
                                    *last_error.lock().unwrap() =
                                        Some(clone_io_error(res.as_ref().err().unwrap()));
                                }
                                let _ = done.send(res);
                                break;
                            }
                        }
                    }
                }
            }

            // Close read side
            read_tx.close_channel();
        });
    }
}

impl AsyncRead for WebsocketConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(err) = self.take_error() {
            self.closed = true;
            return Poll::Ready(Err(err));
        }

        if !self.read_buffer.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.read_buffer.len());
            let chunk = self.read_buffer.split_to(to_read);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.read_rx).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(Some(Ok(bytes))) => {
                let to_read = std::cmp::min(buf.remaining(), bytes.len());
                buf.put_slice(&bytes[..to_read]);
                if to_read < bytes.len() {
                    self.read_buffer.extend_from_slice(&bytes[to_read..]);
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for WebsocketConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Some(err) = self.take_error() {
            self.closed = true;
            return Poll::Ready(Err(err));
        }
        if self.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "websocket closed",
            )));
        }

        let to_write = std::cmp::min(buf.len(), MAX_WS_CHUNK_SIZE);
        let data = Bytes::copy_from_slice(&buf[..to_write]);

        ready!(Pin::new(&mut self.write_tx).poll_ready(cx)).map_err(ws_err_to_io)?;
        Pin::new(&mut self.write_tx)
            .start_send(WsCmd::Data(data))
            .map_err(ws_err_to_io)?;

        Poll::Ready(Ok(to_write))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Some(err) = self.take_error() {
            self.closed = true;
            return Poll::Ready(Err(err));
        }
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        if let Some(rx) = self.pending_flush.as_mut() {
            match Pin::new(rx).poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(Ok(()))) => {
                    self.pending_flush = None;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Ok(Err(e))) => {
                    self.pending_flush = None;
                    self.closed = true;
                    Poll::Ready(Err(e))
                }
                Poll::Ready(Err(_)) => {
                    self.pending_flush = None;
                    self.closed = true;
                    Poll::Ready(Ok(()))
                }
            }
        } else {
            let (tx, rx) = oneshot::channel();
            ready!(Pin::new(&mut self.write_tx).poll_ready(cx)).map_err(ws_err_to_io)?;
            Pin::new(&mut self.write_tx)
                .start_send(WsCmd::Flush(tx))
                .map_err(ws_err_to_io)?;
            self.pending_flush = Some(rx);
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Some(err) = self.take_error() {
            self.closed = true;
            return Poll::Ready(Err(err));
        }
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        if let Some(rx) = self.pending_close.as_mut() {
            match Pin::new(rx).poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(Ok(()))) => {
                    self.pending_close = None;
                    self.closed = true;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Ok(Err(e))) => {
                    self.pending_close = None;
                    self.closed = true;
                    Poll::Ready(Err(e))
                }
                Poll::Ready(Err(_)) => {
                    self.pending_close = None;
                    self.closed = true;
                    Poll::Ready(Ok(()))
                }
            }
        } else {
            let (tx, rx) = oneshot::channel();
            ready!(Pin::new(&mut self.write_tx).poll_ready(cx)).map_err(ws_err_to_io)?;
            Pin::new(&mut self.write_tx)
                .start_send(WsCmd::Close(tx))
                .map_err(ws_err_to_io)?;
            self.pending_close = Some(rx);
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

<<<<<<< HEAD
use std::{fmt::Debug, pin::Pin, task::Poll};
=======
use std::{
    fmt::Debug,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
>>>>>>> d1d10b8 (WebSocket: driver task + channels to reliably handle Ping/Close during upload)

use bytes::{Bytes, BytesMut};
use futures::{
    channel::{mpsc, oneshot},
    ready,
    Sink, SinkExt, Stream, StreamExt,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

<<<<<<< HEAD
use crate::{
    common::errors::{map_io_error, new_io_error},
    proxy::AnyStream,
};
=======
use crate::proxy::AnyStream;

// Keep frames reasonably sized; large frames are more likely to trigger instability.
const MAX_WS_CHUNK_SIZE: usize = 16 * 1024; // 16KB
// Batch flush threshold in the driver to reduce overhead.
const FLUSH_THRESHOLD: usize = 64 * 1024; // 64KB

fn ws_err_to_io(err: impl std::fmt::Display) -> std::io::Error {
    let msg = err.to_string();
    if msg.contains("Sending after closing") {
        // treat as clean disconnect
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, msg)
    } else {
        std::io::Error::new(std::io::ErrorKind::Other, msg)
    }
}

fn clone_io_error(e: &std::io::Error) -> std::io::Error {
    std::io::Error::new(e.kind(), e.to_string())
}

enum WsCmd {
    Data(Bytes),
    Flush(oneshot::Sender<std::io::Result<()>>),
    Close(oneshot::Sender<std::io::Result<()>>),
}
>>>>>>> d1d10b8 (WebSocket: driver task + channels to reliably handle Ping/Close during upload)

pub struct WebsocketConn {
    write_tx: mpsc::Sender<WsCmd>,
    read_rx: mpsc::Receiver<std::io::Result<Bytes>>,
    read_buffer: BytesMut,
<<<<<<< HEAD
=======
    pending_flush: Option<oneshot::Receiver<std::io::Result<()>>>,
    pending_close: Option<oneshot::Receiver<std::io::Result<()>>>,
    closed: bool,
    last_error: Arc<Mutex<Option<std::io::Error>>>,
>>>>>>> d1d10b8 (WebSocket: driver task + channels to reliably handle Ping/Close during upload)
}

impl Debug for WebsocketConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebsocketConn")
            .field("closed", &self.closed)
            .field("read_buffer_len", &self.read_buffer.len())
            .finish()
    }
}

impl WebsocketConn {
    pub fn from_websocket(stream: WebSocketStream<AnyStream>) -> Self {
        let (write_tx, write_rx) = mpsc::channel::<WsCmd>(256);
        let (read_tx, read_rx) = mpsc::channel::<std::io::Result<Bytes>>(256);
        let last_error: Arc<Mutex<Option<std::io::Error>>> = Arc::new(Mutex::new(None));

        Self::spawn_driver(stream, write_rx, read_tx, last_error.clone());

        Self {
            write_tx,
            read_rx,
            read_buffer: BytesMut::new(),
<<<<<<< HEAD
        }
=======
            pending_flush: None,
            pending_close: None,
            closed: false,
            last_error,
        }
    }

    fn take_error(&mut self) -> Option<std::io::Error> {
        self.last_error.lock().unwrap().take()
    }

    fn spawn_driver(
        stream: WebSocketStream<AnyStream>,
        mut write_rx: mpsc::Receiver<WsCmd>,
        mut read_tx: mpsc::Sender<std::io::Result<Bytes>>,
        last_error: Arc<Mutex<Option<std::io::Error>>>,
    ) {
        tokio::spawn(async move {
            let (mut sink, mut ws_stream) = stream.split();
            let mut pending_bytes: usize = 0;
            let mut closing = false;

            loop {
                tokio::select! {
                    biased;

                    // Always prioritize reading control frames so we can respond to Ping
                    // during write-heavy uploads.
                    msg = ws_stream.next(), if !closing => {
                        match msg {
                            None => break,
                            Some(Err(e)) => {
                                *last_error.lock().unwrap() = Some(ws_err_to_io(e));
                                break;
                            }
                            Some(Ok(Message::Ping(data))) => {
                                if let Err(e) = sink.send(Message::Pong(data)).await {
                                    *last_error.lock().unwrap() = Some(ws_err_to_io(e));
                                    break;
                                }
                            }
                            Some(Ok(Message::Pong(_))) => {}
                            Some(Ok(Message::Close(_))) => {
                                closing = true;
                                // best-effort close reply
                                let _ = sink.send(Message::Close(None)).await;
                                break;
                            }
                            Some(Ok(Message::Binary(data))) => {
                                if read_tx.send(Ok(data)).await.is_err() {
                                    break;
                                }
                            }
                            Some(Ok(_)) => {}
                        }
                    }

                    cmd = write_rx.next() => {
                        match cmd {
                            None => break,
                            Some(WsCmd::Data(bytes)) => {
                                if closing {
                                    *last_error.lock().unwrap() = Some(std::io::Error::new(
                                        std::io::ErrorKind::BrokenPipe,
                                        "websocket is closing",
                                    ));
                                    break;
                                }
                                if let Err(e) = sink.feed(Message::Binary(bytes.clone())).await {
                                    *last_error.lock().unwrap() = Some(ws_err_to_io(e));
                                    break;
                                }
                                pending_bytes = pending_bytes.saturating_add(bytes.len());
                                if pending_bytes >= FLUSH_THRESHOLD {
                                    if let Err(e) = sink.flush().await {
                                        *last_error.lock().unwrap() = Some(ws_err_to_io(e));
                                        break;
                                    }
                                    pending_bytes = 0;
                                }
                            }
                            Some(WsCmd::Flush(done)) => {
                                let res = sink.flush().await.map_err(ws_err_to_io);
                                if res.is_err() {
                                    *last_error.lock().unwrap() =
                                        Some(clone_io_error(res.as_ref().err().unwrap()));
                                }
                                pending_bytes = 0;
                                let _ = done.send(res);
                                if last_error.lock().unwrap().is_some() {
                                    break;
                                }
                            }
                            Some(WsCmd::Close(done)) => {
                                closing = true;
                                let _ = sink.flush().await;
                                let res = sink.send(Message::Close(None)).await.map_err(ws_err_to_io);
                                if res.is_err() {
                                    *last_error.lock().unwrap() =
                                        Some(clone_io_error(res.as_ref().err().unwrap()));
                                }
                                let _ = done.send(res);
                                break;
                            }
                        }
                    }
                }
            }

            // Close read side
            read_tx.close_channel();
        });
>>>>>>> d1d10b8 (WebSocket: driver task + channels to reliably handle Ping/Close during upload)
    }
}

impl AsyncRead for WebsocketConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(err) = self.take_error() {
            self.closed = true;
            return Poll::Ready(Err(err));
        }
<<<<<<< HEAD
        Poll::Ready(ready!(Pin::new(&mut self.inner).poll_next(cx)).map_or(
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "ws broken pipe",
            )),
            |item| {
                item.map_or(
                    Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "ws broken pipe",
                    )),
                    |msg| match msg {
                        Message::Binary(data) => {
                            let to_read = std::cmp::min(buf.remaining(), data.len());
                            buf.put_slice(&data[..to_read]);
                            if to_read < data.len() {
                                self.read_buffer.extend_from_slice(&data[to_read..]);
                            }
                            Ok(())
                        }
                        Message::Close(_) => Ok(()),
                        _ => Err(new_io_error("ws invalid message type")),
                    },
                )
            },
        ))
=======

        if !self.read_buffer.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.read_buffer.len());
            let chunk = self.read_buffer.split_to(to_read);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.read_rx).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(Some(Ok(bytes))) => {
                let to_read = std::cmp::min(buf.remaining(), bytes.len());
                buf.put_slice(&bytes[..to_read]);
                if to_read < bytes.len() {
                    self.read_buffer.extend_from_slice(&bytes[to_read..]);
                }
                Poll::Ready(Ok(()))
            }
        }
>>>>>>> d1d10b8 (WebSocket: driver task + channels to reliably handle Ping/Close during upload)
    }
}

impl AsyncWrite for WebsocketConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
<<<<<<< HEAD
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        ready!(Pin::new(&mut self.inner).poll_ready(cx)).map_err(map_io_error)?;
        let message = Message::Binary(Bytes::copy_from_slice(buf));
        Pin::new(&mut self.inner)
            .start_send(message)
            .map_err(map_io_error)?;
        ready!(self.poll_flush(cx)?);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let Self { inner, .. } = self.get_mut();
        Pin::new(inner).poll_flush(cx).map_err(map_io_error)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let Self { inner, .. } = self.get_mut();
        let mut pin = Pin::new(inner);

        let message = Message::Close(None);
        #[allow(unused_must_use)]
        {
            pin.as_mut().start_send(message);
        }
        pin.poll_close(cx).map_err(map_io_error)
=======
    ) -> Poll<std::io::Result<usize>> {
        if let Some(err) = self.take_error() {
            self.closed = true;
            return Poll::Ready(Err(err));
        }
        if self.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "websocket closed",
            )));
        }

        let to_write = std::cmp::min(buf.len(), MAX_WS_CHUNK_SIZE);
        let data = Bytes::copy_from_slice(&buf[..to_write]);

        // Apply proper backpressure using Sink semantics.
        ready!(Pin::new(&mut self.write_tx).poll_ready(cx))
            .map_err(ws_err_to_io)?;
        Pin::new(&mut self.write_tx)
            .start_send(WsCmd::Data(data))
            .map_err(ws_err_to_io)?;

        Poll::Ready(Ok(to_write))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Some(err) = self.take_error() {
            self.closed = true;
            return Poll::Ready(Err(err));
        }
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        if let Some(rx) = self.pending_flush.as_mut() {
            match Pin::new(rx).poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(Ok(()))) => {
                    self.pending_flush = None;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Ok(Err(e))) => {
                    self.pending_flush = None;
                    self.closed = true;
                    Poll::Ready(Err(e))
                }
                Poll::Ready(Err(_)) => {
                    self.pending_flush = None;
                    self.closed = true;
                    Poll::Ready(Ok(()))
                }
            }
        } else {
            let (tx, rx) = oneshot::channel();
            ready!(Pin::new(&mut self.write_tx).poll_ready(cx))
                .map_err(ws_err_to_io)?;
            Pin::new(&mut self.write_tx)
                .start_send(WsCmd::Flush(tx))
                .map_err(ws_err_to_io)?;
            self.pending_flush = Some(rx);
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(err) = self.take_error() {
            self.closed = true;
            return Poll::Ready(Err(err));
        }
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        if let Some(rx) = self.pending_close.as_mut() {
            match Pin::new(rx).poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(Ok(()))) => {
                    self.pending_close = None;
                    self.closed = true;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Ok(Err(e))) => {
                    self.pending_close = None;
                    self.closed = true;
                    Poll::Ready(Err(e))
                }
                Poll::Ready(Err(_)) => {
                    self.pending_close = None;
                    self.closed = true;
                    Poll::Ready(Ok(()))
                }
            }
        } else {
            let (tx, rx) = oneshot::channel();
            ready!(Pin::new(&mut self.write_tx).poll_ready(cx))
                .map_err(ws_err_to_io)?;
            Pin::new(&mut self.write_tx)
                .start_send(WsCmd::Close(tx))
                .map_err(ws_err_to_io)?;
            self.pending_close = Some(rx);
            cx.waker().wake_by_ref();
            Poll::Pending
        }
>>>>>>> d1d10b8 (WebSocket: driver task + channels to reliably handle Ping/Close during upload)
    }
}
