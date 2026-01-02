use async_trait::async_trait;
use bytes::{ BytesMut};
use futures::ready;
use std::{collections::HashMap, fmt::Debug};
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use super::Transport;
use crate::{ proxy::AnyStream};

pub struct Client {
    pub host: String,
    pub path: http::uri::PathAndQuery,
}

impl Client {
    pub fn new(
        host: String,
        path: http::uri::PathAndQuery,
    ) -> Self {
        Self {
            host,
            path,
        }
    }
    fn make_request(
        &self,
        method: String,
        path: String,
        version: String,
        host:String,
    ) -> String {
        let mut headers: HashMap<String, String> = HashMap::new();
        let default_user_agent =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0";
        let default_accept =
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
        let default_accept_encoding = "gzip, deflate, br";
        let default_accept_language = "en-US,en;q=0.5";
        let default_connection = "keep-alive";
        let default_pragma = "no-cache";
        let mut header_string = "".to_string();
        let (key, value) = headers
            .remove_entry("Host")
            .unwrap_or(("Host".to_string(), host));
        header_string.push_str(format!("{}: {}\r\n", key, value).as_str());

        let (key, value) = headers
            .remove_entry("User-Agent")
            .unwrap_or(("User-Agent".to_string(), default_user_agent.to_string()));
        header_string.push_str(format!("{}: {}\r\n", key, value).as_str());

        let (key, value) = headers
            .remove_entry("Accept")
            .unwrap_or(("Accept".to_string(), default_accept.to_string()));
        header_string.push_str(format!("{}: {}\r\n", key, value).as_str());

        let (key, value) = headers.remove_entry("Accept-Language").unwrap_or((
            "Accept-Language".to_string(),
            default_accept_language.to_string(),
        ));
        header_string.push_str(format!("{}: {}\r\n", key, value).as_str());

        let (key, value) = headers.remove_entry("Accept-Encoding").unwrap_or((
            "Accept-Encoding".to_string(),
            default_accept_encoding.to_string(),
        ));
        header_string.push_str(format!("{}: {}\r\n", key, value).as_str());

        let (key, value) = headers
            .remove_entry("Connection")
            .unwrap_or(("Connection".to_string(), default_connection.to_string()));
        header_string.push_str(format!("{}: {}\r\n", key, value).as_str());

        let (key, value) = headers
            .remove_entry("Pragma")
            .unwrap_or(("Pragma".to_string(), default_pragma.to_string()));
        header_string.push_str(format!("{}: {}\r\n", key, value).as_str());

        for (key, value) in &headers {
            let header = format!("{}: {}\r\n", key, value);
            header_string.push_str(header.as_str());
        }

        let request = format!(
            "{} {} HTTP/{}\r\n{}\r\n",
            method, path, version, header_string
        );
        return request;
    }
    fn get_request(&self) -> String {
        let host = self.host.clone();
        let method = "GET".to_string();
        let path = self.path.clone().as_str().to_string();
        let version = "1.1".to_string();
        return self.make_request(method, path, version, host);
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        let mut http_request_header_buffer = BytesMut::new();
        let request = self.get_request();
        http_request_header_buffer.extend_from_slice(request.as_bytes());
        Ok(Box::new(TcpHttpStream::new(stream,http_request_header_buffer)))
    }
}
pub struct TcpHttpStream {
    connection: AnyStream,
    is_http_request_end: bool,
    is_http_response_end: bool,
    buffer: BytesMut,
    http_response_header_buffer: BytesMut,
    http_request_header_buffer: BytesMut,
}

impl Debug for TcpHttpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpHttpStream")
            .field("is_http_request_end", &self.is_http_request_end)
            .field("is_http_response_end", &self.is_http_response_end)
            .field("http_response_header_buffer", &self.http_response_header_buffer)
            .field("http_request_header_buffer", &self.http_request_header_buffer)
            .field("buffer", &self.buffer)
            .finish()
    }
}

impl TcpHttpStream {
    pub fn new(connection: AnyStream,http_request_header_buffer: BytesMut) -> Self {
        Self {
            connection,
            is_http_request_end: false,
            is_http_response_end: false,
            http_response_header_buffer: BytesMut::new(),
            http_request_header_buffer,
            buffer: BytesMut::with_capacity(1024 * 4),
        }
    }
}

impl AsyncRead for TcpHttpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {


        if !self.is_http_response_end {
            let mut data = [0u8; 8 * 1024].to_vec();
            let mut buffer = ReadBuf::new(&mut data);
            let result = ready!(Pin::new(&mut self.connection).poll_read(cx, &mut buffer));
            return match result {
                Ok(_) => {
                    let helper = [13u8, 10, 13, 10];
                    let found = find_subsequence(buffer.filled(), helper.as_ref());

                    let size = match found {
                        None => {
                            self.http_response_header_buffer
                                .extend_from_slice(buffer.filled());
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        Some(found) => found + 4,
                    };
                    let (response, data) = buffer.filled().split_at(size);
                    self.http_response_header_buffer.extend_from_slice(response);
                    self.buffer.extend_from_slice(data);
                    self.is_http_response_end = true;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Err(err) => Poll::Ready(Err(err)),
            };
        }
        if !self.buffer.is_empty() {
            let to_read = std::cmp::min(self.buffer.len(), buf.remaining());
            let data = self.buffer.split_to(to_read);
            buf.put_slice(&data[..to_read]);
            return std::task::Poll::Ready(Ok(()));
        }

        let result = ready!(Pin::new(&mut self.connection).poll_read(cx, buf));
        match result {
            Ok(_) => Poll::Ready(Ok(())),
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl AsyncWrite for TcpHttpStream {

    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        if !self.is_http_request_end {
            let request = self.http_request_header_buffer.as_ref().to_vec();
            let result = ready!(Pin::new(&mut self.connection).poll_write(cx, request.as_slice()));
            match result {
                Ok(size) => {
                    let _ = self.http_request_header_buffer.split_to(size);
                    if self.http_request_header_buffer.is_empty() {
                        self.is_http_request_end = true;
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Err(err) => {
                    return Poll::Ready(Err(err));
                }
            }
        }

        let result = ready!(Pin::new(&mut self.connection).poll_write(cx, buf));
        return match result {
            Ok(_size) => Poll::Ready(Ok(buf.len())),
            Err(err) => Poll::Ready(Err(err)),
        };
    }
    
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        return Pin::new(&mut self.connection).poll_flush(cx);
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        return Pin::new(&mut self.connection).poll_shutdown(cx);
    }
}


fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
