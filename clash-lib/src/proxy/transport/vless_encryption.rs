use async_trait::async_trait;
use base64::Engine as _;
use bytes::{Buf, BytesMut};
use std::{collections::VecDeque, io, pin::Pin, sync::Arc, task::Poll, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::poll_read_buf;

use super::Transport;
use crate::{common::errors::map_io_error, proxy::AnyStream};

/// VLESS post-quantum encryption ("mlkem768x25519plus").
///
/// This is compatible with Xray's VLESS Encryption implementation.
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    pub fn new(encryption: &str) -> io::Result<Self> {
        let cfg = ParsedConfig::parse(encryption)?;
        Ok(Self {
            inner: Arc::new(ClientInner::new(cfg)?),
        })
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        self.inner.handshake(stream).await
    }
}

#[derive(Clone, Debug)]
struct ParsedConfig {
    xor_mode: u32,
    seconds: u32,
    padding: String,
    nfs_public_keys: Vec<Vec<u8>>,
}

impl ParsedConfig {
    fn parse(encryption: &str) -> io::Result<Self> {
        if encryption.is_empty() || encryption.eq_ignore_ascii_case("none") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "encryption is empty/none",
            ));
        }

        let parts: Vec<&str> = encryption.split('.').collect();
        if parts.len() < 4 || parts[0] != "mlkem768x25519plus" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported vless encryption (expected mlkem768x25519plus.*)",
            ));
        }

        let xor_mode = match parts[1] {
            "native" => 0,
            "xorpub" => 1,
            "random" => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "xor mode random is not supported yet",
                ));
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported xor mode: {other}"),
                ));
            }
        };

        let seconds = match parts[2] {
            "0rtt" | "1rtt" => 1,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported rtt mode: {other}"),
                ));
            }
        };

        let mut padding_len = 0usize;
        for r in parts.iter().skip(3) {
            if r.len() < 20 {
                padding_len += r.len() + 1;
                continue;
            }

            let Ok(b) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(r)
            else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid base64 segment",
                ));
            };
            if b.len() != 32 && b.len() != 1184 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid key length (expected 32 or 1184 bytes)",
                ));
            }
        }

        // Strip `mlkem768x25519plus.<xor>.<rtt>.`
        let prefix_len = 27 + parts[2].len();
        if encryption.len() < prefix_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid encryption format",
            ));
        }
        let mut rest = encryption[prefix_len..].to_owned();

        let padding = if padding_len > 0 {
            let p = rest
                .get(..padding_len.saturating_sub(1))
                .unwrap_or_default()
                .to_owned();
            rest = rest.get(padding_len..).unwrap_or_default().to_owned();
            p
        } else {
            String::new()
        };

        let mut nfs_public_keys = Vec::new();
        for seg in rest.split('.').filter(|x| !x.is_empty()) {
            let b = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(seg)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            if b.len() != 32 && b.len() != 1184 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid key length (expected 32 or 1184 bytes)",
                ));
            }
            nfs_public_keys.push(b);
        }

        if nfs_public_keys.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing public key(s) in encryption config",
            ));
        }

        Ok(Self {
            xor_mode,
            seconds,
            padding,
            nfs_public_keys,
        })
    }
}

struct ClientInner {
    keys: Vec<Vec<u8>>,
    hash32s: Vec<[u8; 32]>,
    relays_length: usize,
    xor_mode: u32,
    padding_lens: Vec<[i32; 3]>,
    padding_gaps: Vec<[i32; 3]>,
}

impl ClientInner {
    fn new(cfg: ParsedConfig) -> io::Result<Self> {
        let mut relays_length = 0usize;
        let mut hash32s = Vec::with_capacity(cfg.nfs_public_keys.len());

        for k in cfg.nfs_public_keys.iter() {
            if k.len() == 32 {
                relays_length += 32 + 32;
            } else if k.len() == 1184 {
                relays_length += 1088 + 32;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid public key length (expected 32 or 1184 bytes)",
                ));
            }

            let h = blake3::hash(k);
            hash32s.push(*h.as_bytes());
        }
        relays_length = relays_length.saturating_sub(32);

        let (padding_lens, padding_gaps) = parse_padding(&cfg.padding)?;

        Ok(Self {
            keys: cfg.nfs_public_keys,
            hash32s,
            relays_length,
            xor_mode: cfg.xor_mode,
            padding_lens,
            padding_gaps,
        })
    }

    async fn handshake(&self, mut stream: AnyStream) -> io::Result<AnyStream> {
        use aws_lc_rs::{
            agreement,
            kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768},
            rand::SystemRandom,
        };
        use aes::cipher::StreamCipher;

        let rng = SystemRandom::new();

        // iv + relays
        let mut iv = [0u8; 16];
        crate::common::utils::rand_fill(&mut iv);

        let mut relays = vec![0u8; self.relays_length];
        let mut relays_cursor: &mut [u8] = relays.as_mut_slice();

        let mut nfs_key: Vec<u8> = Vec::new();
        let mut last_ctr: Option<ctr::Ctr128BE<aes::Aes256>> = None;

        for (idx, server_key_bytes) in self.keys.iter().enumerate() {
            let is_last = idx == self.keys.len() - 1;

            let mut key_share_len = 32usize;

            if server_key_bytes.len() == 32 {
                let server_pub =
                    agreement::UnparsedPublicKey::new(&agreement::X25519, server_key_bytes);

                let client_priv = agreement::EphemeralPrivateKey::generate(
                    &agreement::X25519,
                    &rng,
                )
                .map_err(map_io_error)?;
                let client_pub = client_priv.compute_public_key().map_err(map_io_error)?;
                relays_cursor[..32].copy_from_slice(client_pub.as_ref());

                nfs_key = agreement::agree_ephemeral(
                    client_priv,
                    &server_pub,
                    aws_lc_rs::error::Unspecified,
                    |km| Ok(km.to_vec()),
                )
                .map_err(map_io_error)?;
            } else {
                let server_pub =
                    EncapsulationKey::new(&ML_KEM_768, server_key_bytes)
                        .map_err(map_io_error)?;
                let (ciphertext, shared_secret) =
                    server_pub.encapsulate().map_err(map_io_error)?;
                relays_cursor[..1088].copy_from_slice(ciphertext.as_ref());
                key_share_len = 1088;
                nfs_key = shared_secret.as_ref().to_vec();
            }

            if self.xor_mode > 0 {
                let mut ctr = new_ctr(server_key_bytes, &iv);
                ctr.apply_keystream(&mut relays_cursor[..key_share_len]);
            }

            if let Some(ctr) = last_ctr.as_mut() {
                ctr.apply_keystream(&mut relays_cursor[..32]);
            }

            if is_last {
                break;
            }

            let mut ctr = new_ctr(&nfs_key, &iv);
            let mut next_hash = self.hash32s[idx + 1];
            ctr.apply_keystream(&mut next_hash);
            relays_cursor[key_share_len..key_share_len + 32]
                .copy_from_slice(&next_hash);
            last_ctr = Some(ctr);

            relays_cursor = &mut relays_cursor[key_share_len + 32..];
        }

        let mut nfs_aead = Aead::new(&iv, &nfs_key)?;

        // PFS key exchange (client -> server)
        let mlkem_decaps = DecapsulationKey::generate(&ML_KEM_768).map_err(map_io_error)?;
        let mlkem_pub = mlkem_decaps
            .encapsulation_key()
            .map_err(map_io_error)?
            .key_bytes()
            .map_err(map_io_error)?;

        let x25519_priv =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
                .map_err(map_io_error)?;
        let x25519_pub = x25519_priv.compute_public_key().map_err(map_io_error)?;

        let mut pfs_public_key = Vec::with_capacity(1184 + 32);
        pfs_public_key.extend_from_slice(mlkem_pub.as_ref());
        pfs_public_key.extend_from_slice(x25519_pub.as_ref());

        let pfs_cipher_len = pfs_public_key
            .len()
            .checked_add(16)
            .ok_or(io::Error::other("pfs public key too large"))?;
        let mut client_hello = Vec::new();
        client_hello.extend_from_slice(&iv);
        client_hello.extend_from_slice(&relays);

        client_hello.extend_from_slice(
            &nfs_aead.seal(&encode_length(pfs_cipher_len as u16), None, &[])?,
        );
        client_hello.extend_from_slice(
            &nfs_aead.seal(&pfs_public_key, None, &[])?,
        );

        // padding (client -> server)
        let (padding_length, _lens, _gaps) =
            create_padding(&self.padding_lens, &self.padding_gaps);
        if padding_length < 35 {
            return Err(io::Error::other(
                "invalid padding length generated (must be >= 35)",
            ));
        }
        let padding_plain_len = padding_length
            .checked_sub(34)
            .ok_or(io::Error::other("invalid padding length"))?;
        let padding_cipher_len = padding_plain_len + 16;
        client_hello.extend_from_slice(
            &nfs_aead.seal(&encode_length(padding_cipher_len as u16), None, &[])?,
        );
        client_hello.extend_from_slice(
            &nfs_aead.seal(&vec![0u8; padding_plain_len], None, &[])?,
        );

        tokio::io::AsyncWriteExt::write_all(&mut stream, &client_hello).await?;
        tokio::io::AsyncWriteExt::flush(&mut stream).await?;

        // Server PFS key exchange (server -> client)
        let mut server_pfs_cipher = vec![0u8; 1088 + 32 + 16];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut server_pfs_cipher)
            .await?;
        let server_pfs_plain =
            nfs_aead.open(&server_pfs_cipher, Some(&MAX_NONCE), &[])?;

        if server_pfs_plain.len() != 1088 + 32 {
            return Err(io::Error::other("invalid server pfs public key length"));
        }

        let pq_key = mlkem_decaps
            .decapsulate(Ciphertext::from(&server_pfs_plain[..1088]))
            .map_err(map_io_error)?;
        let peer_x25519_pub = agreement::UnparsedPublicKey::new(
            &agreement::X25519,
            &server_pfs_plain[1088..],
        );
        let x25519_key = agreement::agree_ephemeral(
            x25519_priv,
            &peer_x25519_pub,
            aws_lc_rs::error::Unspecified,
            |km| Ok(km.to_vec()),
        )
        .map_err(map_io_error)?;

        let mut pfs_key = Vec::with_capacity(64);
        pfs_key.extend_from_slice(pq_key.as_ref());
        pfs_key.extend_from_slice(&x25519_key);

        let mut united_key = Vec::with_capacity(pfs_key.len() + nfs_key.len());
        united_key.extend_from_slice(&pfs_key);
        united_key.extend_from_slice(&nfs_key);

        let out_aead = Aead::new(&pfs_public_key, &united_key)?;
        let mut in_aead = Aead::new(&server_pfs_plain, &united_key)?;

        // encrypted ticket
        let mut encrypted_ticket = [0u8; 32];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut encrypted_ticket)
            .await?;
        let ticket_plain = in_aead.open(&encrypted_ticket, None, &[])?;

        // server padding length
        let mut encrypted_len = [0u8; 18];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut encrypted_len).await?;
        let len_plain = in_aead.open(&encrypted_len, None, &[])?;
        if len_plain.len() != 2 {
            return Err(io::Error::other("invalid decrypted length"));
        }
        let peer_padding_len = decode_length(&len_plain) as usize;

        // keep the connection open, and delay reading the padding to support
        // slow server padding (same behavior as Xray).
        let wrapped = VlessEncryptionStream::new(
            stream,
            out_aead,
            in_aead,
            peer_padding_len,
        );

        // currently unused, but keep the value to prevent unused variable warning
        let _ = ticket_plain;

        Ok(Box::new(wrapped))
    }
}

struct VlessEncryptionStream {
    inner: AnyStream,
    out_aead: Aead,
    in_aead: Aead,
    peer_padding_cipher_len: usize,

    raw_buf: BytesMut,
    read_buf: BytesMut,
    write_buf: BytesMut,
    pending_plain_len: usize,
}

impl VlessEncryptionStream {
    fn new(
        inner: AnyStream,
        out_aead: Aead,
        in_aead: Aead,
        peer_padding_len: usize,
    ) -> Self {
        Self {
            inner,
            out_aead,
            in_aead,
            peer_padding_cipher_len: peer_padding_len,
            raw_buf: BytesMut::with_capacity(8192),
            read_buf: BytesMut::with_capacity(8192),
            write_buf: BytesMut::new(),
            pending_plain_len: 0,
        }
    }

    fn poll_read_more(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<usize>> {
        poll_read_buf(Pin::new(&mut self.inner), cx, &mut self.raw_buf)
    }
}

impl AsyncRead for VlessEncryptionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.read_buf.is_empty() {
            let to_read = std::cmp::min(this.read_buf.len(), buf.remaining());
            buf.put_slice(&this.read_buf.split_to(to_read));
            return Poll::Ready(Ok(()));
        }

        loop {
            if this.peer_padding_cipher_len > 0 {
                if this.raw_buf.len() < this.peer_padding_cipher_len {
                    match this.poll_read_more(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "unexpected eof while reading peer padding",
                            )));
                        }
                        Poll::Ready(Ok(_)) => continue,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    }
                }

                let cipher_len = this.peer_padding_cipher_len;
                let cipher = this.raw_buf.split_to(cipher_len);
                let _ = this.in_aead.open(&cipher, None, &[])?;
                this.peer_padding_cipher_len = 0;
                continue;
            }

            if this.raw_buf.len() < 5 {
                match this.poll_read_more(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(0)) => {
                        if this.raw_buf.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unexpected eof while reading record header",
                        )));
                    }
                    Poll::Ready(Ok(_)) => continue,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
            }

            let mut header = [0u8; 5];
            header.copy_from_slice(&this.raw_buf[..5]);
            let body_len = decode_header_len(&header)?;
            let total = 5 + body_len;

            if this.raw_buf.len() < total {
                match this.poll_read_more(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unexpected eof while reading record body",
                        )));
                    }
                    Poll::Ready(Ok(_)) => continue,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
            }

            let _ = this.raw_buf.split_to(5);
            let cipher = this.raw_buf.split_to(body_len);
            let plain = this.in_aead.open(&cipher, None, &header)?;
            this.read_buf.extend_from_slice(&plain);

            break;
        }

        let to_read = std::cmp::min(this.read_buf.len(), buf.remaining());
        buf.put_slice(&this.read_buf.split_to(to_read));
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for VlessEncryptionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        loop {
            while !this.write_buf.is_empty() {
                let pending_buf: &[u8] = &this.write_buf;
                match Pin::new(&mut this.inner).poll_write(cx, pending_buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero",
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        this.write_buf.advance(n);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
            }

            if this.pending_plain_len > 0 {
                let n = this.pending_plain_len;
                this.pending_plain_len = 0;
                return Poll::Ready(Ok(n));
            }

            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }

            let to_consume = std::cmp::min(buf.len(), 8192);
            let payload = &buf[..to_consume];

            let record_len = payload
                .len()
                .checked_add(16)
                .ok_or(io::Error::other("payload too large"))?;

            let header = encode_header(record_len)?;
            let cipher = this.out_aead.seal(payload, None, &header)?;

            this.write_buf.reserve(5 + cipher.len());
            this.write_buf.extend_from_slice(&header);
            this.write_buf.extend_from_slice(&cipher);
            this.pending_plain_len = to_consume;
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        while !this.write_buf.is_empty() {
            let pending_buf: &[u8] = &this.write_buf;
            match Pin::new(&mut this.inner).poll_write(cx, pending_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

// --- Encoding helpers ---

fn encode_length(l: u16) -> [u8; 2] {
    l.to_be_bytes()
}

fn decode_length(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn encode_header(l: usize) -> io::Result<[u8; 5]> {
    if l > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "record too large",
        ));
    }
    let len = l as u16;
    Ok([0x17, 0x03, 0x03, (len >> 8) as u8, len as u8])
}

fn decode_header_len(h: &[u8; 5]) -> io::Result<usize> {
    let mut l = u16::from_be_bytes([h[3], h[4]]) as usize;
    if h[0] != 0x17 || h[1] != 0x03 || h[2] != 0x03 {
        l = 0;
    }
    if l < 17 || l > 17000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid header: {h:?}"),
        ));
    }
    Ok(l)
}

// --- Padding parsing ---

fn parse_padding(padding: &str) -> io::Result<(Vec<[i32; 3]>, Vec<[i32; 3]>)> {
    if padding.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut padding_lens = Vec::new();
    let mut padding_gaps = Vec::new();
    let mut max_len = 0i32;

    for (idx, seg) in padding.split('.').enumerate() {
        let parts: Vec<&str> = seg.split('-').collect();
        if parts.len() < 3 || parts.iter().any(|p| p.is_empty()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid padding parameter: {seg}"),
            ));
        }
        let chance: i32 = parts[0].parse().map_err(map_io_error)?;
        let min: i32 = parts[1].parse().map_err(map_io_error)?;
        let max: i32 = parts[2].parse().map_err(map_io_error)?;

        if idx == 0 && (chance < 100 || min < 35 || max < 35) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "first padding length must not be smaller than 35",
            ));
        }

        let entry = [chance, min, max];
        if idx % 2 == 0 {
            padding_lens.push(entry);
            max_len += std::cmp::max(min, max);
        } else {
            padding_gaps.push(entry);
        }
    }

    if max_len as usize > 18 + 65535 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "total padding length must not be larger than 65553",
        ));
    }

    Ok((padding_lens, padding_gaps))
}

fn create_padding(
    padding_lens: &[[i32; 3]],
    padding_gaps: &[[i32; 3]],
) -> (usize, Vec<usize>, Vec<Duration>) {
    use rand::Rng;

    let (lens_cfg, gaps_cfg);
    let mut lens_cfg_ref = padding_lens;
    let mut gaps_cfg_ref = padding_gaps;

    if lens_cfg_ref.is_empty() {
        lens_cfg = vec![[100, 111, 1111], [50, 0, 3333]];
        gaps_cfg = vec![[75, 0, 111]];
        lens_cfg_ref = &lens_cfg;
        gaps_cfg_ref = &gaps_cfg;
    }

    let mut rng = rand::rng();
    let mut total = 0usize;
    let mut lens = Vec::with_capacity(lens_cfg_ref.len());
    let mut gaps = Vec::with_capacity(gaps_cfg_ref.len());

    for [chance, from, to] in lens_cfg_ref.iter().copied() {
        let mut l = 0usize;
        if chance >= rng.random_range(0..100) {
            let (from, to) = if from <= to { (from, to) } else { (to, from) };
            l = if from == to {
                from as usize
            } else {
                rng.random_range(from..to) as usize
            };
        }
        lens.push(l);
        total += l;
    }

    for [chance, from, to] in gaps_cfg_ref.iter().copied() {
        let mut g = 0usize;
        if chance >= rng.random_range(0..100) {
            let (from, to) = if from <= to { (from, to) } else { (to, from) };
            g = if from == to {
                from as usize
            } else {
                rng.random_range(from..to) as usize
            };
        }
        gaps.push(Duration::from_millis(g as u64));
    }

    (total, lens, gaps)
}

// --- CTR ---

fn new_ctr(key: &[u8], iv: &[u8; 16]) -> ctr::Ctr128BE<aes::Aes256> {
    use aes::cipher::{KeyIvInit, StreamCipher};
    let k = derive_key_bytes_context(b"VLESS", key);
    let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new((&k).into(), iv.into());
    // ensure the cipher is initialized (no-op)
    cipher.apply_keystream(&mut []);
    cipher
}

// --- AEAD ---

const MAX_NONCE: [u8; 12] = [0xff; 12];

struct Aead {
    cipher: aes_gcm::Aes256Gcm,
    nonce: [u8; 12],
}

impl Aead {
    fn new(ctx: &[u8], key_material: &[u8]) -> io::Result<Self> {
        use aes_gcm::aead::KeyInit;
        let key = derive_key_bytes_context(ctx, key_material);
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Ok(Self {
            cipher,
            nonce: [0u8; 12],
        })
    }

    fn seal(
        &mut self,
        plaintext: &[u8],
        nonce: Option<&[u8; 12]>,
        aad: &[u8],
    ) -> io::Result<Vec<u8>> {
        use aes_gcm::aead::Aead;
        let nonce_bytes = match nonce {
            Some(n) => *n,
            None => {
                increase_nonce(&mut self.nonce);
                self.nonce
            }
        };
        let payload = aes_gcm::aead::Payload { msg: plaintext, aad };
        self.cipher
            .encrypt(aes_gcm::Nonce::from_slice(&nonce_bytes), payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn open(
        &mut self,
        ciphertext: &[u8],
        nonce: Option<&[u8; 12]>,
        aad: &[u8],
    ) -> io::Result<Vec<u8>> {
        use aes_gcm::aead::Aead;
        let nonce_bytes = match nonce {
            Some(n) => *n,
            None => {
                increase_nonce(&mut self.nonce);
                self.nonce
            }
        };
        let payload = aes_gcm::aead::Payload { msg: ciphertext, aad };
        self.cipher
            .decrypt(aes_gcm::Nonce::from_slice(&nonce_bytes), payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

fn increase_nonce(nonce: &mut [u8; 12]) {
    for i in 0..12 {
        let idx = 11 - i;
        nonce[idx] = nonce[idx].wrapping_add(1);
        if nonce[idx] != 0 {
            break;
        }
    }
}

// --- BLAKE3 derive_key with byte context ---

fn derive_key_bytes_context(context: &[u8], key_material: &[u8]) -> [u8; 32] {
    let context_key = blake3_hash_root_with_flags(context, IV_WORDS, FLAG_DERIVE_KEY_CONTEXT);
    let context_key_words = blake3::platform::words_from_le_bytes_32(&context_key);
    blake3_hash_root_with_flags(
        key_material,
        &context_key_words,
        FLAG_DERIVE_KEY_MATERIAL,
    )
}

type CvWords = [u32; 8];

const IV_WORDS: &CvWords = &[
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
];

const FLAG_CHUNK_START: u8 = 1 << 0;
const FLAG_CHUNK_END: u8 = 1 << 1;
const FLAG_PARENT: u8 = 1 << 2;
const FLAG_ROOT: u8 = 1 << 3;
const FLAG_DERIVE_KEY_CONTEXT: u8 = 1 << 5;
const FLAG_DERIVE_KEY_MATERIAL: u8 = 1 << 6;

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

fn blake3_hash_root_with_flags(input: &[u8], key: &CvWords, flags: u8) -> [u8; 32] {
    let platform = blake3::platform::Platform::detect();
    let mut chunks = input.chunks(CHUNK_LEN).enumerate();

    let Some((first_idx, first_chunk)) = chunks.next() else {
        // empty message
        let out = chunk_output(&[], key, 0, flags, platform);
        return out.root_hash();
    };

    let first_out = chunk_output(first_chunk, key, first_idx as u64, flags, platform);
    let mut cvs: VecDeque<[u8; 32]> = VecDeque::new();
    cvs.push_back(first_out.chaining_value());

    let mut chunk_count = 1usize;
    for (i, chunk) in chunks {
        let out = chunk_output(chunk, key, i as u64, flags, platform);
        cvs.push_back(out.chaining_value());
        chunk_count += 1;
    }

    if chunk_count == 1 {
        return first_out.root_hash();
    }

    while cvs.len() > 2 {
        let mut next = VecDeque::new();
        while cvs.len() >= 2 {
            let Some(left) = cvs.pop_front() else {
                break;
            };
            let Some(right) = cvs.pop_front() else {
                next.push_back(left);
                break;
            };
            let out = parent_output(&left, &right, key, flags, platform);
            next.push_back(out.chaining_value());
        }
        if let Some(last) = cvs.pop_front() {
            next.push_back(last);
        }
        cvs = next;
    }

    let Some(left) = cvs.pop_front() else {
        return [0u8; 32];
    };
    let Some(right) = cvs.pop_front() else {
        return [0u8; 32];
    };
    parent_output(&left, &right, key, flags, platform).root_hash()
}

fn chunk_output(
    input: &[u8],
    key: &CvWords,
    chunk_counter: u64,
    flags: u8,
    platform: blake3::platform::Platform,
) -> Output {
    let mut state = ChunkState::new(key, chunk_counter, flags, platform);
    state.update(input);
    state.output()
}

fn parent_output(
    left_cv: &[u8; 32],
    right_cv: &[u8; 32],
    key: &CvWords,
    flags: u8,
    platform: blake3::platform::Platform,
) -> Output {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(left_cv);
    block[32..].copy_from_slice(right_cv);
    Output {
        input_chaining_value: *key,
        block,
        block_len: BLOCK_LEN as u8,
        counter: 0,
        flags: flags | FLAG_PARENT,
        platform,
    }
}

struct Output {
    input_chaining_value: CvWords,
    block: [u8; 64],
    block_len: u8,
    counter: u64,
    flags: u8,
    platform: blake3::platform::Platform,
}

impl Output {
    fn chaining_value(&self) -> [u8; 32] {
        let mut cv = self.input_chaining_value;
        self.platform.compress_in_place(
            &mut cv,
            &self.block,
            self.block_len,
            self.counter,
            self.flags,
        );
        blake3::platform::le_bytes_from_words_32(&cv)
    }

    fn root_hash(&self) -> [u8; 32] {
        let mut cv = self.input_chaining_value;
        self.platform.compress_in_place(
            &mut cv,
            &self.block,
            self.block_len,
            0,
            self.flags | FLAG_ROOT,
        );
        blake3::platform::le_bytes_from_words_32(&cv)
    }
}

struct ChunkState {
    cv: CvWords,
    chunk_counter: u64,
    buf: [u8; BLOCK_LEN],
    buf_len: u8,
    blocks_compressed: u8,
    flags: u8,
    platform: blake3::platform::Platform,
}

impl ChunkState {
    fn new(
        key: &CvWords,
        chunk_counter: u64,
        flags: u8,
        platform: blake3::platform::Platform,
    ) -> Self {
        Self {
            cv: *key,
            chunk_counter,
            buf: [0u8; BLOCK_LEN],
            buf_len: 0,
            blocks_compressed: 0,
            flags,
            platform,
        }
    }

    fn start_flag(&self) -> u8 {
        if self.blocks_compressed == 0 {
            FLAG_CHUNK_START
        } else {
            0
        }
    }

    fn fill_buf(&mut self, input: &mut &[u8]) {
        let want = BLOCK_LEN - self.buf_len as usize;
        let take = std::cmp::min(want, input.len());
        self.buf[self.buf_len as usize..][..take].copy_from_slice(&input[..take]);
        self.buf_len += take as u8;
        *input = &input[take..];
    }

    fn update(&mut self, mut input: &[u8]) {
        if self.buf_len > 0 {
            self.fill_buf(&mut input);
            if !input.is_empty() {
                let block_flags = self.flags | self.start_flag();
                self.platform.compress_in_place(
                    &mut self.cv,
                    &self.buf,
                    BLOCK_LEN as u8,
                    self.chunk_counter,
                    block_flags,
                );
                self.buf_len = 0;
                self.buf = [0u8; BLOCK_LEN];
                self.blocks_compressed += 1;
            }
        }

        while input.len() > BLOCK_LEN {
            let block_flags = self.flags | self.start_flag();
            self.platform.compress_in_place(
                &mut self.cv,
                input[..BLOCK_LEN].try_into().expect("slice to array"),
                BLOCK_LEN as u8,
                self.chunk_counter,
                block_flags,
            );
            self.blocks_compressed += 1;
            input = &input[BLOCK_LEN..];
        }

        self.fill_buf(&mut input);
    }

    fn output(&self) -> Output {
        let block_flags = self.flags | self.start_flag() | FLAG_CHUNK_END;
        Output {
            input_chaining_value: self.cv,
            block: self.buf,
            block_len: self.buf_len,
            counter: self.chunk_counter,
            flags: block_flags,
            platform: self.platform,
        }
    }
}
