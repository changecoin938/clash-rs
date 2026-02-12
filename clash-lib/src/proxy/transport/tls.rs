use async_trait::async_trait;
use serde::Serialize;
use std::{io, sync::Arc};
use tracing::warn;

use super::Transport;
use crate::{
    common::{
        errors::map_io_error,
        tls::{DefaultTlsVerifier, GLOBAL_ROOT_STORE},
    },
    proxy::AnyStream,
};

#[derive(Serialize, Clone)]
pub struct TLSOptions {
    pub skip_cert_verify: bool,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
}

impl From<TLSOptions> for Client {
    fn from(opt: TLSOptions) -> Self {
        Self::new(opt.skip_cert_verify, opt.sni, opt.alpn, None)
    }
}

#[derive(Serialize, Clone)]
struct RealityOptions {
    pub public_key: Vec<u8>,
    pub short_id: Vec<u8>,
    pub version: [u8; 3],
}

pub struct Client {
    pub skip_cert_verify: bool,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
    pub expected_alpn: Option<String>,
    client_fingerprint: Option<String>,
    reality: Option<RealityOptions>,
}

impl Client {
    pub fn new(
        skip_cert_verify: bool,
        sni: String,
        alpn: Option<Vec<String>>,
        expected_alpn: Option<String>,
    ) -> Self {
        Self {
            skip_cert_verify,
            sni,
            alpn,
            expected_alpn,
            client_fingerprint: None,
            reality: None,
        }
    }

    pub fn enable_reality(
        &mut self,
        public_key: Vec<u8>,
        short_id: Vec<u8>,
        version: [u8; 3],
    ) {
        self.reality = Some(RealityOptions {
            public_key,
            short_id,
            version,
        });
    }

    pub fn set_client_fingerprint(&mut self, fingerprint: Option<String>) {
        self.client_fingerprint = fingerprint;
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(GLOBAL_ROOT_STORE.clone())
            .with_no_client_auth();
        tls_config.alpn_protocols = self
            .alpn
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|x| x.as_bytes().to_vec())
            .collect();

        // REALITY uses a fake/self-issued certificate. We must not rely on WebPKI
        // validation here (Xray uses InsecureSkipVerify + REALITY-specific auth).
        let skip_cert_verify = self.skip_cert_verify || self.reality.is_some();
        tls_config.dangerous().set_certificate_verifier(Arc::new(
            DefaultTlsVerifier::new(None, skip_cert_verify),
        ));

        if let Some(reality) = self.reality.as_ref() {
            tls_config.add_reality(
                reality.public_key.clone(),
                reality.short_id.clone(),
                reality.version[0],
                reality.version[1],
                reality.version[2],
            );
        }

        if let Some(fp) = self.client_fingerprint.as_deref() {
            let profile = match fp.to_ascii_lowercase().as_str() {
                "chrome" | "edge" | "360" | "qq" | "android" => {
                    Some(rustls::client::ClientHelloFingerprint::Chrome)
                }
                "firefox" => Some(rustls::client::ClientHelloFingerprint::Firefox),
                "safari" | "ios" => Some(rustls::client::ClientHelloFingerprint::Safari),
                "random" | "randomized" | "unsafe" => {
                    Some(rustls::client::ClientHelloFingerprint::Randomized)
                }
                "randomizednoalpn" => {
                    Some(rustls::client::ClientHelloFingerprint::RandomizedNoAlpn)
                }
                other => {
                    warn!("unknown client-fingerprint: {other}");
                    None
                }
            };
            if let Some(profile) = profile {
                tls_config.set_client_hello_fingerprint(profile);
            }
        }

        if std::env::var("SSLKEYLOGFILE").is_ok() {
            tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let dns_name =
            rustls::pki_types::ServerName::try_from(self.sni.as_str().to_owned())
                .map_err(map_io_error)?;

        let c = connector.connect(dns_name, stream).await.and_then(|x| {
            if let Some(expected_alpn) = self.expected_alpn.as_ref()
                && x.get_ref().1.alpn_protocol() != Some(expected_alpn.as_bytes())
            {
                return Err(io::Error::other(format!(
                    "unexpected alpn protocol: {:?}, expected: {:?}",
                    x.get_ref().1.alpn_protocol(),
                    expected_alpn
                )));
            }

            Ok(x)
        });
        c.map(|x| Box::new(x) as _)
    }
}
