use crate::{
    Error,
    config::internal::proxy::OutboundVless,
    proxy::{
        HandlerCommonOptions,
        transport::{GrpcClient, H2Client, TlsClient, VlessEncryptionClient, WsClient, XHttpClient},
        vless::{Handler, HandlerOptions},
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use tracing::warn;
use crate::proxy::transport::TcpHttpClient;

impl TryFrom<OutboundVless> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundVless) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundVless> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundVless) -> Result<Self, Self::Error> {
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        let reality_enabled = s.reality_opts.is_some();
        let effective_skip_cert_verify = skip_cert_verify || reality_enabled;
        if reality_enabled && !s.tls.unwrap_or_default() {
            return Err(Error::InvalidConfig(
                "reality-opts requires tls: true".to_owned(),
            ));
        }

        if s.tls.unwrap_or_default() {
            if skip_cert_verify {
                warn!(
                    "skipping TLS cert verification for {}",
                    s.common_opts.server
                );
            }
            if reality_enabled && !skip_cert_verify {
                warn!(
                    "REALITY enabled for {}, TLS cert verification will be skipped",
                    s.common_opts.server
                );
            }
        }

        Ok(Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            uuid: s.uuid.clone(),
            udp: s.udp.unwrap_or(true),
            transport: s
                .network
                .clone()
                .map(|x| match x.as_str() {
                    "tcp_http" => s
                        .tcp_http_opts
                        .as_ref()
                        .ok_or(Error::InvalidConfig(
                            "tcp-http-opts is required for tcp_http".to_owned(),
                        ))
                        .and_then(|x| {
                            let client: TcpHttpClient =
                                (x, &s.common_opts).try_into().map_err(|e| {
                                    Error::InvalidConfig(format!(
                                        "invalid tcp_http options: {e}"
                                    ))
                                })?;
                            Ok(Box::new(client) as _)
                        }),
                    "ws" => s
                        .ws_opts
                        .as_ref()
                        .ok_or(Error::InvalidConfig(
                            "ws_opts is required for ws".to_owned(),
                        ))
                        .and_then(|x| {
                            let client: WsClient =
                                (x, &s.common_opts).try_into().map_err(|e| {
                                    Error::InvalidConfig(format!("invalid ws options: {e}"))
                                })?;
                            Ok(Box::new(client) as _)
                        }),
                    "h2" => s
                        .h2_opts
                        .as_ref()
                        .ok_or(Error::InvalidConfig(
                            "h2_opts is required for h2".to_owned(),
                        ))
                        .and_then(|x| {
                            let client: H2Client =
                                (x, &s.common_opts).try_into().map_err(|e| {
                                    Error::InvalidConfig(format!("invalid h2 options: {e}"))
                                })?;
                            Ok(Box::new(client) as _)
                        }),
                    "grpc" => s
                        .grpc_opts
                        .as_ref()
                        .ok_or(Error::InvalidConfig(
                            "grpc_opts is required for grpc".to_owned(),
                        ))
                        .and_then(|x| {
                            let client: GrpcClient =
                                (s.server_name.clone(), x, &s.common_opts)
                                    .try_into()
                                    .map_err(|e| {
                                        Error::InvalidConfig(format!(
                                            "invalid grpc options: {e}"
                                        ))
                                    })?;
                            Ok(Box::new(client) as _)
                        }),
                    "xhttp" => {
                        if !s.tls.unwrap_or_default() {
                            return Err(Error::InvalidConfig(
                                "xhttp requires tls: true".to_owned(),
                            ));
                        }
                        s.xhttp_opts
                            .as_ref()
                            .ok_or(Error::InvalidConfig(
                                "xhttp-opts is required for xhttp".to_owned(),
                            ))
                            .and_then(|x| {
                                if let Some(mode) =
                                    x.mode.as_deref().filter(|x| !x.is_empty())
                                    && mode != "auto"
                                    && mode != "stream"
                                    && mode != "stream-one"
                                {
                                    return Err(Error::InvalidConfig(format!(
                                        "unsupported xhttp mode: {mode}"
                                    )));
                                }

                                let client: XHttpClient =
                                    (s.server_name.clone(), x, &s.common_opts)
                                        .try_into()
                                        .map_err(|e| {
                                            Error::InvalidConfig(format!(
                                                "invalid xhttp options: {e}"
                                            ))
                                        })?;
                                Ok(Box::new(client) as _)
                            })
                    }
                    _ => Err(Error::InvalidConfig(format!(
                        "unsupported network: {x}"
                    ))),
                })
                .transpose()?,
            tls: match s.tls.unwrap_or_default() {
                true => {
                    let sni = s
                        .server_name
                        .as_ref()
                        .map(|x| x.to_owned())
                        .or_else(|| {
                            s.ws_opts.as_ref().and_then(|x| {
                                x.headers.as_ref().and_then(|x| x.get("Host").cloned())
                            })
                        })
                        .or_else(|| {
                            s.xhttp_opts
                                .as_ref()
                                .and_then(|x| x.host.as_ref())
                                .filter(|x| !x.is_empty())
                                .cloned()
                        })
                        .or_else(|| {
                            s.tcp_http_opts
                                .as_ref()
                                .and_then(|x| x.host.as_ref())
                                .filter(|x| !x.is_empty())
                                .cloned()
                        })
                        .unwrap_or(s.common_opts.server.to_owned());
                    let mut client = TlsClient::new(
                        effective_skip_cert_verify,
                        sni,
                        s.network
                            .as_ref()
                            .map(|x| match x.as_str() {
                                "tcp_http" => Ok(vec!["http/1.1".to_owned()]),
                                "ws" => Ok(vec!["http/1.1".to_owned()]),
                                "http" => Ok(vec![]),
                                "xhttp" => Ok(vec!["h2".to_owned()]),
                                "h2" | "grpc" => Ok(vec!["h2".to_owned()]),
                                _ => Err(Error::InvalidConfig(format!(
                                    "unsupported network: {x}"
                                ))),
                            })
                            .transpose()?,
                        None,
                    );
                    if let Some(reality_opts) = s.reality_opts.as_ref() {
                        let public_key = reality_opts
                            .public_key
                            .as_ref()
                            .ok_or(Error::InvalidConfig(
                                "reality-opts.public-key is required when reality-opts is set"
                                    .to_owned(),
                            ))?;
                        let public_key = URL_SAFE_NO_PAD
                            .decode(public_key)
                            .map_err(|e| {
                                Error::InvalidConfig(format!(
                                    "invalid reality public-key base64: {e}"
                                ))
                            })?;
                        if public_key.len() != 32 {
                            return Err(Error::InvalidConfig(format!(
                                "invalid reality public-key length: expected 32 bytes, got {}",
                                public_key.len()
                            )));
                        }

                        let short_id = match reality_opts.short_id.as_deref() {
                            None | Some("") => Vec::new(),
                            Some(short_id) => {
                                if short_id.len() % 2 != 0 {
                                    return Err(Error::InvalidConfig(
                                        "invalid reality short-id: hex string must have even length"
                                            .to_owned(),
                                    ));
                                }
                                crate::common::utils::decode_hex(short_id).map_err(|e| {
                                    Error::InvalidConfig(format!(
                                        "invalid reality short-id hex: {e}"
                                    ))
                                })?
                            }
                        };

                        if let Some(fp) = s.client_fingerprint.as_ref() {
                            warn!(
                                "client-fingerprint is currently ignored for REALITY: {}",
                                fp
                            );
                        }

                        // REALITY servers can optionally enforce a client version range.
                        // Xray-core currently uses 26.2.6 in its REALITY clienthello SessionID.
                        client.enable_reality(public_key, short_id, [26, 2, 6]);
                    }
                    Some(Box::new(client))
                }
                false => None,
            },
            vless_encryption: match s.encryption.as_deref() {
                None | Some("") | Some("none") => None,
                Some(enc) => {
                    let enc = VlessEncryptionClient::new(enc).map_err(|e| {
                        Error::InvalidConfig(format!("invalid vless encryption: {e}"))
                    })?;
                    Some(Box::new(enc) as _)
                }
            },
        }))
    }
}
