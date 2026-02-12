use tracing::warn;

static DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];

use crate::{
    Error,
    config::internal::proxy::OutboundTrojan,
    proxy::{
        HandlerCommonOptions,
        transport::{GrpcClient, TlsClient, WsClient},
        trojan::{Handler, HandlerOptions},
    },
};
use crate::proxy::transport::TcpHttpClient;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

impl TryFrom<OutboundTrojan> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundTrojan) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundTrojan> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundTrojan) -> Result<Self, Self::Error> {
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        let reality_enabled = s.reality_opts.is_some();
        let effective_skip_cert_verify = skip_cert_verify || reality_enabled;
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

        let h = Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            password: s.password.clone(),
            udp: s.udp.unwrap_or_default(),
            tls: {
                let alpn = s.alpn.clone().or_else(|| match s.network.as_deref() {
                    Some("ws") | Some("tcp_http") => Some(vec!["http/1.1".to_owned()]),
                    Some("grpc") => Some(vec!["h2".to_owned()]),
                    _ => Some(
                        DEFAULT_ALPN
                            .iter()
                            .copied()
                            .map(|x| x.to_owned())
                            .collect::<Vec<String>>(),
                    ),
                });
                let mut client = TlsClient::new(
                    effective_skip_cert_verify,
                    s.sni
                        .as_ref()
                        .map(|x| x.to_owned())
                        .unwrap_or(s.common_opts.server.to_owned()),
                    alpn,
                    match s.network.as_deref() {
                        Some("grpc") => Some("h2".to_owned()),
                        _ => None,
                    },
                );
                if s.client_fingerprint.is_some() {
                    client.set_client_fingerprint(s.client_fingerprint.clone());
                }
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

                    // REALITY servers can optionally enforce a client version range.
                    // Xray-core currently uses 26.2.6 in its REALITY clienthello SessionID.
                    client.enable_reality(public_key, short_id, [26, 2, 6]);
                }
                Some(Box::new(client))
            },
            transport: s
                .network
                .as_ref()
                .filter(|x| x.as_str() != "tcp" && !x.is_empty())
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
                    "grpc" => s
                        .grpc_opts
                        .as_ref()
                        .ok_or(Error::InvalidConfig(
                            "grpc_opts is required for grpc".to_owned(),
                        ))
                        .and_then(|x| {
                            let client: GrpcClient =
                                (s.sni.clone(), x, &s.common_opts)
                                    .try_into()
                                    .map_err(|e| {
                                        Error::InvalidConfig(format!(
                                            "invalid grpc options: {e}"
                                        ))
                                    })?;
                            Ok(Box::new(client) as _)
                        }),
                    _ => Err(Error::InvalidConfig(format!(
                        "unsupported trojan network: {x}"
                    ))),
                })
                .transpose()?,
        });
        Ok(h)
    }
}
