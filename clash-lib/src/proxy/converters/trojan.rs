use tracing::warn;

static DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];

use crate::{
    Error,
    config::internal::proxy::OutboundTrojan,
    proxy::{
        HandlerCommonOptions,
        transport::{GrpcPooledClient, TlsClient, WsClient},
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
                let alpn = s.alpn.clone().map(|list| {
                    list.into_iter()
                        .map(|v| v.trim().to_owned())
                        .filter(|v| !v.is_empty())
                        .collect::<Vec<_>>()
                });
                let mut alpn = alpn.filter(|list| !list.is_empty()).or_else(|| {
                    Some(match s.network.as_deref() {
                        Some("ws") | Some("tcp_http") => {
                            vec!["http/1.1".to_owned()]
                        }
                        Some("grpc") => vec!["h2".to_owned()],
                        _ => DEFAULT_ALPN
                            .iter()
                            .copied()
                            .map(|x| x.to_owned())
                            .collect::<Vec<String>>(),
                    })
                });
                if let Some(required) = match s.network.as_deref() {
                    Some("grpc") => Some("h2"),
                    Some("ws") | Some("tcp_http") => Some("http/1.1"),
                    _ => None,
                } && let Some(list) = alpn.as_mut()
                {
                    if !list.iter().any(|v| v == required) {
                        list.push(required.to_owned());
                    }
                }
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
                    if let Some(spider_x) = reality_opts
                        .spider_x
                        .as_deref()
                        .filter(|x| !x.is_empty())
                    {
                        warn!(
                            "reality-opts.spider-x is currently ignored for {}: {}",
                            s.common_opts.server, spider_x
                        );
                    }
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
            transport: {
                let network = s
                    .network
                    .as_deref()
                    .map(|x| x.trim())
                    .filter(|x| !x.is_empty() && *x != "tcp");
                match network {
                    Some("tcp_http") => Some({
                        let opt = s.tcp_http_opts.as_ref().ok_or(Error::InvalidConfig(
                            "tcp-http-opts is required for tcp_http".to_owned(),
                        ))?;
                        let client: TcpHttpClient =
                            (opt, &s.common_opts).try_into().map_err(|e| {
                                Error::InvalidConfig(format!(
                                    "invalid tcp_http options: {e}"
                                ))
                            })?;
                        Box::new(client) as _
                    }),
                    Some("ws") => Some({
                        let opt = s.ws_opts.as_ref().ok_or(Error::InvalidConfig(
                            "ws_opts is required for ws".to_owned(),
                        ))?;
                        let client: WsClient = (opt, &s.common_opts)
                            .try_into()
                            .map_err(|e| {
                                Error::InvalidConfig(format!(
                                    "invalid ws options: {e}"
                                ))
                            })?;
                        Box::new(client) as _
                    }),
                    Some("grpc") => None,
                    Some(other) => {
                        return Err(Error::InvalidConfig(format!(
                            "unsupported trojan network: {other}"
                        )));
                    }
                    None => None,
                }
            },
            grpc: {
                let network = s
                    .network
                    .as_deref()
                    .map(|x| x.trim())
                    .filter(|x| !x.is_empty() && *x != "tcp");
                match network {
                    Some("grpc") => {
                        let opt = s.grpc_opts.as_ref().ok_or(Error::InvalidConfig(
                            "grpc_opts is required for grpc".to_owned(),
                        ))?;
                        let host = s
                            .sni
                            .as_ref()
                            .filter(|x| !x.is_empty())
                            .cloned()
                            .unwrap_or(s.common_opts.server.to_owned());
                        Some(GrpcPooledClient::new(
                            host,
                            opt.grpc_service_name.clone().unwrap_or_default(),
                            opt.mode.clone(),
                            true,
                        ))
                    }
                    _ => None,
                }
            },
        });
        Ok(h)
    }
}
