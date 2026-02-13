use tracing::warn;

use crate::{
    Error,
    config::internal::proxy::OutboundVmess,
    proxy::{
        HandlerCommonOptions,
        transport::{GrpcPooledClient, H2Client, TlsClient, WsClient, XHttpClient},
        vmess::{Handler, HandlerOptions},
    },
};
use crate::proxy::transport::TcpHttpClient;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

impl TryFrom<OutboundVmess> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundVmess) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundVmess> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundVmess) -> Result<Self, Self::Error> {
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

        let h = Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            uuid: s.uuid.clone(),
            alter_id: s.alter_id,
            security: s.cipher.clone().unwrap_or_default(),
            udp: s.udp.unwrap_or(true),
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
                    Some("h2") => Some({
                        let opt = s.h2_opts.as_ref().ok_or(Error::InvalidConfig(
                            "h2_opts is required for h2".to_owned(),
                        ))?;
                        let client: H2Client =
                            (opt, &s.common_opts).try_into().map_err(|e| {
                                Error::InvalidConfig(format!(
                                    "invalid h2 options: {e}"
                                ))
                            })?;
                        Box::new(client) as _
                    }),
                    Some("xhttp") => {
                        if !s.tls.unwrap_or_default() {
                            return Err(Error::InvalidConfig(
                                "xhttp requires tls: true".to_owned(),
                            ));
                        }
                        Some({
                            let opt =
                                s.xhttp_opts.as_ref().ok_or(Error::InvalidConfig(
                                    "xhttp-opts is required for xhttp".to_owned(),
                                ))?;

                            if let Some(mode) =
                                opt.mode.as_deref().filter(|x| !x.is_empty())
                            {
                                let mode = mode.to_ascii_lowercase();
                                if mode != "auto"
                                    && mode != "packet"
                                    && mode != "packet-up"
                                    && mode != "packet_up"
                                    && mode != "stream"
                                    && mode != "stream-up"
                                    && mode != "stream_up"
                                    && mode != "stream-one"
                                    && mode != "stream_one"
                                {
                                    return Err(Error::InvalidConfig(format!(
                                        "unsupported xhttp mode: {mode}"
                                    )));
                                }
                            }

                            let client: XHttpClient =
                                (s.server_name.clone(), opt, &s.common_opts)
                                    .try_into()
                                    .map_err(|e| {
                                        Error::InvalidConfig(format!(
                                            "invalid xhttp options: {e}"
                                        ))
                                    })?;
                            Box::new(client) as _
                        })
                    }
                    Some("grpc") => None,
                    Some(other) => {
                        return Err(Error::InvalidConfig(format!(
                            "unsupported network: {other}"
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
                            .server_name
                            .as_ref()
                            .filter(|x| !x.is_empty())
                            .cloned()
                            .unwrap_or(s.common_opts.server.to_owned());
                        Some(GrpcPooledClient::new(
                            host,
                            opt.grpc_service_name.clone().unwrap_or_default(),
                            opt.mode.clone(),
                            s.tls.unwrap_or_default(),
                        ))
                    }
                    _ => None,
                }
            },
            tls: match s.tls.unwrap_or_default() {
                true => {
                    let alpn = s.alpn.clone().map(|list| {
                        list.into_iter()
                            .map(|v| v.trim().to_owned())
                            .filter(|v| !v.is_empty())
                            .collect::<Vec<_>>()
                    });
                    let default_alpn = s
                        .network
                        .as_ref()
                        .map(|x| match x.as_str() {
                            "tcp" => Ok(vec![]),
                            "tcp_http" => Ok(vec!["http/1.1".to_owned()]),
                            "ws" => Ok(vec!["http/1.1".to_owned()]),
                            "http" => Ok(vec![]),
                            "xhttp" => Ok(vec!["h2".to_owned()]),
                            "h2" | "grpc" => Ok(vec!["h2".to_owned()]),
                            _ => Err(Error::InvalidConfig(format!(
                                "unsupported network: {x}"
                            ))),
                        })
                        .transpose()?;
                    let mut alpn = alpn
                        .filter(|list| !list.is_empty())
                        .or(default_alpn);
                    if let Some(required) = match s.network.as_deref() {
                        Some("xhttp") | Some("h2") | Some("grpc") => Some("h2"),
                        Some("ws") | Some("tcp_http") => Some("http/1.1"),
                        _ => None,
                    } && let Some(list) = alpn.as_mut()
                    {
                        if !list.iter().any(|v| v == required) {
                            list.push(required.to_owned());
                        }
                    }
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
                        alpn,
                        match s.network.as_deref() {
                            Some("xhttp") | Some("h2") | Some("grpc") => {
                                Some("h2".to_owned())
                            }
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
                }
                false => None,
            },
        });
        Ok(h)
    }
}
