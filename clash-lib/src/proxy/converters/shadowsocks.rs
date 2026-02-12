use std::collections::HashMap;
use tracing::warn;
use crate::{
    Error,
    config::internal::proxy::OutboundShadowsocks,
    proxy::{
        HandlerCommonOptions,
        shadowsocks::outbound::{Handler, HandlerOptions},
        transport::{
            Shadowtls, SimpleOBFSMode, SimpleOBFSOption, SimpleObfsHttp,
            SimpleObfsTLS, V2RayOBFSOption, V2rayWsClient,
        },
    },
};
use crate::proxy::transport::{GrpcClient, H2Client, TcpHttpClient, TlsClient, WsClient};

impl TryFrom<OutboundShadowsocks> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundShadowsocks) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundShadowsocks> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundShadowsocks) -> Result<Self, Self::Error> {
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if skip_cert_verify {
            warn!(
                "skipping TLS cert verification for {}",
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
            password: s.password.to_owned(),
            cipher: s.cipher.to_owned(),
            plugin: match &s.plugin {
                Some(plugin) => match plugin.as_str() {
                    "obfs" => {
                        tracing::warn!(
                            "simple-obfs is deprecated, please use v2ray-plugin \
                             instead"
                        );
                        let opt: SimpleOBFSOption = s
                            .plugin_opts
                            .clone()
                            .ok_or(Error::InvalidConfig(
                                "plugin_opts is required for plugin obfs".to_owned(),
                            ))?
                            .try_into()?;
                        let plugin = match opt.mode {
                            SimpleOBFSMode::Http => Box::new(SimpleObfsHttp::new(
                                opt.host,
                                s.common_opts.port,
                            ))
                                as _,
                            SimpleOBFSMode::Tls => {
                                Box::new(SimpleObfsTLS::new(opt.host)) as _
                            }
                        };
                        Some(plugin)
                    }
                    "v2ray-plugin" => {
                        let opt: V2RayOBFSOption = s
                            .plugin_opts
                            .clone()
                            .ok_or(Error::InvalidConfig(
                                "plugin_opts is required for plugin obfs".to_owned(),
                            ))?
                            .try_into()?;
                        // TODO: support more transport options, replace it with
                        // `V2rayClient`
                        let plugin = V2rayWsClient::try_from(opt)?;
                        Some(Box::new(plugin) as _)
                    }
                    "shadow-tls" => {
                        let plugin: Shadowtls = s
                            .plugin_opts
                            .clone()
                            .ok_or(Error::InvalidConfig(
                                "plugin_opts is required for plugin obfs".to_owned(),
                            ))?
                            .try_into()?;
                        Some(Box::new(plugin) as _)
                    }
                    _ => {
                        return Err(Error::InvalidConfig(format!(
                            "unsupported plugin: {plugin}"
                        )));
                    }
                },
                None => None,
            },
            udp: s.udp,
            tls: match s.tls.unwrap_or_default() {
                true => {
                    let sni = s
                        .server_name
                        .as_ref()
                        .map(|x| x.to_owned())
                        .or_else(|| {
                            s.ws_opts.as_ref().and_then(|x| {
                                x.headers.clone().and_then(|x| {
                                    let h = x.get("Host");
                                    h.cloned()
                                })
                            })
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
                        s.skip_cert_verify.unwrap_or_default(),
                        sni,
                        s.network
                            .as_ref()
                            .map(|x| match x.as_str() {
                                "tcp" => Ok(vec![]),
                                "tcp_http" => Ok(vec!["http/1.1".to_owned()]),
                                "ws" => Ok(vec!["http/1.1".to_owned()]),
                                "http" => Ok(vec![]),
                                "h2" | "grpc" => Ok(vec!["h2".to_owned()]),
                                _ => Err(Error::InvalidConfig(format!(
                                    "unsupported network: {x}"
                                ))),
                            })
                            .transpose()?,
                        match s.network.as_deref() {
                            Some("h2") | Some("grpc") => Some("h2".to_owned()),
                            _ => None,
                        },
                    );
                    if s.client_fingerprint.is_some() {
                        client.set_client_fingerprint(s.client_fingerprint.clone());
                    }
                    Some(Box::new(client))
                }
                false => None,
            },
            transport: s
                .network
                .clone()
                .filter(|x| x != "tcp" && !x.is_empty())
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
                    _ => Err(Error::InvalidConfig(format!(
                        "unsupported network: {x}"
                    ))),
                })
                .transpose()?,
        });
        Ok(h)
    }
}

impl TryFrom<HashMap<String, serde_yaml::Value>> for SimpleOBFSOption {
    type Error = crate::Error;

    fn try_from(
        value: HashMap<String, serde_yaml::Value>,
    ) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let mode = value
            .get("mode")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;

        match mode {
            "http" => Ok(SimpleOBFSOption {
                mode: SimpleOBFSMode::Http,
                host: host.to_owned(),
            }),
            "tls" => Ok(SimpleOBFSOption {
                mode: SimpleOBFSMode::Tls,
                host: host.to_owned(),
            }),
            _ => Err(Error::InvalidConfig(format!("invalid obfs mode: {mode}"))),
        }
    }
}

impl TryFrom<HashMap<String, serde_yaml::Value>> for V2RayOBFSOption {
    type Error = crate::Error;

    fn try_from(
        value: HashMap<String, serde_yaml::Value>,
    ) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let mode = value
            .get("mode")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;
        let port = value
            .get("port")
            .and_then(|x| x.as_u64())
            .ok_or(Error::InvalidConfig("obfs port is required".to_owned()))?
            as u16;

        if mode != "websocket" {
            return Err(Error::InvalidConfig(format!("invalid obfs mode: {mode}")));
        }

        let path = value.get("path").and_then(|x| x.as_str()).unwrap_or("");
        let mux = value.get("mux").and_then(|x| x.as_bool()).unwrap_or(false);
        let tls = value.get("tls").and_then(|x| x.as_bool()).unwrap_or(false);
        let skip_cert_verify = value
            .get("skip-cert-verify")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);

        let mut headers = HashMap::new();
        if let Some(h) = value.get("headers")
            && let Some(h) = h.as_mapping()
        {
            for (k, v) in h {
                if let (Some(k), Some(v)) = (k.as_str(), v.as_str()) {
                    headers.insert(k.to_owned(), v.to_owned());
                }
            }
        }

        Ok(V2RayOBFSOption {
            mode: mode.to_owned(),
            host: host.to_owned(),
            port,
            path: path.to_owned(),
            tls,
            headers,
            skip_cert_verify,
            mux,
        })
    }
}

impl TryFrom<HashMap<String, serde_yaml::Value>> for Shadowtls {
    type Error = crate::Error;

    fn try_from(
        value: HashMap<String, serde_yaml::Value>,
    ) -> Result<Self, Self::Error> {
        let host = value
            .get("host")
            .and_then(|x| x.as_str())
            .unwrap_or("bing.com");
        let password = value
            .get("password")
            .and_then(|x| x.as_str().to_owned())
            .ok_or(Error::InvalidConfig("obfs mode is required".to_owned()))?;
        let strict = value
            .get("strict")
            .and_then(|x| x.as_bool())
            .unwrap_or(true);

        Ok(Shadowtls::new(
            host.to_string(),
            password.to_string(),
            strict,
        ))
    }
}
