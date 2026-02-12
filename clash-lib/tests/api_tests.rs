#![cfg(feature = "shadowsocks")]

use crate::common::{send_http_request, start_clash, wait_port_ready};
use bytes::{Buf, Bytes};
use clash_lib::{Config, Options};
use http_body_util::BodyExt;
use std::{path::PathBuf, sync::OnceLock, time::Duration};
use tokio::sync::oneshot;

mod common;

fn ensure_client_started() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let wd =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
        let config_path = wd.join("rules.yaml");
        assert!(
            config_path.exists(),
            "Config file does not exist at: {}",
            config_path.to_string_lossy()
        );

        std::thread::spawn(move || {
            start_clash(Options {
                config: Config::File(config_path.to_string_lossy().to_string()),
                cwd: Some(wd.to_string_lossy().to_string()),
                rt: None,
                log_file: None,
            })
            .expect("Failed to start clash");
        });

        wait_port_ready(9090).expect("Clash server is not ready");
        wait_port_ready(8899).expect("Proxy port is not ready");
    });
}

fn ensure_server_started() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let wd =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/server");
        let config_path = wd.join("server.yaml");
        assert!(
            config_path.exists(),
            "Config file does not exist at: {}",
            config_path.to_string_lossy()
        );

        std::thread::spawn(move || {
            start_clash(Options {
                config: Config::File(config_path.to_string_lossy().to_string()),
                cwd: Some(wd.to_string_lossy().to_string()),
                rt: None,
                log_file: None,
            })
            .expect("Failed to start server");
        });

        wait_port_ready(8901).expect("Shadowsocks server is not ready");
    });
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_get_set_allow_lan() {
    ensure_client_started();

    async fn get_allow_lan() -> bool {
        let get_configs_url = "http://127.0.0.1:9090/configs";
        let req = hyper::Request::builder()
            .uri(get_configs_url)
            .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .method(http::method::Method::GET)
            .body(http_body_util::Empty::<Bytes>::new())
            .expect("Failed to build request");

        let response = send_http_request(get_configs_url.parse().unwrap(), req)
            .await
            .expect("Failed to send request");
        let json: serde_json::Value = serde_json::from_reader(
            response
                .collect()
                .await
                .expect("Failed to collect response body")
                .aggregate()
                .reader(),
        )
        .expect("Failed to parse JSON response");
        json.get("allow-lan")
            .expect("No 'allow-lan' field in response")
            .as_bool()
            .expect("'allow-lan' is not a boolean")
    }

    assert!(
        get_allow_lan().await,
        "'allow_lan' should be true by config"
    );

    let configs_url = "http://127.0.0.1:9090/configs";
    let req = hyper::Request::builder()
        .uri(configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PATCH)
        .body("{\"allow-lan\": false}".into())
        .expect("Failed to build request");

    let res = send_http_request::<String>(configs_url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), http::StatusCode::ACCEPTED);

    assert!(
        !get_allow_lan().await,
        "'allow_lan' should be false after update"
    );

    // Restore global state for other tests in this binary (tests run in
    // unspecified order).
    let configs_url = "http://127.0.0.1:9090/configs";
    let req = hyper::Request::builder()
        .uri(configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PATCH)
        .body("{\"allow-lan\": true}".into())
        .expect("Failed to build request");

    let res = send_http_request::<String>(configs_url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), http::StatusCode::ACCEPTED);
}

#[tokio::test(flavor = "current_thread")]
#[serial_test::serial]
async fn test_connections_returns_proxy_chain_names() {
    ensure_client_started();
    ensure_server_started();

    let wd_server =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/server");
    let wd_client =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let server_config = wd_server.join("server.yaml");
    let client_config = wd_client.join("rules.yaml");

    assert!(
        server_config.exists(),
        "Server config file does not exist at: {}",
        server_config.to_string_lossy()
    );
    assert!(
        client_config.exists(),
        "Client config file does not exist at: {}",
        client_config.to_string_lossy()
    );

    wait_port_ready(8899).expect("Proxy port is not ready");

    // Use a local slow server (no external network dependency) while keeping the
    // destination host as `httpbin.yba.dev` to exercise group chaining logic.
    //
    // NOTE: `rules.yaml` maps `httpbin.yba.dev` -> 127.0.0.1 via `hosts` with
    // `dns.use-hosts: true`.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("Failed to bind local drip server");
    let drip_port = listener
        .local_addr()
        .expect("Failed to get local addr")
        .port();

    let (accepted_tx, accepted_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };

        let _ = accepted_tx.send(());

        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await;

        let _ = socket
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ntransfer-encoding: chunked\r\n\r\n",
            )
            .await;
        let _ = socket.flush().await;

        for _ in 0..30 {
            let _ = socket.write_all(b"5\r\nhello\r\n").await;
            let _ = socket.flush().await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let _ = socket.write_all(b"0\r\n\r\n").await;
        let _ = socket.flush().await;
    });

    let curl_url = format!("http://httpbin.yba.dev:{drip_port}/drip");
    let mut curl = tokio::process::Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "15",
            "-x",
            "socks5h://127.0.0.1:8899",
            curl_url.as_str(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn curl");

    tokio::time::timeout(Duration::from_secs(5), accepted_rx)
        .await
        .expect("Curl never reached drip server")
        .expect("Drip accept notifier dropped");

    let connections_url = "http://127.0.0.1:9090/connections";
    let expected_chains = ["DIRECT", "url-test", "test 🌏"];

    let mut last_snapshot: serde_json::Value = serde_json::Value::Null;
    let conn = {
        let mut found = None;
        for _ in 0..50 {
            let req = hyper::Request::builder()
                .uri(connections_url)
                .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
                .method(http::method::Method::GET)
                .body(http_body_util::Empty::<Bytes>::new())
                .expect("Failed to build request");

            let response = send_http_request(connections_url.parse().unwrap(), req)
                .await
                .expect("Failed to send request")
                .collect()
                .await
                .expect("Failed to collect response body")
                .aggregate()
                .reader();

            last_snapshot = serde_json::from_reader(response)
                .expect("Failed to parse JSON response");
            let connections = last_snapshot
                .get("connections")
                .and_then(|c| c.as_array())
                .expect("No 'connections' field in response");

            found = connections.iter().find(|conn| {
                conn.get("metadata")
                    .and_then(|m| m.get("destinationPort"))
                    .and_then(|p| p.as_u64())
                    == Some(drip_port as u64)
            });
            if found.is_none() {
                found = connections.iter().find(|conn| {
                    conn.get("metadata")
                        .and_then(|m| m.get("host"))
                        .and_then(|h| h.as_str())
                        == Some("httpbin.yba.dev")
                });
            }
            if found.is_none() {
                found = connections.iter().find(|conn| {
                    conn.get("chains")
                        .and_then(|c| c.as_array())
                        .is_some_and(|c| {
                            c.len() == expected_chains.len()
                                && c.iter()
                                    .zip(expected_chains)
                                    .all(|(v, e)| v == e)
                        })
                });
            }

            if let Some(conn) = found {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        found
    }
    .unwrap_or_else(|| {
        panic!(
            "No matching connection found in response. Snapshot: {}",
            serde_json::to_string_pretty(&last_snapshot).unwrap_or_default()
        )
    });

    let chains = conn.get("chains").expect("No 'chains' field in connection");

    assert!(chains.is_array(), "First connection is not an array");

    assert_eq!(
        chains.as_array().unwrap(),
        &expected_chains,
        "Chains do not match expected values"
    );

    let output = curl
        .wait_with_output()
        .await
        .expect("Failed to wait for curl");
    assert!(
        output.status.success(),
        "Curl command failed with output: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
