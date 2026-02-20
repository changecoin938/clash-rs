use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router, middleware,
    extract::{Query, Request, State},
    response::IntoResponse,
    routing::get,
};
use hickory_proto::{op::Message, rr::RecordType};
use http::StatusCode;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::app::{api::AppState, dns::ThreadSafeDNSResolver};

#[derive(Clone)]
struct DNSState {
    #[allow(dead_code)]
    resolver: ThreadSafeDNSResolver,
}

#[derive(Clone)]
struct QueryRateLimiter {
    inner: Arc<tokio::sync::Mutex<RateLimitState>>,
    max: u64,
    per: Duration,
}

#[derive(Debug)]
struct RateLimitState {
    window_start: Instant,
    count: u64,
}

impl QueryRateLimiter {
    fn new(max: u64, per: Duration) -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(RateLimitState {
                window_start: Instant::now(),
                count: 0,
            })),
            max,
            per,
        }
    }
}

async fn rate_limit(
    State(limiter): State<QueryRateLimiter>,
    req: Request,
    next: middleware::Next,
) -> axum::response::Response {
    let mut state = limiter.inner.lock().await;
    let now = Instant::now();
    if now.duration_since(state.window_start) >= limiter.per {
        state.window_start = now;
        state.count = 0;
    }

    if state.count >= limiter.max {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded")
            .into_response();
    }
    state.count += 1;
    drop(state);

    next.run(req).await
}

pub fn routes(resolver: ThreadSafeDNSResolver) -> Router<Arc<AppState>> {
    let state = DNSState { resolver };
    let limiter = QueryRateLimiter::new(10, Duration::from_secs(1));
    Router::new()
        .route("/query", get(query_dns))
        .route_layer(middleware::from_fn_with_state(limiter, rate_limit))
        .with_state(state)
}

#[derive(Deserialize)]
struct DnsQUery {
    name: String,
    #[serde(rename = "type")]
    typ: String,
}

async fn query_dns(
    State(state): State<DNSState>,
    q: Query<DnsQUery>,
) -> impl IntoResponse {
    if let crate::app::dns::ResolverKind::System = state.resolver.kind() {
        return (StatusCode::BAD_REQUEST, "Clash resolver is not enabled.")
            .into_response();
    }
    let typ: RecordType = q.typ.parse().unwrap_or(RecordType::A);
    let mut m = Message::new();

    let name = hickory_proto::rr::Name::from_str_relaxed(q.name.as_str());

    if name.is_err() {
        return (StatusCode::BAD_REQUEST, "Invalid name").into_response();
    }

    m.add_query(hickory_proto::op::Query::query(name.unwrap(), typ));

    match state.resolver.exchange(&m).await {
        Ok(response) => {
            let mut resp = Map::new();
            resp.insert("Status".to_owned(), response.response_code().low().into());
            resp.insert(
                "Question".to_owned(),
                response
                    .queries()
                    .iter()
                    .map(|x| {
                        let mut data = Map::new();
                        data.insert("name".to_owned(), x.name().to_string().into());
                        data.insert(
                            "qtype".to_owned(),
                            u16::from(x.query_type()).into(),
                        );
                        data.insert(
                            "qclass".to_owned(),
                            u16::from(x.query_class()).into(),
                        );
                        data.into()
                    })
                    .collect::<Vec<Value>>()
                    .into(),
            );

            resp.insert("TC".to_owned(), response.truncated().into());
            resp.insert("RD".to_owned(), response.recursion_desired().into());
            resp.insert("RA".to_owned(), response.recursion_available().into());
            resp.insert("AD".to_owned(), response.authentic_data().into());
            resp.insert("CD".to_owned(), response.checking_disabled().into());

            let rr2json = |rr: &hickory_proto::rr::Record| -> Value {
                let mut data = Map::new();
                data.insert("name".to_owned(), rr.name().to_string().into());
                data.insert("type".to_owned(), u16::from(rr.record_type()).into());
                data.insert("ttl".to_owned(), rr.ttl().into());
                data.insert("data".to_owned(), rr.data().to_string().into());
                data.into()
            };

            if response.answer_count() > 0 {
                resp.insert(
                    "Answer".to_owned(),
                    response.answers().iter().map(rr2json).collect(),
                );
            }

            if response.name_server_count() > 0 {
                resp.insert(
                    "Authority".to_owned(),
                    response.name_servers().iter().map(rr2json).collect(),
                );
            }

            if response.additional_count() > 0 {
                resp.insert(
                    "Additional".to_owned(),
                    response.additionals().iter().map(rr2json).collect(),
                );
            }

            Json(resp).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
