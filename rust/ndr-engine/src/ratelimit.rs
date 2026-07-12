// Simple per-IP sliding-window rate limiter using dashmap.
// Limits: 300 req/60s for general API, 20 req/60s for /api/login.
// Uses token bucket approximation via request timestamp deque.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

const WINDOW:       Duration = Duration::from_secs(60);
const LIMIT_API:    usize    = 300;
const LIMIT_LOGIN:  usize    = 20;

struct Bucket {
    timestamps: VecDeque<Instant>,
}

impl Bucket {
    fn new() -> Self { Self { timestamps: VecDeque::new() } }

    fn allow(&mut self, limit: usize) -> bool {
        let now = Instant::now();
        // Evict expired entries
        while self.timestamps.front().map(|t| now.duration_since(*t) > WINDOW).unwrap_or(false) {
            self.timestamps.pop_front();
        }
        if self.timestamps.len() >= limit {
            return false;
        }
        self.timestamps.push_back(now);
        true
    }
}

static BUCKETS: LazyLock<Arc<DashMap<String, Bucket>>> =
    LazyLock::new(|| Arc::new(DashMap::new()));

pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let ip    = addr.ip().to_string();
    let path  = req.uri().path().to_string();
    let limit = if path.contains("/login") { LIMIT_LOGIN } else { LIMIT_API };

    let key = format!("{}:{}", ip, if path.contains("/login") { "login" } else { "api" });

    let allowed = {
        let mut bucket = BUCKETS.entry(key).or_insert_with(Bucket::new);
        bucket.allow(limit)
    };

    if !allowed {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(req).await)
}
