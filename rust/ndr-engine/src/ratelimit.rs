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

fn ingest_event_limit() -> usize {
    std::env::var("INGEST_RATE_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or(50_000)
}

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

// ── Per-sensor ingest event-volume rate limit ─────────────────────────────
// Tracks cumulative event count per sensor key over a fixed 60s window.
// This is intentionally a simple tumbling window (not sliding) — cheap and
// sufficient for burst protection.

struct CountBucket {
    count:        usize,
    window_start: Instant,
}

impl CountBucket {
    fn new() -> Self { Self { count: 0, window_start: Instant::now() } }

    fn allow_n(&mut self, n: usize, limit: usize) -> bool {
        if Instant::now().duration_since(self.window_start) > WINDOW {
            self.count = 0;
            self.window_start = Instant::now();
        }
        if self.count + n > limit {
            return false;
        }
        self.count += n;
        true
    }
}

static INGEST_BUCKETS: LazyLock<Arc<DashMap<String, CountBucket>>> =
    LazyLock::new(|| Arc::new(DashMap::new()));

/// Returns false (and logs a warning) if `sensor_key` has sent more than
/// INGEST_RATE_LIMIT events in the last 60 seconds.
pub fn check_ingest_rate(sensor_key: &str, event_count: usize) -> bool {
    let limit = ingest_event_limit();
    INGEST_BUCKETS
        .entry(sensor_key.to_string())
        .or_insert_with(CountBucket::new)
        .allow_n(event_count, limit)
}

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
