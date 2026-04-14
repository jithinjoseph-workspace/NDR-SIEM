// NDR Engine — Real-time Correlation Engine
// Uses community_id as the join key — same approach as Malcolm and Security Onion.
// DashMap gives lock-free concurrent access without a global Mutex.
// License: Apache-2.0

mod session;
pub use session::{Session, CorrelationHit};

use crate::normalizer::{EventSource, NormalizedEvent};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// In-memory correlation engine backed by a DashMap keyed on community_id.
/// Both Zeek and Suricata events for the same flow share one Session entry.
/// When both sides are present → emit a CorrelationHit.
pub struct CorrelationEngine {
    sessions: Arc<DashMap<String, Session>>,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }

    /// Feed a normalised event into the engine.
    /// Returns Some(CorrelationHit) the moment both Zeek and Suricata are seen.
    pub fn process(&self, event: NormalizedEvent) -> Option<CorrelationHit> {
        let cid = event.community_id.clone()?;
        let now = now_secs();

        let mut session = self.sessions
            .entry(cid.clone())
            .or_insert_with(|| Session::new(cid.clone()));

        session.last_seen = now;

        match event.event_source {
            EventSource::Zeek => {
                // Track proto for TTL decision
                if let Some(p) = &event.proto {
                    session.proto = Some(p.clone());
                }
                session.zeek = Some(event);

                // Check if Suricata side already arrived
                if let (Some(z), Some(s)) = (&session.zeek, &session.suricata) {
                    return Some(CorrelationHit {
                        community_id: cid,
                        zeek:         z.clone(),
                        suricata:     s.clone(),
                        hit_time:     now,
                    });
                }
            }

            EventSource::Suricata => {
                session.suricata = Some(event);

                // Check if Zeek side already arrived
                if let (Some(z), Some(s)) = (&session.zeek, &session.suricata) {
                    return Some(CorrelationHit {
                        community_id: cid,
                        zeek:         z.clone(),
                        suricata:     s.clone(),
                        hit_time:     now,
                    });
                }
            }

            EventSource::Unknown => {}
        }

        None
    }

    /// Drop expired sessions. Call from a background task every 30s.
    pub fn sweep_expired(&self) {
        let now = now_secs();
        self.sessions.retain(|_, s| !s.is_expired(now));
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}
