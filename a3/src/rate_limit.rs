//! Rate limiting backend trait and in-memory implementation.
//!
//! The [`RateLimitBackend`] trait allows pluggable backends (e.g., Redis for
//! distributed deployments). The default [`InMemoryBackend`] is suitable for
//! single-process deployments only.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Trait for rate limit backends.
///
/// Implement this trait to provide a custom rate limiting backend
/// (e.g., Redis for distributed/multi-instance deployments).
///
/// The default [`InMemoryBackend`] uses a `DashMap` and is suitable for
/// single-process deployments only — rate limits are not shared across
/// multiple instances.
pub trait RateLimitBackend: Send + Sync + 'static {
    /// Check if the request identified by `key` is allowed.
    /// Returns `Ok(remaining)` if allowed, `Err(retry_after_secs)` if rate limited.
    fn check(&self, key: &str, limit: u32, window: Duration) -> Result<u32, u64>;
}

/// In-memory rate limiter using a sliding window counter.
///
/// **Single-process only.** Rate limit counters are stored in-process memory
/// and are not shared across multiple instances. For distributed deployments,
/// implement [`RateLimitBackend`] with a shared store (e.g., Redis).
#[derive(Debug, Clone)]
pub struct InMemoryBackend {
    entries: Arc<DashMap<String, WindowEntry>>,
}

#[derive(Debug, Clone)]
struct WindowEntry {
    count: u32,
    window_start: Instant,
}

impl InMemoryBackend {
    /// Create a new in-memory rate limit backend.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
        }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimitBackend for InMemoryBackend {
    fn check(&self, key: &str, limit: u32, window: Duration) -> Result<u32, u64> {
        let now = Instant::now();
        let mut entry = self.entries.entry(key.to_string()).or_insert(WindowEntry {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(entry.window_start) >= window {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count >= limit {
            let retry_after = window
                .checked_sub(now.duration_since(entry.window_start))
                .unwrap_or(Duration::ZERO)
                .as_secs();
            return Err(retry_after.max(1));
        }

        entry.count += 1;
        Ok(limit - entry.count)
    }
}
