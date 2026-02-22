//! Rate limiting backend trait and in-memory implementation.
//!
//! The [`RateLimitBackend`] trait allows pluggable backends (e.g., Redis for
//! distributed deployments). The default [`InMemoryBackend`] is suitable for
//! single-process deployments only.

use dashmap::DashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Result of a successful rate limit check.
#[derive(Debug, Clone)]
pub struct RateLimitOutcome {
    /// Number of requests remaining in the current window.
    pub remaining: u32,
    /// Maximum requests allowed in the window.
    pub limit: u32,
    /// Seconds until the current window resets.
    pub reset_after: u64,
}

/// Result of a rejected rate limit check.
#[derive(Debug, Clone)]
pub struct RateLimitRejection {
    /// Seconds the client should wait before retrying.
    pub retry_after: u64,
    /// Maximum requests allowed in the window.
    pub limit: u32,
}

/// Trait for rate limit backends.
///
/// Implement this trait to provide a custom rate limiting backend
/// (e.g., Redis for distributed/multi-instance deployments).
///
/// The method is async-ready (returns a boxed future) so that backends
/// using network stores (Redis, Memcached, etc.) can perform non-blocking I/O.
///
/// The default [`InMemoryBackend`] uses a `DashMap` and is suitable for
/// single-process deployments only — rate limits are not shared across
/// multiple instances.
///
/// # Example: Custom Redis Backend
///
/// ```rust,ignore
/// use acube::rate_limit::{RateLimitBackend, RateLimitOutcome, RateLimitRejection};
/// use std::pin::Pin;
/// use std::future::Future;
/// use std::time::Duration;
///
/// struct RedisBackend { /* redis connection pool */ }
///
/// impl RateLimitBackend for RedisBackend {
///     fn check(
///         &self,
///         key: &str,
///         limit: u32,
///         window: Duration,
///     ) -> Pin<Box<dyn Future<Output = Result<RateLimitOutcome, RateLimitRejection>> + Send + '_>> {
///         let key = key.to_string();
///         Box::pin(async move {
///             // Use async Redis client here...
///             todo!()
///         })
///     }
/// }
/// ```
pub trait RateLimitBackend: Send + Sync + 'static {
    /// Check if the request identified by `key` is allowed.
    ///
    /// Returns `Ok(RateLimitOutcome)` if the request is within limits,
    /// or `Err(RateLimitRejection)` if the rate limit has been exceeded.
    fn check(
        &self,
        key: &str,
        limit: u32,
        window: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<RateLimitOutcome, RateLimitRejection>> + Send + '_>>;
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
    fn check(
        &self,
        key: &str,
        limit: u32,
        window: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<RateLimitOutcome, RateLimitRejection>> + Send + '_>>
    {
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

        let reset_after = window
            .checked_sub(now.duration_since(entry.window_start))
            .unwrap_or(Duration::ZERO)
            .as_secs()
            .max(1);

        if entry.count >= limit {
            let rejection = RateLimitRejection {
                retry_after: reset_after,
                limit,
            };
            return Box::pin(async move { Err(rejection) });
        }

        entry.count += 1;
        let outcome = RateLimitOutcome {
            remaining: limit - entry.count,
            limit,
            reset_after,
        };
        Box::pin(async move { Ok(outcome) })
    }
}
