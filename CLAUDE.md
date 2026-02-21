# a3 (エースリー) — AI Security Framework for Rust

## What is a3?

a3 is a Rust web framework that enforces server-side security at the syntax level.
Security is opt-out, not opt-in — if you don't declare security, it won't compile.

Built on axum 0.7 + tower 0.4 + tokio 1.

## Quick Start

```rust
use a3::prelude::*;

#[derive(A3Schema, Debug, Deserialize)]
pub struct CreateUserInput {
    #[a3(min_length = 3, max_length = 30, pattern = "^[a-zA-Z0-9_]+$")]
    #[a3(sanitize(trim))]
    pub username: String,

    #[a3(format = "email", pii)]
    #[a3(sanitize(trim, lowercase))]
    pub email: String,

    #[a3(min_length = 1, max_length = 100)]
    #[a3(sanitize(trim, strip_html))]
    pub display_name: String,
}

#[derive(A3Error, Debug)]
pub enum UserError {
    #[a3(status = 404, message = "User not found")]
    NotFound,
    #[a3(status = 409, message = "Username already taken")]
    UsernameTaken,
}

#[a3_endpoint(POST "/users")]
#[a3_security(jwt, scopes = ["users:create"])]
#[a3_rate_limit(10, per_minute)]
async fn create_user(
    ctx: A3Context,
    input: Valid<CreateUserInput>,
) -> A3Result<Created<UserOutput>, UserError> {
    let input = input.into_inner();
    // Business logic here...
    Ok(Created(user))
}

#[a3_endpoint(GET "/health")]
#[a3_security(none)]
#[a3_rate_limit(none)]
async fn health_check(_ctx: A3Context) -> A3Result<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("1.0.0")))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    a3::init_tracing();
    let service = Service::builder()
        .name("my-service")
        .version("1.0.0")
        .endpoint(create_user())
        .endpoint(health_check())
        .auth(JwtAuth::from_env()?)
        .cors_allow_origins(&["https://myapp.com"])
        .build()?;
    a3::serve(service, "0.0.0.0:3000").await
}
```

## Rules (MUST follow)

1. **Every endpoint MUST have `#[a3_security(...)]`** — otherwise it won't compile.
   - `#[a3_security(jwt, scopes = ["scope:name"])]` for protected endpoints
   - `#[a3_security(none)]` to explicitly opt out (e.g., health checks)

2. **Rate limiting is automatic** — default 100/min per endpoint.
   - Override: `#[a3_rate_limit(10, per_minute)]`
   - Disable: `#[a3_rate_limit(none)]`

3. **Use `Valid<T>` for input** — handles validation, sanitization, and unknown field rejection.
   - T must derive `A3Schema` and `Deserialize`
   - Returns structured 400 errors automatically

4. **Use `A3Result<T, E>`** where E derives `A3Error`.
   - Use `Never` as the error type for infallible endpoints.

5. **First parameter is always `A3Context`** (or `_ctx: A3Context`).

## What a3 does automatically

- 7 security headers on every response (HSTS, CSP, X-Frame-Options, etc.)
- CORS with safe defaults (deny all origins unless explicitly configured)
- Request ID (UUID) on every request/response
- Payload size limit (1 MB default)
- Structured JSON errors (never leaks internal info)
- Panic handler (returns structured 500, no stack traces)
- JWT signature validation (HS256 via `jsonwebtoken`)
- Scope verification per endpoint

## Schema Attributes

```rust
#[a3(min_length = N)]        // String min length
#[a3(max_length = N)]        // String max length
#[a3(pattern = "regex")]     // Regex pattern match
#[a3(format = "email")]      // Email format validation
#[a3(format = "uuid")]       // UUID format validation
#[a3(min = N)]               // Numeric minimum
#[a3(max = N)]               // Numeric maximum
#[a3(sanitize(trim))]        // Trim whitespace
#[a3(sanitize(lowercase))]   // Convert to lowercase
#[a3(sanitize(strip_html))]  // Remove HTML tags
#[a3(pii)]                   // Mark as PII (metadata only)
```

## Error Attributes

```rust
#[a3(status = 404, message = "User not found")]           // Required
#[a3(status = 502, retryable, message = "DB unavailable")] // retryable flag
```

## Builder Methods

```rust
Service::builder()
    .name("service-name")                          // Required
    .version("1.0.0")                              // Required
    .endpoint(handler_fn())                        // Add endpoint
    .auth(JwtAuth::from_env()?)                    // JWT auth (required if any JWT endpoint)
    .cors_allow_origins(&["https://example.com"])  // CORS origins (default: deny all)
    .payload_limit(2 * 1024 * 1024)                // Body limit (default: 1 MB)
    .rate_limit_backend(InMemoryBackend::new())    // Rate limit backend (default: in-memory)
    .build()?                                      // Validates and builds
```

## Response Types

- `Json<T>` — 200 OK with JSON body
- `Created<T>` — 201 Created with JSON body
- `A3Result<T, E>` — Result alias (Ok = success, Err = structured error)
- `HealthStatus::ok("version")` — Standard health check response

## Environment Variables

- `JWT_SECRET` — HMAC secret for JWT validation (default: "dev-secret")
- `RUST_LOG` — Log level filter (e.g., "info", "debug")
