This project uses the a3 framework. Follow the rules below when generating code.

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
#[a3_security(jwt)]
#[a3_authorize(scopes = ["users:create"])]
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
#[a3_authorize(public)]
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
   - `#[a3_security(jwt)]` for JWT-authenticated endpoints
   - `#[a3_security(none)]` to explicitly opt out (e.g., health checks)

2. **Every endpoint MUST have `#[a3_authorize(...)]`** — otherwise it won't compile.
   - `#[a3_authorize(scopes = ["scope:name"])]` — requires specific scopes
   - `#[a3_authorize(role = "admin")]` — requires a specific role
   - `#[a3_authorize(authenticated)]` — requires any valid JWT (no scopes/role check)
   - `#[a3_authorize(public)]` — no authorization (must pair with `#[a3_security(none)]`)

3. **Consistency rules** (compile errors if violated):
   - `#[a3_security(none)]` + `#[a3_authorize(scopes/role/authenticated)]` → error
   - `#[a3_security(jwt)]` + `#[a3_authorize(public)]` → error

4. **Rate limiting is automatic** — default 100/min per endpoint.
   - Override: `#[a3_rate_limit(10, per_minute)]`
   - Disable: `#[a3_rate_limit(none)]`

5. **Use `Valid<T>` for input** — handles validation, sanitization, and unknown field rejection.
   - T must derive `A3Schema` and `Deserialize`
   - Returns structured 400 errors automatically

6. **Use `A3Result<T, E>`** where E derives `A3Error`.
   - Use `Never` as the error type for infallible endpoints.

7. **First parameter is always `A3Context`** (or `_ctx: A3Context`).

## What a3 does automatically

- 7 security headers on every response (HSTS, CSP, X-Frame-Options, etc.)
- CORS with safe defaults (deny all origins unless explicitly configured)
- Request ID (UUID) on every request/response
- Payload size limit (1 MB default)
- Structured JSON errors (never leaks internal info)
- Panic handler (returns structured 500, no stack traces)
- JWT signature validation (HS256 via `jsonwebtoken`)
- Authorization enforcement per endpoint (scopes, roles, authenticated)

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
    .state(pool)                                   // Shared state (Extension<T>)
    .auth(JwtAuth::from_env()?)                    // JWT auth (required if any JWT endpoint)
    .cors_allow_origins(&["https://example.com"])  // CORS origins (default: deny all)
    .content_security_policy("default-src 'self'") // CSP (default: "default-src 'none'")
    .payload_limit(2 * 1024 * 1024)                // Body limit (default: 1 MB)
    .rate_limit_backend(InMemoryBackend::new())    // Rate limit backend (default: in-memory)
    .build()?                                      // Validates and builds
```

`.state(value)` adds shared application state accessible via `axum::extract::Extension<T>` in handlers.
Can be called multiple times with different types. The value must be `Clone + Send + Sync + 'static`.

```rust
// Builder
let service = Service::builder()
    .name("my-app")
    .version("1.0.0")
    .state(pool)       // SqlitePool
    .state(config)     // AppConfig
    .endpoint(handler())
    .build()?;

a3::serve(service, "0.0.0.0:3000").await

// Handler — extract with Extension<T>
#[a3_endpoint(GET "/items")]
#[a3_security(jwt)]
#[a3_authorize(scopes = ["items:read"])]
async fn handler(
    ctx: A3Context,
    axum::extract::Extension(pool): axum::extract::Extension<SqlitePool>,
) -> A3Result<Json<Vec<Item>>, ItemError> {
    // use pool...
}
```

## Response Types

- `Json<T>` — 200 OK with JSON body
- `Created<T>` — 201 Created with JSON body
- `A3Result<T, E>` — Result alias (Ok = success, Err = structured error)
- `HealthStatus::ok("version")` — Standard health check response

## JWT Algorithms

a3 supports HS256, RS256, and ES256:

```rust
// HS256 (default) — symmetric HMAC secret
.auth(JwtAuth::new("my-secret"))
.auth(JwtAuth::from_env()?)  // reads JWT_SECRET

// RS256 — RSA public key (PEM)
.auth(JwtAuth::from_rsa_pem(include_bytes!("public_key.pem"))?)

// ES256 — EC public key (PEM, PKCS#8)
.auth(JwtAuth::from_ec_pem(include_bytes!("public_key.pem"))?)
```

`from_env()` reads `JWT_ALGORITHM` (`HS256`/`RS256`/`ES256`, default: `HS256`):

- HS256: `JWT_SECRET` (default: `"dev-secret"`)
- RS256/ES256: `JWT_PUBLIC_KEY` (PEM string, required)

## AuthIdentity

When an endpoint has `#[a3_security(jwt)]`, the authenticated identity is available via `ctx.auth`:

```rust
#[a3_endpoint(GET "/me")]
#[a3_security(jwt)]
#[a3_authorize(scopes = ["profile:read"])]
async fn get_me(ctx: A3Context) -> A3Result<Json<Profile>, MyError> {
    let identity = ctx.auth.as_ref().unwrap(); // Always Some for JWT endpoints
    let user_id = &identity.subject;           // User ID from JWT "sub" claim
    let scopes = &identity.scopes;             // Granted scopes
    let role = &identity.role;                 // Role claim (Option<String>)
    // ...
}
```

- `ctx.auth` is `Option<AuthIdentity>` — `Some` for JWT endpoints, `None` for `#[a3_security(none)]`
- `AuthIdentity.subject: String` — the JWT `sub` claim (typically user ID)
- `AuthIdentity.scopes: Vec<String>` — the granted scopes
- `AuthIdentity.role: Option<String>` — the role claim

## JWT Claims

When issuing JWTs (e.g., login/register endpoints), use the `JwtClaims` struct:

```rust
use a3::prelude::*;   // JwtClaims, ScopeClaim are in the prelude
use jsonwebtoken::{encode, EncodingKey, Header};

let claims = JwtClaims {
    sub: user_id.to_string(),                              // Subject (user ID)
    scopes: ScopeClaim(vec!["tasks:*".to_string()]),       // Granted scopes
    role: Some("admin".to_string()),                       // Role (optional)
    exp: Some(chrono::Utc::now().timestamp() as u64 + 86400), // Expiration (Unix timestamp)
    iat: Some(chrono::Utc::now().timestamp() as u64),      // Issued at
};

let token = encode(
    &Header::default(),
    &claims,
    &EncodingKey::from_secret(secret.as_bytes()),
)?;
```

- `JwtClaims.sub: String` — subject (required)
- `JwtClaims.scopes: ScopeClaim` — scopes as `ScopeClaim(Vec<String>)`
- `JwtClaims.role: Option<String>` — role claim (optional)
- `JwtClaims.exp: Option<u64>` — expiration time (Unix timestamp)
- `JwtClaims.iat: Option<u64>` — issued-at time (Unix timestamp)

`ScopeClaim` wraps `Vec<String>` and deserializes from either a JSON array `["a", "b"]` or comma-separated string `"a,b"`.

## Environment Variables

- `JWT_ALGORITHM` — Algorithm for JWT validation: `HS256` (default), `RS256`, `ES256`
- `JWT_SECRET` — HMAC secret for HS256 (default: "dev-secret")
- `JWT_PUBLIC_KEY` — PEM public key for RS256/ES256
- `RUST_LOG` — Log level filter (e.g., "info", "debug")
