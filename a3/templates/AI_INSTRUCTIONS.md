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

## Dynamic Authorization (Multi-tenant / Resource-based)

`#[a3_authorize(role = "admin")]` and `#[a3_authorize(scopes = [...])]` verify
static claims baked into the JWT at token issuance.

For apps where roles vary per team/project (e.g., admin in Team A, viewer in Team B),
JWT static claims are insufficient.

Use `#[a3_authorize(authenticated)]` and verify permissions in the handler:

```rust
#[a3_endpoint(DELETE "/teams/:id/memos/:memo_id")]
#[a3_security(jwt)]
#[a3_authorize(authenticated)]  // a3 only verifies JWT validity
async fn delete_memo(ctx: A3Context) -> A3Result<NoContent, MemoError> {
    let pool = ctx.state::<SqlitePool>();
    let user_id = ctx.user_id();
    let team_id: String = ctx.path("id");

    // Look up the user's role in this specific team from DB
    let role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM team_members WHERE team_id = ? AND user_id = ?"
    )
    .bind(&team_id)
    .bind(user_id)
    .fetch_optional(&pool)
    .await
    .map_err(|_| MemoError::Internal)?
    .ok_or(MemoError::Forbidden)?;

    if role != "admin" && role != "member" {
        return Err(MemoError::Forbidden);
    }

    // ... delete logic
}
```

When to use which:
- `role = "admin"` / `scopes = [...]` — same permissions for all resources (global admin, API key scopes)
- `authenticated` + handler check — permissions vary per resource (teams, projects, organizations)

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
#[a3(format = "url")]        // URL format validation (http/https)
#[a3(format = "uuid")]       // UUID format validation
#[a3(min = N)]               // Numeric minimum
#[a3(max = N)]               // Numeric maximum
#[a3(sanitize(trim))]        // Trim whitespace
#[a3(sanitize(lowercase))]   // Convert to lowercase
#[a3(sanitize(strip_html))]  // Remove HTML tags
#[a3(pii)]                   // Mark as PII (metadata only)
```

### Field Types

```rust
// Option<T> — None skips validation, Some(v) validates v
#[a3(max_length = 1000)]
#[a3(sanitize(strip_html))]
pub description: Option<String>,

// bool — no validation attributes needed, works as-is
pub is_active: bool,

// Vec<T> — element-level validation is not supported;
// validate individual elements in your handler if needed
pub tags: Vec<String>,
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
    .state(pool)                                   // Shared state → ctx.state::<T>()
    .auth(JwtAuth::from_env()?)                    // JWT auth (required if any JWT endpoint)
    .cors_allow_origins(&["https://example.com"])  // CORS origins (default: deny all)
    .content_security_policy("default-src 'self'") // CSP (default: "default-src 'none'")
    .payload_limit(2 * 1024 * 1024)                // Body limit (default: 1 MB)
    .rate_limit_backend(InMemoryBackend::new())    // Rate limit backend (default: in-memory)
    .build()?                                      // Validates and builds
```

`.state(value)` adds shared application state accessible via `ctx.state::<T>()` in handlers.
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

// Handler — use ctx.state::<T>()
#[a3_endpoint(GET "/items")]
#[a3_security(jwt)]
#[a3_authorize(scopes = ["items:read"])]
async fn handler(ctx: A3Context) -> A3Result<Json<Vec<Item>>, ItemError> {
    let pool = ctx.state::<SqlitePool>();
    // use pool...
}
```

## Response Types

- `Json<T>` — 200 OK with JSON body
- `Created<T>` — 201 Created with JSON body
- `NoContent` — 204 No Content (empty body, use for DELETE endpoints)
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

## A3Context Helpers

`A3Context` provides convenience methods for common operations:

```rust
// Get authenticated user ID (panics if not authenticated — use only with #[a3_security(jwt)])
let user_id = ctx.user_id();

// Get path parameters (panics if not found — route must define the param)
let id: String = ctx.path("id");
let page: i32 = ctx.path("page");

// Get shared state (panics if not registered — must call .state(value) on builder)
let pool = ctx.state::<SqlitePool>();
```

All panics are intentional for developer configuration errors. a3's panic handler returns a structured 500 response.

### Full Example: DELETE endpoint

```rust
#[a3_endpoint(DELETE "/items/:id")]
#[a3_security(jwt)]
#[a3_authorize(scopes = ["items:delete"])]
async fn delete_item(ctx: A3Context) -> A3Result<NoContent, ItemError> {
    let id: String = ctx.path("id");
    let user_id = ctx.user_id();
    let pool = ctx.state::<SqlitePool>();
    // delete item...
    Ok(NoContent)
}
```

### Full Example: PATCH with path + body

```rust
#[a3_endpoint(PATCH "/items/:id")]
#[a3_security(jwt)]
#[a3_authorize(scopes = ["items:update"])]
async fn update_item(
    ctx: A3Context,
    input: Valid<UpdateItemInput>,
) -> A3Result<Json<ItemOutput>, ItemError> {
    let id: String = ctx.path("id");
    let pool = ctx.state::<SqlitePool>();
    let input = input.into_inner();
    // update item...
    Ok(Json(item))
}
```

### Query Parameters

Use `axum::extract::Query<T>` as an additional handler parameter:

```rust
#[derive(Deserialize)]
pub struct ListParams {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[a3_endpoint(GET "/items")]
#[a3_security(jwt)]
#[a3_authorize(authenticated)]
async fn list_items(
    ctx: A3Context,
    axum::extract::Query(params): axum::extract::Query<ListParams>,
) -> A3Result<Json<ItemList>, ItemError> {
    let pool = ctx.state::<SqlitePool>();
    let page = params.page.unwrap_or(1);
    // ...
}
```

### Endpoint Registration Order

When two routes can match the same path, register the more specific one first:

```rust
// /items/search must come before /items/:id
// otherwise "search" matches as an :id value
Service::builder()
    .endpoint(search_items())   // GET /items/search — first
    .endpoint(get_item())       // GET /items/:id    — second
```

## AuthIdentity

When an endpoint has `#[a3_security(jwt)]`, the authenticated identity is available via `ctx.auth`:

```rust
#[a3_endpoint(GET "/me")]
#[a3_security(jwt)]
#[a3_authorize(scopes = ["profile:read"])]
async fn get_me(ctx: A3Context) -> A3Result<Json<Profile>, MyError> {
    let user_id = ctx.user_id();       // Shorthand for ctx.auth subject
    let identity = ctx.auth.as_ref().unwrap(); // Full identity access
    let scopes = &identity.scopes;             // Granted scopes
    let role = &identity.role;                 // Role claim (Option<String>)
    // ...
}
```

- `ctx.user_id()` — shorthand for the JWT `sub` claim (panics if not authenticated)
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
