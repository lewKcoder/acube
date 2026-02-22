This project uses the acube framework. Follow the rules below when generating code.

# acube (エーキューブ) — AI Security Framework for Rust

## What is acube?

acube is a Rust web framework that enforces server-side security at the syntax level.
Security is opt-out, not opt-in — if you don't declare security, it won't compile.

Built on axum 0.7 + tower 0.4 + tokio 1.

## Quick Start

```rust
use acube::prelude::*;

#[derive(AcubeSchema, Debug, Deserialize)]
pub struct CreateUserInput {
    #[acube(min_length = 3, max_length = 30, pattern = "^[a-zA-Z0-9_]+$")]
    #[acube(sanitize(trim))]
    pub username: String,

    #[acube(format = "email", pii)]
    #[acube(sanitize(trim, lowercase))]
    pub email: String,

    #[acube(min_length = 1, max_length = 100)]
    #[acube(sanitize(trim, strip_html))]
    pub display_name: String,
}

#[derive(AcubeError, Debug)]
pub enum UserError {
    #[acube(status = 404, message = "User not found")]
    NotFound,
    #[acube(status = 409, message = "Username already taken")]
    UsernameTaken,
}

#[acube_endpoint(POST "/users")]
#[acube_security(jwt)]
#[acube_authorize(scopes = ["users:create"])]
#[acube_rate_limit(10, per_minute)]
async fn create_user(
    ctx: AcubeContext,
    input: Valid<CreateUserInput>,
) -> AcubeResult<Created<UserOutput>, UserError> {
    let input = input.into_inner();
    // Business logic here...
    Ok(Created(user))
}

#[acube_endpoint(GET "/health")]
#[acube_security(none)]
#[acube_authorize(public)]
#[acube_rate_limit(none)]
async fn health_check(_ctx: AcubeContext) -> AcubeResult<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("1.0.0")))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    acube::init_tracing();
    let service = Service::builder()
        .name("my-service")
        .version("1.0.0")
        .endpoint(create_user())
        .endpoint(health_check())
        .auth(JwtAuth::from_env()?)
        .cors_allow_origins(&["https://myapp.com"])
        .build()?;
    acube::serve(service, "0.0.0.0:3000").await
}
```

## Rules (MUST follow)

1. **Every endpoint MUST have `#[acube_security(...)]`** — otherwise it won't compile.
   - `#[acube_security(jwt)]` for JWT-authenticated endpoints
   - `#[acube_security(none)]` to explicitly opt out (e.g., health checks)

2. **Every endpoint MUST have `#[acube_authorize(...)]`** — otherwise it won't compile.
   - `#[acube_authorize(scopes = ["scope:name"])]` — requires specific scopes
   - `#[acube_authorize(role = "admin")]` — requires a specific role
   - `#[acube_authorize(authenticated)]` — requires any valid JWT (no scopes/role check)
   - `#[acube_authorize(custom = "fn_name")]` — calls a custom async function for authorization
   - `#[acube_authorize(public)]` — no authorization (must pair with `#[acube_security(none)]`)

3. **Consistency rules** (compile errors if violated):
   - `#[acube_security(none)]` + `#[acube_authorize(scopes/role/authenticated/custom)]` → error
   - `#[acube_security(jwt)]` + `#[acube_authorize(public)]` → error

4. **Rate limiting is automatic** — default 100/min per endpoint.
   - Override: `#[acube_rate_limit(10, per_minute)]`
   - Disable: `#[acube_rate_limit(none)]`

5. **Use `Valid<T>` for input** — handles validation, sanitization, and unknown field rejection.
   - T must derive `AcubeSchema` and `Deserialize`
   - Returns structured 400 errors automatically

6. **Use `AcubeResult<T, E>`** where E derives `AcubeError`.
   - Use `Never` as the error type for infallible endpoints.

7. **First parameter is always `AcubeContext`** (or `_ctx: AcubeContext`).

## Dynamic Authorization (Multi-tenant / Resource-based)

`#[acube_authorize(role = "admin")]` and `#[acube_authorize(scopes = [...])]` verify
static claims baked into the JWT at token issuance.

For apps where roles vary per team/project (e.g., admin in Team A, viewer in Team B),
JWT static claims are insufficient.

Use `#[acube_authorize(authenticated)]` and verify permissions in the handler:

```rust
#[acube_endpoint(DELETE "/teams/:id/memos/:memo_id")]
#[acube_security(jwt)]
#[acube_authorize(authenticated)]  // acube only verifies JWT validity
async fn delete_memo(ctx: AcubeContext) -> AcubeResult<NoContent, MemoError> {
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

### Custom Authorization Hook

For reusable resource-based authorization (e.g., ownership checks), use `#[acube_authorize(custom = "fn_name")]`:

```rust
async fn check_owner(ctx: &AcubeContext) -> Result<(), AcubeAuthError> {
    let image_id: String = ctx.path("id");
    let pool = ctx.state::<SqlitePool>();
    let user_id = ctx.user_id();

    let owner = sqlx::query_scalar::<_, String>(
        "SELECT user_id FROM images WHERE id = ?"
    )
    .bind(&image_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| AcubeAuthError::Forbidden("Internal error".into()))?
    .ok_or(AcubeAuthError::Forbidden("Not found".into()))?;

    if owner != user_id {
        return Err(AcubeAuthError::Forbidden("Not the owner".into()));
    }
    Ok(())
}

#[acube_endpoint(DELETE "/images/:id")]
#[acube_security(jwt)]
#[acube_authorize(custom = "check_owner")]
async fn delete_image(ctx: AcubeContext) -> AcubeResult<NoContent, ImageError> {
    // Only reaches here if check_owner returned Ok(())
    // ... delete logic
}
```

- The custom function signature must be `async fn(ctx: &AcubeContext) -> Result<(), AcubeAuthError>`
- `AcubeAuthError::Forbidden(msg)` returns a structured 403 response
- JWT is validated first (middleware layer), then the custom function runs
- `#[acube_security(none)]` + `#[acube_authorize(custom = "...")]` is a compile error

When to use which:

- `role = "admin"` / `scopes = [...]` — same permissions for all resources (global admin, API key scopes)
- `custom = "fn_name"` — reusable per-resource authorization (ownership, team membership)
- `authenticated` + handler check — inline one-off authorization logic

## What acube does automatically

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
#[acube(min_length = N)]        // String min length
#[acube(max_length = N)]        // String max length
#[acube(pattern = "regex")]     // Regex pattern match
#[acube(format = "email")]      // Email format validation
#[acube(format = "url")]        // URL format validation (http/https)
#[acube(format = "uuid")]       // UUID format validation
#[acube(min = N)]               // Numeric minimum (i32, i64, f64)
#[acube(max = N)]               // Numeric maximum (i32, i64, f64)
#[acube(sanitize(trim))]        // Trim whitespace
#[acube(sanitize(lowercase))]   // Convert to lowercase
#[acube(sanitize(strip_html))]  // Remove HTML tags
#[acube(pii)]                   // Mark as PII (metadata only)
#[acube(one_of = ["a", "b"])]  // Allowed values (enum validation)
```

### Field Types

```rust
// Option<T> — None skips validation, Some(v) validates v
#[acube(max_length = 1000)]
#[acube(sanitize(strip_html))]
pub description: Option<String>,

// bool — no validation attributes needed, works as-is
pub is_active: bool,

// Vec<T> — element-level validation is not supported;
// validate individual elements in your handler if needed
pub tags: Vec<String>,

// Nested AcubeSchema structs — recursively validated
pub exif: ExifInput,           // always validated
pub exif_opt: Option<ExifInput>, // validated when Some
pub items: Vec<TagInput>,      // each element validated
```

### Nested Struct Validation

Fields typed as another `AcubeSchema` struct are recursively validated. Error field paths are prefixed (e.g., `"exif.iso"`, `"items[0].name"`).

```rust
#[derive(AcubeSchema, Debug, Deserialize)]
pub struct ExifInput {
    #[acube(max = 102400)]
    pub iso: Option<i32>,
}

#[derive(AcubeSchema, Debug, Deserialize)]
pub struct CreateImageInput {
    #[acube(min_length = 1)]
    pub title: String,
    pub exif: ExifInput,             // recursively validated
    pub exif_opt: Option<ExifInput>, // validated when Some
    pub tags: Vec<TagInput>,         // each element validated
}
```

### `one_of` Validation

Restrict a string field to a set of allowed values:

```rust
#[acube(one_of = ["draft", "published", "archived"])]
pub status: String,

#[acube(one_of = ["active", "inactive"])]
pub state: Option<String>,  // None skips check, Some validates
```

### Option<数値型> のバリデーション

Option<T> に min/max を付けた場合、None はスキップ、Some なら検証されます:

```rust
#[derive(AcubeSchema, Debug, Deserialize)]
pub struct ExifInput {
    #[acube(min = 50, max = 102400)]
    pub iso: Option<i32>,       // None → OK、Some(100) → OK、Some(999999) → エラー

    #[acube(min = 0.0)]
    pub focal_length: Option<f64>,  // f64 の min/max もサポート
}
```

## Error Attributes

```rust
#[acube(status = 404, message = "User not found")]           // Required
#[acube(status = 502, retryable, message = "DB unavailable")] // retryable flag
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

acube::serve(service, "0.0.0.0:3000").await

// Handler — use ctx.state::<T>()
#[acube_endpoint(GET "/items")]
#[acube_security(jwt)]
#[acube_authorize(scopes = ["items:read"])]
async fn handler(ctx: AcubeContext) -> AcubeResult<Json<Vec<Item>>, ItemError> {
    let pool = ctx.state::<SqlitePool>();
    // use pool...
}
```

## Response Types

- `Json<T>` — 200 OK with JSON body
- `Created<T>` — 201 Created with JSON body
- `NoContent` — 204 No Content (empty body, use for DELETE endpoints)
- `AcubeResult<T, E>` — Result alias (Ok = success, Err = structured error)
- `HealthStatus::ok("version")` — Standard health check response

## JWT Algorithms

acube supports HS256, RS256, and ES256:

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

## AcubeContext Helpers

`AcubeContext` provides convenience methods for common operations:

```rust
// Get authenticated user ID (panics if not authenticated — use only with #[acube_security(jwt)])
let user_id = ctx.user_id();

// Get path parameters (panics if not found — route must define the param)
let id: String = ctx.path("id");
let page: i32 = ctx.path("page");

// Get shared state (panics if not registered — must call .state(value) on builder)
let pool = ctx.state::<SqlitePool>();
```

All panics are intentional for developer configuration errors. acube's panic handler returns a structured 500 response.

### Full Example: DELETE endpoint

```rust
#[acube_endpoint(DELETE "/items/:id")]
#[acube_security(jwt)]
#[acube_authorize(scopes = ["items:delete"])]
async fn delete_item(ctx: AcubeContext) -> AcubeResult<NoContent, ItemError> {
    let id: String = ctx.path("id");
    let user_id = ctx.user_id();
    let pool = ctx.state::<SqlitePool>();
    // delete item...
    Ok(NoContent)
}
```

### Full Example: PATCH with path + body

```rust
#[acube_endpoint(PATCH "/items/:id")]
#[acube_security(jwt)]
#[acube_authorize(scopes = ["items:update"])]
async fn update_item(
    ctx: AcubeContext,
    input: Valid<UpdateItemInput>,
) -> AcubeResult<Json<ItemOutput>, ItemError> {
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

#[acube_endpoint(GET "/items")]
#[acube_security(jwt)]
#[acube_authorize(authenticated)]
async fn list_items(
    ctx: AcubeContext,
    axum::extract::Query(params): axum::extract::Query<ListParams>,
) -> AcubeResult<Json<ItemList>, ItemError> {
    let pool = ctx.state::<SqlitePool>();
    let page = params.page.unwrap_or(1);
    // ...
}
```

### ページネーション（カーソルベース推奨）

```rust
#[derive(Deserialize)]
pub struct ListParams {
    pub cursor: Option<String>,  // 前回最後のID
    pub limit: Option<i64>,      // デフォルト20、最大100
}

#[acube_endpoint(GET "/items")]
#[acube_security(jwt)]
#[acube_authorize(authenticated)]
async fn list_items(
    ctx: AcubeContext,
    Query(params): Query<ListParams>,
) -> AcubeResult<Json<ListResponse>, ItemError> {
    let pool = ctx.state::<SqlitePool>();
    let user_id = ctx.user_id();
    let limit = params.limit.unwrap_or(20).min(100);
    let fetch_limit = limit + 1; // 1つ多く取得して has_more を判定

    let items = match &params.cursor {
        Some(cursor) => {
            sqlx::query_as("SELECT * FROM items WHERE user_id = ? AND id < ? ORDER BY id DESC LIMIT ?")
                .bind(user_id).bind(cursor).bind(fetch_limit)
                .fetch_all(pool).await
        }
        None => {
            sqlx::query_as("SELECT * FROM items WHERE user_id = ? ORDER BY id DESC LIMIT ?")
                .bind(user_id).bind(fetch_limit)
                .fetch_all(pool).await
        }
    }.map_err(|_| ItemError::Internal)?;

    let has_more = items.len() as i64 > limit;
    let items: Vec<_> = items.into_iter().take(limit as usize).collect();
    let next_cursor = if has_more { items.last().map(|i| i.id.clone()) } else { None };

    Ok(Json(ListResponse { items, next_cursor, has_more }))
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

When an endpoint has `#[acube_security(jwt)]`, the authenticated identity is available via `ctx.auth`:

```rust
#[acube_endpoint(GET "/me")]
#[acube_security(jwt)]
#[acube_authorize(scopes = ["profile:read"])]
async fn get_me(ctx: AcubeContext) -> AcubeResult<Json<Profile>, MyError> {
    let user_id = ctx.user_id();       // Shorthand for ctx.auth subject
    let identity = ctx.auth.as_ref().unwrap(); // Full identity access
    let scopes = &identity.scopes;             // Granted scopes
    let role = &identity.role;                 // Role claim (Option<String>)
    // ...
}
```

- `ctx.user_id()` — shorthand for the JWT `sub` claim (panics if not authenticated)
- `ctx.auth` is `Option<AuthIdentity>` — `Some` for JWT endpoints, `None` for `#[acube_security(none)]`
- `AuthIdentity.subject: String` — the JWT `sub` claim (typically user ID)
- `AuthIdentity.scopes: Vec<String>` — the granted scopes
- `AuthIdentity.role: Option<String>` — the role claim

## JWT Claims

When issuing JWTs (e.g., login/register endpoints), use the `JwtClaims` struct:

```rust
use acube::prelude::*;   // JwtClaims, ScopeClaim are in the prelude
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

## 所有権チェック（リソースの所有者確認）

複数のエンドポイントで「自分のリソースのみ操作可能」を実装する場合、
ヘルパー関数を定義して繰り返しを減らしてください:

```rust
async fn verify_owner(
    pool: &SqlitePool,
    table: &str,
    id: &str,
    user_id: &str,
) -> Result<(), ItemError> {
    let query = format!("SELECT user_id FROM {} WHERE id = ?", table);
    let owner: Option<String> = sqlx::query_scalar(&query)
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|_| ItemError::Internal)?
        .ok_or(ItemError::NotFound)?;  // 存在しない → 404

    if owner != user_id {
        return Err(ItemError::NotFound);  // 他人のリソース → 404（403ではなく）
    }
    Ok(())
}

// 使用例
async fn delete_item(ctx: AcubeContext) -> AcubeResult<NoContent, ItemError> {
    let pool = ctx.state::<SqlitePool>();
    let user_id = ctx.user_id();
    let id: String = ctx.path("id");

    verify_owner(pool, "items", &id, user_id).await?;
    sqlx::query("DELETE FROM items WHERE id = ?").bind(&id).execute(pool).await
        .map_err(|_| ItemError::Internal)?;
    Ok(NoContent)
}
```

注意: 他人のリソースには 403 (Forbidden) ではなく 404 (Not Found) を返してください。
403 はリソースの存在を攻撃者に漏らします。

## Environment Variables

- `JWT_ALGORITHM` — Algorithm for JWT validation: `HS256` (default), `RS256`, `ES256`
- `JWT_SECRET` — HMAC secret for HS256 (default: "dev-secret")
- `JWT_PUBLIC_KEY` — PEM public key for RS256/ES256
- `RUST_LOG` — Log level filter (e.g., "info", "debug")
