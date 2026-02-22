# acube

**Security-first server framework where forgetting security is a compile error.**

AI generates working servers -- but forgets security headers, rate limiting, input sanitization, and unknown field rejection. Not because AI is bad, but because Express, FastAPI, and axum allow it.

acube doesn't.

```rust
use acube::prelude::*;

#[acube_endpoint(GET "/health")]
#[acube_security(none)]       // <- remove this = compile error
#[acube_authorize(public)]    // <- remove this = compile error
async fn health(_ctx: AcubeContext) -> AcubeResult<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("1.0.0")))
}
```

## The Problem

We benchmarked AI-generated code across 4 frameworks. Same API spec, same AI, 3 runs each:

| Framework | Security Score | % of Max  |
| --------- | -------------- | --------- |
| Express   | 12.0 / 31      | 38.7%     |
| FastAPI   | 12.3 / 31      | 39.7%     |
| axum      | 11.7 / 31      | 37.6%     |
| **acube** | **28.0 / 31**  | **90.3%** |

The gap isn't about language. Express (JS), FastAPI (Python), and axum (Rust) all score ~38%. The problem is framework design -- when security is opt-in, AI opts out.

acube scores 90.3% because security is opt-out. You have to explicitly write `#[acube_security(none)]` to disable it.

The missing 3 points? CORS -- which has since been added as a deny-all default. Current score: **31/31**.

> **Note:** Both code generation and security auditing were performed by the same AI (Claude). See [benchmarks/report.md](benchmarks/report.md) for full methodology and scoring rubric.

## How acube solves this

Security is the default, not an add-on. Every endpoint must declare its authentication and authorization at compile time -- there is no way to "forget" it. Headers, rate limiting, CORS, and input sanitization are injected automatically. You opt out explicitly, not in.

## Install

```bash
cargo install cargo-acube
cargo acube new my-app
cd my-app
cargo run
```

Or add to an existing project:

```toml
[dependencies]
acube = "0.1"
```

Then run `cargo acube init` to generate AI instruction files for your editor.

## What acube does automatically

| Feature                 | Without acube                      | With acube                                                |
| ----------------------- | ---------------------------------- | --------------------------------------------------------- |
| Security headers (7)    | You add them manually              | Auto-injected on every response                           |
| Rate limiting           | You install middleware             | Default 100/min, opt-out with `#[acube_rate_limit(none)]` |
| Input validation        | You call validators                | `Valid<T>` validates + sanitizes before your handler runs |
| Unknown field rejection | Usually ignored                    | Strict mode always on                                     |
| CORS                    | You configure it                   | Deny-all by default, explicit allowlist                   |
| Error sanitization      | You hope you didn't leak internals | Internal details never reach the client                   |
| Authentication          | You might forget                   | `#[acube_security]` required or compile error             |
| Authorization           | You might forget                   | `#[acube_authorize]` required or compile error            |
| OpenAPI                 | You maintain it manually           | Auto-generated from your code                             |

## Code example

A typical CRUD endpoint:

```rust
#[derive(AcubeSchema, Deserialize)]
pub struct CreateTaskInput {
    #[acube(min_length = 1, max_length = 200, sanitize(trim, strip_html))]
    pub title: String,

    #[acube(max_length = 2000, sanitize(trim, strip_html))]
    pub description: Option<String>,

    #[acube(one_of = ["low", "medium", "high"])]
    pub priority: String,
}

#[derive(AcubeError, Debug)]
pub enum TaskError {
    #[acube(status = 404, message = "Task not found")]
    NotFound,

    #[acube(status = 500, retryable, message = "Database unavailable")]
    Internal,
}

#[acube_endpoint(POST "/tasks")]
#[acube_security(jwt)]
#[acube_authorize(authenticated)]
async fn create_task(ctx: AcubeContext, input: Valid<CreateTaskInput>) -> AcubeResult<Created<TaskOutput>, TaskError> {
    let pool = ctx.state::<SqlitePool>();
    let user_id = ctx.user_id();
    // ... your application logic here
    Ok(Created(task))
}

#[acube_endpoint(DELETE "/tasks/:id")]
#[acube_security(jwt)]
#[acube_authorize(authenticated)]
async fn delete_task(ctx: AcubeContext) -> AcubeResult<NoContent, TaskError> {
    let id: String = ctx.path("id");
    // ... your application logic here
    Ok(NoContent)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    acube::init_tracing();
    let service = Service::builder()
        .name("task-api")
        .version("1.0.0")
        .state(pool)
        .auth(JwtAuth::from_env()?)
        .cors_allow_origins(&["http://localhost:5173"])
        .openapi(true)  // GET /openapi.json
        .endpoint(create_task())
        .endpoint(delete_task())
        .build()?;
    acube::serve(service, "0.0.0.0:3000").await
}
```

## Authorization

acube enforces authorization declarations at compile time.

```rust
// Static: JWT claims checked automatically
#[acube_authorize(role = "admin")]           // JWT role == "admin"
#[acube_authorize(scopes = ["tasks:write"])] // JWT scopes contain "tasks:write"
#[acube_authorize(authenticated)]            // Any valid JWT

// Dynamic: your function, acube's enforcement
#[acube_authorize(custom = "check_team_role")]
async fn delete_memo(ctx: AcubeContext) -> AcubeResult<NoContent, MemoError> {
    todo!()
}

async fn check_team_role(ctx: &AcubeContext) -> Result<(), AcubeAuthError> {
    let pool = ctx.state::<SqlitePool>();
    let team_id: String = ctx.path("id");
    let user_id = ctx.user_id();
    // ... check DB, return Ok(()) or Err(AcubeAuthError::Forbidden(...))
    todo!()
}

// Public endpoint (explicit opt-out)
#[acube_security(none)]
#[acube_authorize(public)]
async fn health(_ctx: AcubeContext) -> AcubeResult<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("1.0.0")))
}
```

## AI-native

acube is designed to be used by AI coding tools. Run `cargo acube init` to generate instruction files for:

- Claude Code (`CLAUDE.md`)
- Cursor (`.cursorrules`)
- GitHub Copilot (`.github/copilot-instructions.md`)
- OpenAI Codex (`AGENTS.md`)
- Google Gemini (`GEMINI.md`)
- Windsurf (`.windsurfrules`)

These files teach AI how to use acube correctly. No training data needed.

## Performance

Measured on Apple M-series with [`oha`](https://github.com/hatoo/oha) (10s, 50 connections, release build):

| Configuration                              | Requests/sec | vs raw axum |
| ------------------------------------------ | ------------ | ----------- |
| raw axum                                   | 209,166      | baseline    |
| acube minimal                              | 189,603      | 90.6%       |
| acube full (JWT + validation + rate limit) | 174,181      | 83.3%       |

The 6-stage security pipeline adds ~10-17% overhead. p99 latency stays under 1ms.

To reproduce: `cd benchmarks/performance && bash run_benchmarks.sh`

## What acube does NOT do

acube is a security-focused server framework, not a full-stack framework.

**Not included:** Database/ORM, session management, file uploads, WebSocket, GraphQL, email, job queues, cron.

**Use alongside acube:** sqlx, sea-orm, reqwest, lettre -- anything you'd use with axum works in acube handlers.

## License

MIT
