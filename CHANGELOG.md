# Changelog

## 0.1.0 (2026-02-22)

Initial release.

- `#[derive(AcubeSchema)]` — Input validation + sanitization with recursive nested struct support
- `#[derive(AcubeError)]` — Structured error responses
- `#[acube_endpoint]` + `#[acube_security]` — Compile-time authentication enforcement
- `#[acube_authorize]` — Compile-time authorization enforcement (static roles, scopes, custom hooks)
- 7 security headers auto-injected
- CORS deny-all by default
- Rate limiting (default 100/min, configurable)
- OpenAPI 3.0 auto-generation
- `cargo acube new` / `cargo acube init` CLI
- 244 tests
