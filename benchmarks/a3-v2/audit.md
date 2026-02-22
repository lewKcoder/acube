# a³ v2 Audit Results (Post-Phase 5: CORS + JWT + Error Sanitization)

## Context

After Phase 5 implementation (default CORS, real JWT validation, error sanitization),
3 new a³ implementations were generated using the updated CLAUDE.md and audited
against the same 31-point rubric.

**Key change**: The framework now automatically applies a deny-all CORS layer.
None of the 3 runs explicitly called `.cors_allow_origins()`, but the framework's
default CORS behavior blocks all cross-origin requests — exactly the a³ philosophy
of security-by-default.

---

## Run 1

### Compile/Start: PASS
Standard a³ pattern. Uses `JwtAuth::from_env()`, `Service::builder()`, all macros correct.

### Security Headers: 7/7
Framework auto-injects all 7 headers via middleware layer. No user code needed.

### Input Validation: 5/5
- [x] username min_length=3, max_length=30, pattern="^[a-zA-Z0-9_]+$"
- [x] email format="email"
- [x] display_name min_length=1, max_length=100
- [x] sanitize(trim), sanitize(trim, lowercase), sanitize(trim, strip_html)
- [x] A3Schema derives deny_unknown_fields

### Unknown Field Rejection: 3/3
`Valid<T>` with `A3Schema` automatically rejects unknown fields with structured 400.

### Error Safety: 5/5
- [x] A3Error derive: structured JSON, no internals
- [x] Validation errors: field names only (Phase 5 sanitization)
- [x] Request IDs on all responses
- [x] Deserialization errors: generic "Invalid request body"
- [x] No stack traces (panic handler)

### Rate Limiting: 3/3
- [x] `#[a3_rate_limit(10, per_minute)]` on create_user
- [x] Default 100/min on get_user, delete_user
- [x] `#[a3_rate_limit(none)]` on health

### Auth: 5/5
- [x] `JwtAuth::from_env()` — real JWT validation (HS256)
- [x] jwt scopes on create/read/delete
- [x] `#[a3_security(none)]` on health
- [x] 401 on missing/invalid/expired tokens

### CORS: 3/3
Framework applies deny-all CORS layer automatically. No explicit call needed.
- [x] CorsLayer present (via framework)
- [x] Origin restriction: deny all (no wildcard)
- [x] Methods/headers configured (GET, POST, PUT, PATCH, DELETE; Content-Type, Authorization)

### **Total: 31/31**

---

## Run 2

### Compile/Start: PASS
Uses `UserDb` struct with `next_id` counter (avoids ID collision after deletes).
Calls `.rate_limit_backend(InMemoryBackend::new())` explicitly.

### Security Headers: 7/7
Framework auto-injects.

### Input Validation: 5/5
Same validation attributes as Run 1. All correct.

### Unknown Field Rejection: 3/3
`Valid<T>` + `A3Schema` = automatic.

### Error Safety: 5/5
Same framework guarantees. `DeleteConfirmation` typed struct (not ad-hoc JSON).

### Rate Limiting: 3/3
- [x] `#[a3_rate_limit(30, per_minute)]` on create_user (different limit, still present)
- [x] Default 100/min on get/delete
- [x] `#[a3_rate_limit(none)]` on health

### Auth: 5/5
- [x] `JwtAuth::from_env()` — real JWT
- [x] `#[a3_security(jwt)]` without explicit scopes (valid — any authenticated user)
- [x] `#[a3_security(none)]` on health

### CORS: 3/3
Framework default deny-all. Same as Run 1.

### **Total: 31/31**

---

## Run 3

### Compile/Start: PASS
Different naming: `NewUserPayload`, `UserResponse`, `UserServiceError`, `register_user`, `fetch_user`, `remove_user`.

### Security Headers: 7/7
Framework auto-injects.

### Input Validation: 5/5
Same validation attributes. All correct.

### Unknown Field Rejection: 3/3
`Valid<T>` + `A3Schema` = automatic.

### Error Safety: 5/5
Same framework guarantees. `DeleteConfirmation` typed struct.

### Rate Limiting: 3/3
- [x] `#[a3_rate_limit(10, per_minute)]` on register_user
- [x] Default 100/min on fetch/remove
- [x] `#[a3_rate_limit(none)]` on health

### Auth: 5/5
- [x] `JwtAuth::from_env()` — real JWT
- [x] jwt scopes on create/read/delete
- [x] `#[a3_security(none)]` on health

### CORS: 3/3
Framework default deny-all. Same as Run 1.

### **Total: 31/31**

---

## Summary

| Run | Score | Notes |
|-----|-------|-------|
| Run 1 | 31/31 | Standard pattern, explicit scopes |
| Run 2 | 31/31 | UserDb struct, no explicit scopes, 30/min rate limit |
| Run 3 | 31/31 | Different naming throughout, explicit scopes |
| **Mean** | **31.0** | **100%** |
| **Std Dev** | **0.0** | Zero variance |

**The 3-point CORS gap from v1 has been closed.** The framework now provides
31/31 security coverage automatically.
