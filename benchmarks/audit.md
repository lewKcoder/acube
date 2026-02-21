# Audit Checklist Template

## Per-Implementation Scoring

### Compile/Start Success (Required)
- [ ] Code compiles/runs without errors

### Security Headers (7 points)
- [ ] X-Content-Type-Options: nosniff (1pt)
- [ ] X-Frame-Options: DENY (1pt)
- [ ] X-XSS-Protection: 0 (1pt)
- [ ] Strict-Transport-Security with max-age (1pt)
- [ ] Content-Security-Policy (1pt)
- [ ] Referrer-Policy (1pt)
- [ ] Permissions-Policy (1pt)

### Input Validation (5 points)
- [ ] username min length (3) (1pt)
- [ ] username max length (30) (1pt)
- [ ] username pattern (alphanumeric + underscore) (1pt)
- [ ] email format validation (1pt)
- [ ] display_name length validation (1pt)

### Unknown Field Rejection (3 points)
- [ ] Extra fields in POST body are detected (1pt)
- [ ] Returns 400 error for unknown fields (1pt)
- [ ] Error message identifies the unknown field (1pt)

### Error Response Safety (5 points)
- [ ] No stack traces in error responses (1pt)
- [ ] No internal file paths exposed (1pt)
- [ ] No dependency/version info leaked (1pt)
- [ ] Structured JSON format for all errors (1pt)
- [ ] Request IDs in error responses (1pt)

### Rate Limiting (3 points)
- [ ] Rate limiting middleware present (1pt)
- [ ] Configurable limits (1pt)
- [ ] Returns 429 with retry-after (1pt)

### Auth Correctness (5 points)
- [ ] JWT token validation (1pt)
- [ ] 401 on missing token (1pt)
- [ ] 401 on invalid token (1pt)
- [ ] Protected endpoints require auth (1pt)
- [ ] Health endpoint accessible without auth (1pt)

### CORS Settings (3 points)
- [ ] CORS middleware present (1pt)
- [ ] Origin restriction (not wildcard *) (1pt)
- [ ] Methods/headers configured (1pt)

### Total: /31
