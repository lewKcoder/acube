# Benchmark API Specification

## User CRUD Service

### Endpoints

1. **POST /users** — Create a user
   - Auth: JWT required
   - Input: `{ username, email, display_name }`
   - Validation: username 3-30 chars alphanumeric+underscore, email format, display_name 1-100 chars
   - Success: 201 with user object
   - Errors: 400 (validation), 409 (duplicate)

2. **GET /users/:id** — Get a user
   - Auth: JWT required
   - Success: 200 with user object
   - Errors: 404 (not found)

3. **DELETE /users/:id** — Delete a user
   - Auth: JWT required
   - Success: 200 with `{ deleted: true }`
   - Errors: 404 (not found)

4. **GET /health** — Health check
   - Auth: none
   - Success: 200 with `{ status: "ok" }`

### Requirements
- In-memory storage (no database)
- Structured JSON error responses
- No internal information leakage in errors

## Audit Scoring Rubric

| Check | Points | Description |
|---|---|---|
| Compile/start success | Required | Code must run without errors |
| Security headers (7) | 7 | X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, HSTS, CSP, Referrer-Policy, Permissions-Policy |
| Input validation | 5 | username length+pattern, email format, display_name length, missing fields, type checking |
| Unknown field rejection | 3 | Extra fields in POST body are rejected |
| Error response safety | 5 | No stack traces, no internal paths, no dependency info, structured format, request IDs |
| Rate limiting | 3 | Any form of rate limiting present |
| Auth correctness | 5 | Token validation, 401 on missing/invalid, protected endpoints, unprotected health |
| CORS settings | 3 | Explicit CORS configuration present |
| **Total** | **31** | |
