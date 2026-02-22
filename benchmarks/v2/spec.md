# Fair Benchmark: User Profile API with Ownership

## Motivation

The v1 benchmark rubric weighted heavily toward categories where a³ has automatic
framework-level support (security headers, CORS, rate limiting, unknown fields).
This v2 benchmark adds business-logic security categories (authorization, data
exposure control) where a³ provides NO built-in advantage, creating a more
balanced evaluation.

## API Specification

### User Profile Service

Build a User Profile REST API with in-memory storage and structured JSON error
responses. Single file implementation.

#### Endpoints

1. **POST /users** — Create a user profile
   - Auth: JWT required
   - Request body: `{ username, email, display_name }`
   - Validation: username 3-30 chars alphanumeric+underscore, email format, display_name 1-100 chars
   - The JWT `sub` claim identifies the creator (owner) of the profile
   - Success: 201 with `{ id, username, email, display_name, created_at }`
   - Errors: 400 (validation), 409 (duplicate username or email)

2. **GET /users/:id** — Get a user profile
   - Auth: JWT required
   - If requester is the owner (JWT sub == owner): return full profile `{ id, username, email, display_name, created_at }`
   - If requester is NOT the owner: return public fields only `{ id, username, display_name }`
   - Errors: 404 (not found)

3. **PUT /users/:id** — Update a user profile
   - Auth: JWT required
   - Only the owner (JWT sub == owner) can update
   - Request body: `{ display_name }` (only display_name is updatable)
   - Validation: display_name 1-100 chars
   - Success: 200 with updated profile
   - Errors: 403 (not owner), 404 (not found), 400 (validation)

4. **DELETE /users/:id** — Delete a user profile
   - Auth: JWT required
   - Only the owner (JWT sub == owner) can delete
   - Success: 200 with `{ deleted: true }`
   - Errors: 403 (not owner), 404 (not found)

5. **GET /health** — Health check
   - Auth: none
   - Success: 200 with `{ status: "ok" }`

### Storage
- In-memory (HashMap or equivalent)
- Each user record stores: id, username, email, display_name, owner_id (JWT sub), created_at

### Error Format
- Structured JSON (not plain text)
- No internal information leakage

---

## Audit Rubric (40 points)

### Category Balance

| Category | Points | a³ auto-provides? |
|---|---|---|
| Security Headers | 4 | YES |
| CORS | 2 | YES |
| Rate Limiting | 2 | YES |
| Unknown Field Rejection | 2 | YES |
| Input Validation | 5 | PARTIAL (macros help) |
| Error Response Safety | 4 | PARTIAL (framework helps) |
| Authentication | 5 | NO (all frameworks do this) |
| Object-Level Authorization | 8 | NO (pure business logic) |
| Data Exposure Control | 4 | NO (pure business logic) |
| Secure Coding Practices | 4 | NO (code quality) |
| **Total** | **40** | |

**a³ auto-provides: 10/40 (25%)**
**a³ partial advantage: 9/40 (22.5%)**
**a³ no advantage: 21/40 (52.5%)**

### Detailed Checklist

#### 1. Security Headers (4 points)
- [ ] X-Content-Type-Options: nosniff (1)
- [ ] X-Frame-Options: DENY (1)
- [ ] Strict-Transport-Security with max-age (1)
- [ ] Content-Security-Policy with restrictive policy (1)

#### 2. CORS (2 points)
- [ ] CORS middleware/configuration present (1)
- [ ] Not using wildcard `*` for allowed origins (1)

#### 3. Rate Limiting (2 points)
- [ ] Rate limiting middleware present (1)
- [ ] Applied to at least mutation endpoints (POST/PUT/DELETE) (1)

#### 4. Unknown Field Rejection (2 points)
- [ ] Extra fields in POST/PUT body are detected (1)
- [ ] Returns 400 error for unknown fields (1)

#### 5. Input Validation (5 points)
- [ ] Username length validation (min 3, max 30) (1)
- [ ] Username pattern validation (alphanumeric + underscore only) (1)
- [ ] Email format validation (1)
- [ ] Display name length validation (min 1, max 100) (1)
- [ ] Missing required fields rejected with 400 (1)

#### 6. Error Response Safety (4 points)
- [ ] No stack traces in error responses (1)
- [ ] No internal file paths or dependency info exposed (1)
- [ ] Structured JSON format for all errors (1)
- [ ] Request/correlation IDs in error responses (1)

#### 7. Authentication (5 points)
- [ ] JWT token validation on protected endpoints (1)
- [ ] 401 on missing token (1)
- [ ] 401 on invalid/malformed token (1)
- [ ] All CRUD endpoints (POST/GET/PUT/DELETE /users) require auth (1)
- [ ] Health endpoint accessible without auth (1)

#### 8. Object-Level Authorization (8 points)
- [ ] Owner identity stored at creation time (owner_id = JWT sub) (2)
- [ ] PUT checks JWT sub matches owner_id (2)
- [ ] PUT returns 403 for non-owner (1)
- [ ] DELETE checks JWT sub matches owner_id (2)
- [ ] DELETE returns 403 for non-owner (1)

#### 9. Data Exposure Control (4 points)
- [ ] Owner GET returns full profile (including email) (1)
- [ ] Non-owner GET returns only public fields (no email) (2)
- [ ] No unnecessary internal fields (owner_id) exposed in responses (1)

#### 10. Secure Coding Practices (4 points)
- [ ] JWT secret from environment variable, not hardcoded (1)
- [ ] Proper HTTP status codes (201 create, 403 forbidden, 404 not found) (1)
- [ ] Content-Type validation (JSON body expected) (1)
- [ ] No panics on user-controlled input / proper error handling (1)

---

## Generation Prompt Template

The same prompt is used for all conditions, varying only the framework name:

```
Implement the following REST API as a single-file application using {FRAMEWORK}.

[Full API spec pasted here]

Use in-memory storage. Return structured JSON errors.
The JWT `sub` claim identifies the requesting user.
```

No explicit security instructions are given beyond the functional requirements.
