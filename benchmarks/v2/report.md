# Fair Benchmark v2: AI Security Audit Report

## Methodology

**Goal**: Re-evaluate a³ with a balanced rubric where >50% of points come from
categories where a³ has NO built-in advantage.

**Changes from v1**:
- Added Object-Level Authorization (8pts) — pure business logic, a³ has no support
- Added Data Exposure Control (4pts) — pure business logic
- Added Secure Coding Practices (4pts) — code quality
- Reduced Security Headers weight (7→4) and CORS (3→2)
- Total: 40 points (was 31)

**Category balance**:
- a³ auto-provides: 10/40 (25%) — was 51.6% in v1
- a³ no advantage: 21/40 (52.5%) — was 16% in v1

**API spec**: User Profile CRUD with **ownership model** — only the creator
(JWT sub) can update/delete, non-owners see limited profile (no email).

4 conditions × 3 runs = 12 implementations generated and audited.

---

## Results

### Score Table (per run)

| Category (max) | Exp R1 | Exp R2 | Exp R3 | FAPI R1 | FAPI R2 | FAPI R3 | axum R1 | axum R2 | axum R3 | a³ R1 | a³ R2 | a³ R3 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Sec Headers (4) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **4** | **4** | **4** |
| CORS (2) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **2** | **2** | **2** |
| Rate Limit (2) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **2** | **2** | **2** |
| Unknown Fields (2) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **2** | **2** | **2** |
| Input Valid (5) | **5** | **5** | **5** | **5** | **5** | **5** | **5** | **5** | **5** | **5** | **5** | **5** |
| Error Safety (4) | 3 | 3 | 3 | 3 | 3 | 2 | 3 | 2 | 3 | **4** | **4** | **4** |
| Auth (5) | **5** | **5** | **5** | **5** | **5** | **5** | **5** | **5** | **5** | **5** | **5** | **5** |
| Authz/BOLA (8) | **8** | **8** | **8** | **8** | **8** | **8** | **8** | **8** | **8** | **8** | **8** | **8** |
| Data Exposure (4) | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** |
| Secure Coding (4) | 3 | 3 | 3 | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** | **4** |
| **Total (40)** | **28** | **28** | **28** | **29** | **29** | **28** | **29** | **28** | **29** | **40** | **40** | **40** |

### Average Scores

| Condition | Run 1 | Run 2 | Run 3 | Mean | Std Dev | % of Max |
|---|---|---|---|---|---|---|
| A: Express | 28 | 28 | 28 | **28.0** | 0.00 | 70.0% |
| B: FastAPI | 29 | 29 | 28 | **28.7** | 0.58 | 71.7% |
| C: axum | 29 | 28 | 29 | **28.7** | 0.58 | 71.7% |
| D: **a³** | 40 | 40 | 40 | **40.0** | 0.00 | **100.0%** |

---

## Analysis

### v1 vs v2 Comparison

| Metric | v1 (biased rubric) | v2 (fair rubric) |
|---|---|---|
| Alternative mean score | 12.0/31 (38.7%) | 28.5/40 (71.2%) |
| a³ mean score | 31.0/31 (100%) | 40.0/40 (100%) |
| Gap (points) | +19.0 | **+11.5** |
| Gap (percentage points) | +61.3pp | **+28.8pp** |
| a³ auto-provided weight | 51.6% of rubric | 25% of rubric |

The gap narrowed from 61.3pp to 28.8pp because the v2 rubric includes
business logic categories where all frameworks perform equally.

### Category-by-Category Breakdown

**Where a³ dominates (framework-enforced, 10/40 = 25%):**

| Category | A-C Mean | a³ | Gap | Why |
|---|---|---|---|---|
| Security Headers (4) | 0.0 | 4.0 | +4.0 | Auto-injected, zero user code |
| CORS (2) | 0.0 | 2.0 | +2.0 | Deny-all by default |
| Rate Limiting (2) | 0.0 | 2.0 | +2.0 | Default 100/min, explicit opt-out |
| Unknown Fields (2) | 0.0 | 2.0 | +2.0 | A3Schema + Valid\<T\> |

**Where a³ has partial advantage (9/40 = 22.5%):**

| Category | A-C Mean | a³ | Gap | Why |
|---|---|---|---|---|
| Error Safety (4) | 2.7 | 4.0 | +1.3 | Request IDs, sanitized errors |
| Secure Coding (4) | 3.7 | 4.0 | +0.3 | Framework handles content-type |

**Where ALL frameworks are equal (21/40 = 52.5%):**

| Category | A-C Mean | a³ | Gap | Why |
|---|---|---|---|---|
| Input Validation (5) | 5.0 | 5.0 | 0.0 | All frameworks validate when spec requires it |
| Authentication (5) | 5.0 | 5.0 | 0.0 | AI knows JWT well |
| Authorization/BOLA (8) | 8.0 | 8.0 | 0.0 | Spec explicitly requires ownership checks |
| Data Exposure (4) | 4.0 | 4.0 | 0.0 | Spec explicitly requires field filtering |

### Key Insights

1. **Business logic security is implemented correctly by ALL frameworks.**
   Authorization (BOLA), data exposure control, and authentication
   score equally regardless of framework. When the spec says "only the
   owner can delete", AI implements it correctly every time. Score: 17/17
   for all conditions.

2. **Infrastructure security is STILL universally forgotten.**
   Zero of 9 non-a³ implementations add security headers, CORS, rate
   limiting, or unknown field rejection. These features are not in the
   functional spec, so AI doesn't add them. a³ provides them automatically.

3. **The a³ advantage is specifically in "non-functional security".**
   a³ doesn't help with business logic (and doesn't claim to). Its value
   is in closing the gap between "functionally correct" and "production-secure"
   — the infrastructure that developers (and AI) forget because it's not
   in the requirements.

4. **Error safety shows a consistent pattern.**
   All alternatives return structured JSON (good) but none add request IDs.
   Two runs (FastAPI R3, axum R2) leak internal error messages from the JWT
   library. a³ sanitizes all error messages automatically.

5. **The fair benchmark confirms a³'s thesis, but with appropriate context.**
   a³ scores 100% vs ~71% for alternatives. The advantage (+28.8pp) is
   real but comes entirely from infrastructure security features that the
   framework auto-provides. In business logic security, a³ has zero advantage.

---

## Error Safety Details

Implementations that leak internal information:

| Run | Issue | Risk |
|---|---|---|
| FastAPI R3 | `f"Invalid token: {exc}"` exposes JWT error details | Token validation internals exposed |
| axum R2 | `format!("Invalid token: {e}")` exposes JWT error details | Same |

All other runs return generic error messages for auth failures.

---

## Verdict

**a³ achieves a perfect 40/40 on the fair rubric. Alternatives score ~28.5/40 (71%).**

The 28.8 percentage point gap is smaller than v1's 61.3pp gap because
over half the v2 rubric tests business logic that all frameworks handle equally.

| Criterion | Result |
|---|---|
| a³ > alternatives | **YES** — 40.0 vs 28.5, +40% relative |
| Advantage from auto-provided features only? | **YES** — 0 gap in business logic categories |
| Alternatives implement ownership correctly? | **YES** — 8/8 in all 9 runs |
| Alternatives implement data filtering correctly? | **YES** — 4/4 in all 9 runs |
| Alternatives add infrastructure security? | **NO** — 0/10 in all 9 runs |

### Conclusion

a³ provides value specifically in **infrastructure security that is orthogonal
to functional requirements**. When security is part of the spec (auth, ownership,
data filtering), AI implements it correctly regardless of framework. When security
is NOT part of the spec (headers, CORS, rate limiting, unknown fields), only a³
provides it — because the framework makes it automatic.

This is a narrower but more honest claim than v1's 90.3% vs 38% comparison.
