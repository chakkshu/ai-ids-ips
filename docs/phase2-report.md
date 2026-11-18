# Phase 2 — Security Hardening (Revised Report)

**Status:** Complete for review. Phase 3 has not been started.
**Scope:** Authentication, TOTP, server-side sessions, RBAC, user management, UI hardening, and tests, applied on top of the existing Phase 1/2 scaffold.
**Branch:** `master` (all changes uncommitted).

---

## 1. What changed

### Configuration (`core/config.py`)
- Explicit Argon2id parameters: time cost, memory cost, parallelism, hash length, salt length.
- Password policy: minimum length (12), complexity, common-password check, username/email substring rejection, history depth (5).
- Lockout: 5 failures / 15 minutes, success reset, admin reset, lock/unlock audit.
- Session idle/absolute timeouts, cookie `SameSite` (`Strict` by default), secure-cookie flag, trusted proxy hop count.
- Flask-Limiter storage selection: Redis in production, in-memory in development/test.
- TOTP window, recovery-code count, SocketIO origin allow-list, initial-admin forced-change flag.
- Validators for KEK, session/cookie settings, and storage URI resolution helpers.

### Cryptography (`core/crypto.py`, new)
- AES-256-GCM envelope encryption: per-value DEK, KEK wrapping, versioned envelopes, purpose-bound AAD, authenticated decryption.
- Used for TOTP secrets; secrets are never stored or logged in plaintext.

### RBAC (`core/rbac.py`, new; `docs/rbac.md`, new)
- Explicit `Permission` enum and `ROLE_PERMISSIONS` matrix for Admin/Analyst/Viewer.
- Default-deny policy functions; Admin is not an implicit superuser in decorators.
- Documented role → permission and route → role matrices, guards, and 401/403 semantics.

### Schemas (`core/schemas.py`, new)
- Strict Pydantic models (`extra="forbid"`) for user creation, role updates, password changes, and recovery-code submission.
- Prevents mass assignment of `is_active`, `must_change_password`, hashes, TOTP secrets, etc.

### Models (`core/models/`)
- `PasswordHistory`, `RecoveryCode`, encrypted TOTP secret (`Text`), `totp_last_step`, `last_password_change_at`.
- `UserSession.revoked_at` / `revoke_reason` and relationships.
- Enum `values_callable` so lowercase values match the Alembic schema.
- Audit ledger supports `hash_version` v1 (legacy) and v2 (binds username, IP, correlation ID), with backward-compatible verification.

### Security core (`core/security.py`)
- Configurable Argon2id hashing, verification, rehash-on-login, and constant-time dummy verification for unknown users.
- Password policy, common-password denylist (`core/data/common_passwords.txt`), history recording (exact depth 5), and reuse checks.
- Lockout tracking, expiry clearing, and audited lock/unlock events.
- TOTP generation, encryption, verification with time-step replay protection, and one-time recovery-code issue/verify/consume.
- Server-side sessions with idle/absolute timeouts, hash-only token storage, rotation, per-session and all-session revocation.
- Audit append with row/advisory locking and v2 actor/IP/correlation binding.
- Default-deny `role_required` / `permission_required`, 401/403 helpers, forced-password-change and 2FA guards, safe `next` validation, client-IP helper.

### Application factory (`services/web_api/__init__.py`)
- `ProxyFix` applied as the outermost WSGI layer using an exact configured hop count (also covers SocketIO traffic).
- Limiter storage configured per environment; global CSRF protection.
- Same-origin SocketIO; nonce-based CSP with no `unsafe-inline`/`unsafe-eval`.
- Security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, production HSTS, `frame-ancestors 'none'`, `object-src 'none'`.
- Server-side session validation on each authenticated request.
- Global forced-password-change and pending-2FA guards.
- `can()` / `csp_nonce()` template context and HTML/JSON error negotiation (HTML wins ties).

### Authentication (`services/web_api/blueprints/auth.py`)
- Rate-limited login and 2FA endpoints; generic errors; dummy hash for unknown users.
- Lockout enforcement and audited lock/unlock; rehash on successful login.
- Password stage creates a pending 2FA session only; no authenticated session before the code.
- Encrypted TOTP enrollment requiring a valid code; replay protection via last accepted step.
- One-time hashed recovery codes shown once, plus password-confirmed regeneration.
- Session rotation on login/finalize; logout revokes the server-side session.
- Password change enforces policy/history, revokes all sessions, and forces fresh 2FA when enabled.

### User administration (`services/web_api/blueprints/users.py`)
- List, create, deactivate/activate, role update, lock/unlock, 2FA reset, forced password change, delete.
- Pydantic validation, safe view models (no hashes/secrets), session revocation, and actor/target/correlation-aware audit entries.
- Last-active-admin protection and self-action guards.
- Explicit role enum conversion and 404/denial paths audited.

### Audit and dashboard blueprints
- Permission-based audit view and chain verification; tamper detection and verification events audited.
- Dashboard uses `permission_required(DASHBOARD_VIEW)` without `login_required` to preserve 401-unauthenticated semantics.

### UI (`templates/`, `static/css/soc-theme.css`, `static/js/app.js`)
- Dark SOC theme, responsive sidebar/header, status pills, flash partials, error pages.
- Role-aware navigation; login, 2FA, change-password, enrollment, and recovery-code pages.
- Skip link, ARIA labels/current/expanded states, focus-visible styles, reduced-motion support.
- No inline scripts/styles or inline event handlers; nonce on every script.
- `app.js` provides nav toggling, data-attribute copy/confirm handlers, and a CSRF-header `apiFetch` helper.

### Bootstrap and migrations
- `run.py` seeds the admin with Argon2id hashing, password history, forced first-login change, and an audit entry; audit verification uses the shared verifier.
- Migration `0002_phase2_security_hardening` adds the new columns/tables.
- Initial migration downgrade is now dialect-aware (`DROP TYPE` only on PostgreSQL), so the chain is reversible on SQLite too.

### Tests, tooling, and CI
- `tests/conftest.py`: isolated database, cheap Argon2id, CSRF/login/user/auth-client fixtures, per-test reset, limiter reset.
- `tests/unit/test_phase2_auth_security.py`: hashing/policy, lockout/expiry, enumeration, TOTP/replay, recovery codes + UI regeneration, session fixation/timeouts/revocation, forced change, password reuse, open redirect, CSRF, rate limiting, audit chain.
- `tests/unit/test_phase2_rbac_web.py`: permission matrix, full route × role matrix, all user-management actions, last-admin/self guards, headers/CSP/cookies/ProxyFix/limiter, sidebar, escaping, error negotiation, static assets.
- `tests/conftest.py` optionally runs the whole suite against PostgreSQL via `AI_IDS_TEST_DATABASE_URL`.
- CI now installs dev requirements, runs mypy, validates Alembic up/down on PostgreSQL, and runs the suite against the PostgreSQL service.
- `mypy.ini` added; `requirements-dev.txt` includes `freezegun`; Black formatting normalized across the tree.

### Verification-driven fixes
- Recovery-code consumption now flushes immediately (`autoflush=False` sessions) so a code cannot be reused in the same transaction.
- Recovery-code rotation deletes through the ORM to avoid identity-map/PK reuse warnings.
- `ProxyFix` moved outside the SocketIO wrapper so both HTTP and WebSocket traffic see trusted-proxy corrections.
- `safe_next_url` no longer requires an application context.
- Password-history pruning flushes deletes so retention is exactly 5.
- Audit timestamp canonicalization and role-update typing fixed for mypy.
- Enrollment test corrected to reuse the CSRF token from the page that generated the pending secret (a fresh GET rotates it).

---

## 2. Commands and actual results

All commands were run from `C:\Users\KHUSHI\Desktop\ai-ids-ips` with the project virtualenv.

| Gate | Command | Result |
|---|---|---|
| Ruff | `.venv\Scripts\python.exe -m ruff check .` | `All checks passed!` (exit 0) |
| Black | `.venv\Scripts\python.exe -m black --check .` | `44 files would be left unchanged.` (exit 0) |
| Mypy | `.venv\Scripts\python.exe -m mypy core services run.py` | `Success: no issues found in 29 source files` (exit 0) |
| Bandit | `.venv\Scripts\python.exe -m bandit -r core ml services prevention capture utils -ll` | `No issues identified.` — 3,439 lines, 0 issues at every severity (exit 0) |
| Pytest + coverage (SQLite) | `.venv\Scripts\python.exe -m pytest tests/ -q --cov=core --cov=ml --cov=services --cov=prevention --cov=capture --cov=utils --cov-report=term-missing` | **113 passed**, total coverage **89%** (exit 0) |
| Pytest (PostgreSQL 16) | Container on `127.0.0.1:55432`, `AI_IDS_TEST_DATABASE_URL=postgresql+psycopg2://…` | **113 passed** in 120.02s (exit 0) |
| Alembic (SQLite) | `alembic upgrade head` → `current` → `downgrade base` → `upgrade head` | `0002_phase2_security_hardening (head)`; all four steps exit 0 |
| Alembic (PostgreSQL 16) | Same sequence against the container | `0002_phase2_security_hardening (head)`; all four steps exit 0 |
| Seed smoke test | `run.py seed-db` then `run.py verify-audit-chain` | `MUST_CHANGE=True`, `ROLE=admin`, `HISTORY=1`, `SEED_AUDIT=1`, `ADMIN_PASSWORD_OK=True`; audit chain verified (1/1 entries) |

Notable coverage by module: `core/schemas.py` 100%, `core/models/user.py` 99%, `core/rbac.py` 94%, `core/security.py` 87%, `services/web_api/blueprints/auth.py` 86%, `users.py` 91%.

PostgreSQL was exercised with the repository's compose `db` service (PostgreSQL 16-alpine) on port 55432 via a temporary override, then removed with `down -v`.

---

## 3. Unverified items

These were **not** executed and are not claimed as verified:

- Live Redis-backed rate limiting (Redis was not running; tests use `memory://`). Production storage selection is implemented and unit-checked, but not load-tested against Redis.
- Full application compose stack (web, worker, engines). Only the PostgreSQL service was started for migration/tests.
- GitHub Actions execution. The workflow was updated but not run here.
- Browser end-to-end tests (Playwright/Selenium) and automated accessibility auditing (axe/Lighthouse). Accessibility is implemented but not machine-audited.
- A physical authenticator app; TOTP was exercised with `pyotp`.
- Load, performance, and concurrency testing.
- Production TLS/proxy termination and real HSTS behavior behind a load balancer.
- Coverage gaps (11% overall), including some error branches, Celery worker startup, replay simulator, and several config validators.

---

## 4. Pending items

1. Review and approve this revised Phase 2 report.
2. Commit the Phase 2 changes (none committed yet).
3. Optionally run the CI workflow on GitHub and add a live-Redis integration check.
4. Optional: add Playwright + axe checks and remove the obsolete `version:` key from `docker/docker-compose.yml`.
5. **Do not start Phase 3 until this report is approved.**

---

## 5. Risks and notes

- **Secrets:** `.env` contains development secrets and the default seeded admin password. Production must override `APP_SECRET_KEY`, `APP_MASTER_KEK`, `AUDIT_HMAC_SECRET`, DB/Redis credentials, and the initial admin password.
- **Forced rotation:** the seeded admin is blocked from all routes except change-password/logout/health until the password is changed.
- **Rate limiting:** in-memory storage is per-process and unsuitable for multi-worker production; production must use Redis.
- **Sessions:** server-side revocation is authoritative; cookie replay after logout is rejected. Idle timeout is 30 minutes and absolute timeout 8 hours by default.
- **Audit chain:** existing v1 entries remain valid; new v2 entries bind actor/IP/correlation. Deleting or editing rows breaks verification as intended.
- **Last admin:** demotion/deactivation/deletion of the sole active Admin is blocked; self lock/deactivate/delete are blocked earlier.
- **Recovery codes:** displayed once, hashed at rest, single-use, and replaced on regeneration. Loss requires admin 2FA reset or regeneration.
- **Database portability:** SQLite is used for fast tests; PostgreSQL 16 passed both migrations and the full suite. SQLite remains a development convenience, not a production target.
- **Formatting footprint:** Black reformatted several pre-existing files (models, migrations, phase-1 test); these are formatting-only changes.
- **Compose warning:** `docker/docker-compose.yml` still declares the obsolete `version` key; Compose v2+ ignores it.
