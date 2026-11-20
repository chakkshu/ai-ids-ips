# Role-Based Access Control (RBAC) Policy

This document is the authoritative description of the Phase 2 and Phase 6
authorization model. The executable matrix lives in `core/rbac.py`; the two must
be kept in sync. The Phase 6 `/api/v1` matrix is additionally exercised by
`tests/unit/phase6/test_api_rbac.py`.

## Principles

1. **Default deny.** A route is denied unless the authenticated user's role is
   explicitly granted the required permission. There is no implicit superuser.
2. **Backend enforcement.** UI affordances are conveniences only. Every route
   enforces authorization server-side through `@permission_required(...)` or
   `@role_required(...)`.
3. **Least privilege.** Analysts can triage alerts, verify integrity, and view
   prevention/threat-intel data, but cannot manage users, blocks, keys, or
   blocklists. Viewers are read-only.
4. **No role leakage.** Unauthenticated requests receive `401`; authenticated
   requests lacking a permission receive `403`. Neither response reveals which
   role would have succeeded.

## Roles

| Role | Intended user | Summary |
|------|---------------|---------|
| `admin` | SOC platform administrator | Full console control, including user lifecycle, prevention, keys, and security resets. |
| `analyst` | SOC analyst / incident responder | Read dashboards and audit data; triage alerts; verify audit-chain integrity. |
| `viewer` | Auditor / stakeholder | Read-only dashboard, audit ledger, prevention, alert, and threat-intel access. |

## Permission Matrix

| Permission | Admin | Analyst | Viewer | Description |
|------------|:-----:|:-------:|:------:|-------------|
| `dashboard:view` | ✅ | ✅ | ✅ | View SOC dashboard metrics and recent alerts. |
| `audit:view` | ✅ | ✅ | ✅ | Read the tamper-evident audit ledger. |
| `audit:verify` | ✅ | ✅ | ❌ | Trigger cryptographic verification of the audit hash chain. |
| `users:view` | ✅ | ❌ | ❌ | Reserved for user-list views. |
| `users:manage` | ✅ | ❌ | ❌ | Create, activate, deactivate, delete, lock, unlock, reset 2FA, force password change, and change roles. |
| `models:manage` | ✅ | ❌ | ❌ | Promote or roll back ML model versions through the registry service layer. |
| `self:manage` | ✅ | ✅ | ✅ | Manage own password, TOTP enrollment, and recovery codes. |
| `prevention:view` | ✅ | ✅ | ✅ | Read blocked IPs, whitelist entries, and prevention policy. |
| `prevention:manage` | ✅ | ❌ | ❌ | Create/extend/release blocks, manage whitelist and policy, and approve/reject pending blocks. |
| `alerts:view` | ✅ | ✅ | ✅ | Read the alert queue and individual alert detail. |
| `alerts:manage` | ✅ | ✅ | ❌ | Change alert status, assign alerts, comment, and submit feedback. |
| `threat-intel:view` | ✅ | ✅ | ✅ | Read IP profiles, enrich IPs, and export the blocklist. |
| `threat-intel:manage` | ✅ | ❌ | ❌ | Import external blocklists. |
| `keys:manage` | ✅ | ❌ | ❌ | Register/activate KEKs and rewrap encrypted fields. |

The `users:view` permission is defined for completeness; the current user list
route requires the stronger `users:manage` permission. `models:manage` is
enforced in `ml.registry.service`; operator commands must supply an actor user
ID, and the service refuses non-admin actors before touching the registry.
Phase 6 route permissions are enforced by `@permission_required(...)`; key
rotation and blocklist import also validate input through strict schemas before
any state change.

## Route Enforcement

| Route | Method | Required permission | Unauthenticated | Viewer | Analyst | Admin |
|-------|--------|---------------------|:---------------:|:------:|:-------:|:-----:|
| `/dashboard` | GET | `dashboard:view` | 401 | 200 | 200 | 200 |
| `/audit` | GET | `audit:view` | 401 | 200 | 200 | 200 |
| `/audit/verify` | POST | `audit:verify` | 401 | 403 | 302 | 302 |
| `/users` | GET | `users:manage` | 401 | 403 | 403 | 200 |
| `/users/create` | POST | `users:manage` | 401 | 403 | 403 | 302 |
| `/users/<id>/role` | POST | `users:manage` | 401 | 403 | 403 | 302 |
| `/users/<id>/activate` | POST | `users:manage` | 401 | 403 | 403 | 302 |
| `/users/<id>/deactivate` | POST | `users:manage` | 401 | 403 | 403 | 302 |
| `/users/<id>/lock` | POST | `users:manage` | 401 | 403 | 403 | 302 |
| `/users/<id>/unlock` | POST | `users:manage` | 401 | 403 | 403 | 302 |
| `/users/<id>/reset-2fa` | POST | `users:manage` | 401 | 403 | 403 | 302 |
| `/users/<id>/force-password-change` | POST | `users:manage` | 401 | 403 | 403 | 302 |
| `/users/<id>/delete` | POST | `users:manage` | 401 | 403 | 403 | 302 |
| `/change-password` | GET/POST | authenticated self | 302 | 200 | 200 | 200 |
| `/setup-2fa` | GET/POST | authenticated self | 302 | 200 | 200 | 200 |
| `/api/v1/health/live` | GET | public | 200 | 200 | 200 | 200 |
| `/api/v1/health/ready` | GET | public | 200/503 | 200/503 | 200/503 | 200/503 |

`302` on destructive POST routes is the post-action redirect back to the user
list; `302` on `/audit/verify` is the redirect back to the ledger after a
verification result is flashed.

## Phase 6 `/api/v1` Route Matrix

All Phase 6 API routes return JSON. Unauthenticated requests receive `401`;
authenticated requests without the required permission receive `403`. The table
below shows the observed success status for each role; `201` is used where the
route creates a resource.

| Route | Method | Required permission | Unauth. | Viewer | Analyst | Admin |
|-------|--------|---------------------|:-------:|:------:|:-------:|:-----:|
| `/api/v1/prevention/blocked-ips` | GET | `prevention:view` | 401 | 200 | 200 | 200 |
| `/api/v1/prevention/blocked-ips` | POST | `prevention:manage` | 401 | 403 | 403 | 201 |
| `/api/v1/prevention/blocked-ips/<block_id>/unblock` | POST | `prevention:manage` | 401 | 403 | 403 | 200 |
| `/api/v1/prevention/blocked-ips/<block_id>/extend` | POST | `prevention:manage` | 401 | 403 | 403 | 200 |
| `/api/v1/prevention/whitelist` | GET | `prevention:view` | 401 | 200 | 200 | 200 |
| `/api/v1/prevention/whitelist` | POST | `prevention:manage` | 401 | 403 | 403 | 201 |
| `/api/v1/prevention/policy` | GET | `prevention:view` | 401 | 200 | 200 | 200 |
| `/api/v1/prevention/policy` | PUT | `prevention:manage` | 401 | 403 | 403 | 200 |
| `/api/v1/prevention/approvals` | GET | `prevention:manage` | 401 | 403 | 403 | 200 |
| `/api/v1/prevention/approvals/<block_id>/approve` | POST | `prevention:manage` | 401 | 403 | 403 | 200 |
| `/api/v1/prevention/approvals/<block_id>/reject` | POST | `prevention:manage` | 401 | 403 | 403 | 200 |
| `/api/v1/alerts` | GET | `alerts:view` | 401 | 200 | 200 | 200 |
| `/api/v1/alerts/<alert_id>` | GET | `alerts:view` | 401 | 200 | 200 | 200 |
| `/api/v1/alerts/<alert_id>/status` | POST | `alerts:manage` | 401 | 403 | 200 | 200 |
| `/api/v1/alerts/<alert_id>/assign` | POST | `alerts:manage` | 401 | 403 | 200 | 200 |
| `/api/v1/alerts/<alert_id>/comments` | POST | `alerts:manage` | 401 | 403 | 201 | 201 |
| `/api/v1/alerts/<alert_id>/feedback` | POST | `alerts:manage` | 401 | 403 | 201 | 201 |
| `/api/v1/threat-intel/ips/<ip_address>` | GET | `threat-intel:view` | 401 | 200 | 200 | 200 |
| `/api/v1/threat-intel/enrich` | POST | `threat-intel:view` | 401 | 200 | 200 | 200 |
| `/api/v1/threat-intel/blocklist/import` | POST | `threat-intel:manage` | 401 | 403 | 403 | 200 |
| `/api/v1/threat-intel/blocklist/export` | GET | `threat-intel:view` | 401 | 200 | 200 | 200 |
| `/api/v1/keys/rotate` | POST | `keys:manage` | 401 | 403 | 403 | 200 |
| `/api/v1/keys/rewrap` | POST | `keys:manage` | 401 | 403 | 403 | 200 |

Authenticated JSON POST/PUT requests require the `X-CSRFToken` header from the
signed-in `/dashboard` meta tag. Missing CSRF input is rejected before the
route handler runs and is outside the authorization matrix above.

## Safety Guards

- **Last active administrator.** The final active `admin` cannot be demoted,
  deactivated, locked, or deleted. The guard counts other active admins before
  applying the change.
- **Self-action guards.** Administrators cannot deactivate, lock, or delete
  their own account through the user-management routes.
- **Session revocation.** All of a target user's server-side sessions are
  revoked on password change, role change, deactivation, administrative
  lockout, forced password change, 2FA reset, and account deletion.
- **Audit trail.** Every privileged action records the actor, target, status,
  IP address, correlation ID, and structured details in the hash-chained audit
  ledger.
- **Prevention safety gates.** Firewall changes default to dry-run; real
  enforcement requires `active` mode, an explicit opt-in, and non-simulation
  operation. Whitelisted, protected, gateway, admin, and DNS addresses are
  rejected before any adapter call.
- **Command safety.** Firewall adapters validate IPs with `ipaddress` and pass
  argument lists to `subprocess.run(..., shell=False)`; no shell string is ever
  constructed from user input.
- **Key safety.** Key material is accepted only from environment-provided
  secrets, never logged, and retired KEKs remain available for old envelopes.

## UI Behavior

Templates use the `can()` helper injected by the application factory:

```jinja
{% if can(Permission.USERS_MANAGE) %}
  <a href="{{ url_for('users.index') }}">User Management</a>
{% endif %}
```

Hiding a control is not authorization. The server independently checks the
permission before performing any operation.
