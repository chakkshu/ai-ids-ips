# Role-Based Access Control (RBAC) Policy

This document is the authoritative description of the Phase 2 authorization
model. The executable matrix lives in `core/rbac.py`; the two must be kept in
sync.

## Principles

1. **Default deny.** A route is denied unless the authenticated user's role is
   explicitly granted the required permission. There is no implicit superuser.
2. **Backend enforcement.** UI affordances are conveniences only. Every route
   enforces authorization server-side through `@permission_required(...)` or
   `@role_required(...)`.
3. **Least privilege.** Analysts can triage and verify integrity but cannot
   manage users. Viewers are read-only.
4. **No role leakage.** Unauthenticated requests receive `401`; authenticated
   requests lacking a permission receive `403`. Neither response reveals which
   role would have succeeded.

## Roles

| Role | Intended user | Summary |
|------|---------------|---------|
| `admin` | SOC platform administrator | Full console control, including user lifecycle and security resets. |
| `analyst` | SOC analyst / incident responder | Read dashboards and audit data; verify audit-chain integrity. |
| `viewer` | Auditor / stakeholder | Read-only dashboard and audit ledger access. |

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

The `users:view` permission is defined for completeness; the current user list
route requires the stronger `users:manage` permission. `models:manage` is
enforced in `ml.registry.service`; operator commands must supply an actor user
ID, and the service refuses non-admin actors before touching the registry.

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

## UI Behavior

Templates use the `can()` helper injected by the application factory:

```jinja
{% if can(Permission.USERS_MANAGE) %}
  <a href="{{ url_for('users.index') }}">User Management</a>
{% endif %}
```

Hiding a control is not authorization. The server independently checks the
permission before performing any operation.
