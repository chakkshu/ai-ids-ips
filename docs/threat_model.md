# AI-Powered Intrusion Detection and Prevention System (AI-IDS/IPS)
## Threat Model & Security Architecture Specification

### 1. Introduction & Security Methodology

This document outlines the formal threat model for the AI-IDS/IPS platform. As an enterprise-grade defensive security solution, the system itself represents a high-value target for adversaries seeking to:
- Evade detection (adversarial ML attacks).
- Disable automated prevention mechanisms.
- Leverage the IPS mechanism to orchestrate Denial of Service against legitimate services (blocking spoofed victim IPs).
- Tamper with forensic logs and audit trails.
- Execute unauthorized administrative actions.

This threat model uses the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) combined with **DREAD** risk scoring (Damage, Reproducibility, Exploitability, Affected Users, Discoverability) to identify vulnerabilities and document mitigations.

---

### 2. Trust Boundaries & Data Flow Diagram

```
 +-----------------------------------------------------------------------------------------------+
 | UNTRUSTED NETWORK ZONE                                                                        |
 |   [ External Attacker / Malicious Traffic ]                                                   |
 +-----------------------------------------------+-----------------------------------------------+
                                                 | Raw Packets / Spoofed Headers
                                  [ TRUST BOUNDARY 1: Physical / Network Capture ]
                                                 v
 +-----------------------------------------------+-----------------------------------------------+
 | INGESTION SUBSYSTEM (Demilitarized Component)                                                 |
 |   [ Scapy Sniffer / Sensor ]                                                                  |
 |   - BPF Filter Isolation                                                                      |
 |   - Flow Assembler / Feature Extraction (Memory Only)                                         |
 +-----------------------------------------------+-----------------------------------------------+
                                                 | Structured JSON Flow Tuples
                                  [ TRUST BOUNDARY 2: Inter-Service Broker ]
                                                 v
 +-----------------------------------------------+-----------------------------------------------+
 | PROCESSING & CONTROL SUBSYSTEM (Authenticated Private Network)                                |
 |                                                                                               |
 |   [ Redis Broker (Stream: flows:raw) ] ◄─── Mutual Auth / Password Bound                      |
 |                 │                                                                             |
 |                 ▼                                                                             |
 |   [ Detection Engine ] ──► [ Model Registry (Cryptographic Signatures) ]                     |
 |                 │                                                                             |
 |                 ▼                                                                             |
 |   [ Prevention Engine ] ──► [ Immutable Whitelist (Never-Block Rule) ]                        |
 |                 │                                                                             |
 |                 ▼                                                                             |
 |   [ Firewall Adapters (netsh / iptables) ] ──► Parameterized APIs Only                        |
 +-----------------------------------------------+-----------------------------------------------+
                                                 | Filtered Queries / Administrative Commands
                                  [ TRUST BOUNDARY 3: Web Application & API ]
                                                 v
 +-----------------------------------------------+-----------------------------------------------+
 | PRESENTATION & PERSISTENCE SUBSYSTEM                                                          |
 |                                                                                               |
 |   [ Nginx TLS 1.3 Reverse Proxy ] ──► Strict Headers (CSP, HSTS, X-Content-Type, X-Frame)     |
 |                 │                                                                             |
 |                 ▼                                                                             |
 |   [ Flask REST API /api/v1 ] ──► RBAC, Argon2id, TOTP 2FA, Rate Limiting                      |
 |                 │                                                                             |
 |                 ▼                                                                             |
 |   [ PostgreSQL 16 ] ──► AES-256-GCM Envelope Encryption & Tamper-Evident SHA-256 Audit Chain  |
 +-----------------------------------------------------------------------------------------------+
```

---

### 3. STRIDE Threat Analysis

| Threat ID | STRIDE Category | Threat Description | Attack Vector | Severity (DREAD Avg) | Built-in Mitigation Strategy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TH-01** | **Spoofing** | Attacker spoofs source IP to trick the IPS into blocking legitimate infrastructure (Self-DoS). | Sending SYN packets with source IP set to the gateway, DNS, or domain controller. | **High (8.2)** | **Immutable CIDR Whitelist**: Engine enforces an untouchable allowlist (loopback, RFC1918 gateways, local DNS, server's own interfaces). Multi-detection thresholds and TCP handshake state verification prevent single-packet triggers. |
| **TH-02** | **Tampering** | Command injection via crafted packet headers into system firewall commands (`netsh`/`iptables`). | Injecting shell metacharacters (`&`, `\|`, `;`, `$(...)`) into IP address fields. | **Critical (9.4)** | **Strict Type Validation & Parameterization**: IP fields must parse cleanly as `ipaddress.IPv4Address` or `ipaddress.IPv6Address`. Subprocess arguments are passed as fixed lists without shell invocation (`shell=False`). |
| **TH-03** | **Tampering** | Adversary tampers with database audit logs to conceal malicious activity or analyst actions. | Direct SQL injection or compromised DB account altering records. | **High (7.8)** | **Hash-Chained Audit Ledger**: Each audit record stores `SHA256(previous_hash + current_record_data)`. Any out-of-band edit invalidates the entire chain, detectable via verification CLI. |
| **TH-04** | **Repudiation** | Analyst denies modifying a prevention policy or executing an unauthorized manual block. | Shared analyst credentials or lack of attribution in administrative actions. | **Medium (6.0)** | **Mandatory User-Attributed Auditing**: All state-changing endpoints log user identity, client IP, timestamp, and parameter diffs directly to the hash-chained ledger. |
| **TH-05** | **Information Disclosure** | Exposure of sensitive network topology, captured payloads, or API credentials in database dumps. | Database backup theft or unauthorized read access to `network_flows`. | **High (7.6)** | **AES-256-GCM Envelope Encryption**: Sensitive payloads and threat intel API keys are encrypted at rest with unique per-record DEKs protected by a Master KEK. |
| **TH-06** | **Denial of Service** | Flow table exhaustion / Resource exhaustion via high-volume random-port packet floods. | Flooding millions of distinct 5-tuples causing unbounded memory growth in sensor. | **High (8.0)** | **Bounded LRU Flow Table & Drop Statistics**: Hard memory caps with aggressive LRU eviction for incomplete flows, plus BPF pre-filtering of high-volume non-monitored traffic. |
| **TH-07** | **Elevation of Privilege** | Analyst or unauthenticated user elevates privileges to Admin to override prevention policies. | Parameter tampering, insecure direct object references (IDOR), or CSRF attacks. | **Critical (9.0)** | **Backend-Enforced RBAC & Anti-CSRF**: Strict server-side `@role_required(Role.ADMIN)` decorators; Flask-WTF CSRF tokens; Argon2id + TOTP 2FA required for administrative sessions. |
| **TH-08** | **Tampering** | Adversarial ML evasion (crafting packet timing/sizes to evade Random Forest detection). | Padding packet lengths or perturbing inter-arrival times (IAT) to mimic benign traffic. | **Medium (7.0)** | **Dual-Layer Detection**: Isolation Forest anomaly detector flags traffic that deviates from normal benign profiles even if multiclass model confidence drops. Regular drift monitoring and analyst feedback loop support rapid retraining. |

---

### 4. DREAD Risk Assessment Matrix

The DREAD model scores threats from 1 to 10 across five categories:
- **D**amage potential
- **R**eproducibility
- **E**xploitability
- **A**ffected users
- **D**iscoverability

$$\text{DREAD Score} = \frac{D + R + E + A + D}{5}$$

```
  10 ──┐                                         [TH-02: Command Injection]
       │                                         [TH-07: Privilege Escalation]
   8 ──┼──────── [TH-01: Spoofed Self-DoS]
       │         [TH-06: Sensor Resource Exhaustion]
       │         [TH-03: Audit Log Tampering]
   6 ──┼──────────────────────────────────────── [TH-05: Data Disclosure]
       │                                         [TH-08: Adversarial ML]
   4 ──┼──────────────────────────────────────── [TH-04: Action Repudiation]
       │
   0 ──┴───────────────────────────────────────────────────────────────────► Impact
```

---

### 5. Architectural Security Controls & Mitigations

#### 5.1 Command Injection Defense (Zero-Trust Subprocess Execution)
Under no circumstances are firewall commands executed through a command shell.
- **Forbidden Pattern**: `os.system(f"netsh advfirewall ... {user_ip}")`
- **Mandatory Pattern**:
  ```python
  import ipaddress, subprocess
  validated_ip = ipaddress.ip_address(raw_ip)
  subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                  f"name=BLOCK_{validated_ip}", "dir=in", "action=block",
                  f"remoteip={validated_ip}"], check=True, shell=False)
  ```

#### 5.2 Safe Prevention Policy & Fail-Safes
- **Dry-Run by Default**: The prevention engine defaults to `PREVENTION_MODE=dry_run`. Actions are logged and pushed to the dashboard as "Simulated Blocks" until explicitly toggled to `active` by an authorized Administrator.
- **Fail-Open Policy Option**: If the prevention engine crashes or loses connectivity with the database, it defaults to non-blocking operation to prevent network blackouts.
- **Automatic Block Expiry**: Blocks are stored with mandatory expiration timestamps. A scheduled worker automatically purges expired firewall rules, preventing indefinite accumulation.

#### 5.3 Web Security Headers
All HTTP responses passing through Nginx and Flask inject enterprise-grade defensive headers:
- `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-...'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' wss:; font-src 'self'; frame-ancestors 'none';`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), camera=(), microphone=()`

#### 5.4 Cryptographic Standards
- **Password Storage**: Argon2id via `argon2-cffi` (`time_cost=3`, `memory_cost=65536`, `parallelism=4`, salt length $\ge 16$ bytes).
- **Two-Factor Authentication**: RFC 6238 TOTP using SHA-1 (compatible with Google Authenticator / Aegis / 1Password), requiring 6-digit verification codes within a $\pm 1$ step tolerance window.
- **Envelope Encryption**: AES-256-GCM with unique 96-bit nonces per record. Keys are never hardcoded or logged in plaintext.
- **Audit Hash Ledger**: HMAC-SHA256 chaining.
