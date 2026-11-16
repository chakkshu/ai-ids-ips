# AI-Powered Intrusion Detection and Prevention System (AI-IDS/IPS)
## Enterprise Architecture & Technical Specification

### 1. Architectural Overview & Design Philosophy

The AI-IDS/IPS platform is an enterprise-grade, service-oriented defensive cybersecurity solution designed to ingest high-velocity network packet streams, construct bidirectional network flows, detect known and zero-day malicious traffic using a dual-layer machine learning engine (Random Forest classifier + Isolation Forest anomaly detector), and enact safe, auditable, and automated prevention measures.

The system is strictly defensive and adheres to defense-in-depth, zero-trust network monitoring, and OWASP Application Security Verification Standard (ASVS) Level 2/3 guidelines.

```
 +--------------------------------------------------------------------------------------------------+
 |                                  INGESTION & CAPTURE LAYER                                       |
 |                                                                                                  |
 |   +---------------------------------------+       +------------------------------------------+   |
 |   |          Network Interface            |       |         Replay Simulator (Demo)          |   |
 |   |  (Scapy + Npcap/WinPcap/libpcap)      |       |    (CICIDS2017 Held-out Test Split)      |   |
 |   +-------------------+-------------------+       +--------------------+---------------------+   |
 |                       |                                                |                         |
 |                       +-----------------------+------------------------+                         |
 |                                               |                                                  |
 |                                               v                                                  |
 |                             +-----------------------------------+                                |
 |                             |           sensor service          |                                |
 |                             |  (Bidirectional Flow Assembler    |                                |
 |                             |   + 80+ CICFlowMeter Features)    |                                |
 |                             +-----------------+-----------------+                                |
 +-----------------------------------------------|--------------------------------------------------+
                                                 |
                                                 | JSON Flow Events
                                                 v
 +--------------------------------------------------------------------------------------------------+
 |                                     MESSAGE BUS & CACHE LAYER                                    |
 |                                                                                                  |
 |      Redis 7: Stream "flows:raw" | Stream "detections:stream" | PubSub "realtime:events"         |
 +---------------------------------------+-------------------------------+--------------------------+
                                         |                               |
                                         | Flow Records                  | Detection Notifications
                                         v                               v
 +------------------------------------------------+    +--------------------------------------------+
 |               DETECTION LAYER                  |    |              REALTIME GATEWAY              |
 |                                                |    |                                            |
 |  +------------------------------------------+  |    |  +--------------------------------------+  |
 |  |         detection-engine service         |  |    |  |        realtime service              |  |
 |  |  - Multiclass Random Forest (15 classes) |  |    |  |  (Flask-SocketIO / WebSocket Hub)   |  |
 |  |  - Isolation Forest (Anomaly/Zero-Day)   |  |    |  +-------------------+------------------+  |
 |  |  - Top feature contribution extractor    |  |    +----------------------|---------------------+
 |  +--------------------+---------------------+  |                           |
 +-----------------------|------------------------+                           | Live Push
                         | High-Confidence Detections                         v
                         v                                     +------------------------------------+
 +------------------------------------------------+            |          FRONTEND SOC UI           |
 |              PREVENTION LAYER                  |            |                                    |
 |                                                |            |  - Real-time KPI Cards             |
 |  +------------------------------------------+  |            |  - Interactive Traffic Visualizer  |
 |  |        prevention-engine service         |  |            |  - Threat Alert Management         |
 |  |  - Safe Policy Evaluator                 |  |            |  - Process & System Monitor        |
 |  |  - Immutable CIDR Whitelist Guard        |  |            |  - Model Registry & Drift Metrics  |
 |  |  - Dry-Run / Active Execution Driver     |  |            |  - Dark SOC Theme (Responsive)     |
 |  |  - Windows (netsh) & Linux (iptables)    |  |            +------------------------------------+
 |  +--------------------+---------------------+  |                           ^
 +-----------------------|------------------------+                           |
                         | Approved Action / Alert                            |
                         v                                                    |
 +------------------------------------------------+                           |
 |            ASYNC WORKER & PERSISTENCE          |                           |
 |                                                |                           |
 |  +------------------------------------------+  |                           |
 |  |              Celery Worker               |  |                           |
 |  |  - Threat Intel (GeoIP, AbuseIPDB, VT)   |  |                           |
 |  |  - Alert Deduplication & Email/Webhook   |  |                           |
 |  |  - Hash-Chained Audit Ledger Append      |  |                           |
 |  |  - Automated Drift Audits & Retraining   |  |                           |
 |  +--------------------+---------------------+  |                           |
 |                       |                        |                           |
 |                       v                        |                           |
 |  +------------------------------------------+  |                           |
 |  |          PostgreSQL 16 Database          |  |                           |
 |  |  - Monthly Partitioned Flows             |  |    +----------------------+---------------------+
 |  |  - Detections & Alerts Tables            |  |    |                 WEB API                    |
 |  |  - AES-256-GCM Envelope Encryption       |  |    |                                            |
 |  |  - Tamper-Evident SHA-256 Audit Log      |◄─┼────┤  +--------------------------------------+  |
 |  +------------------------------------------+  |    |  |           web-api service            |  |
 +------------------------------------------------+    |  |  - Flask Application Factory         |  |
                                                       |  |  - REST Endpoints (/api/v1)          |  |
                                                       |  |  - OpenAPI / Swagger Docs            |  |
                                                       |  |  - Role-Based Access Control (RBAC)  |  |
                                                       |  |  - Argon2id + TOTP 2FA Authentication|  |
                                                       |  +--------------------------------------+  |
                                                       +--------------------------------------------+
```

---

### 2. Service Decomposition & Responsibilities

#### 2.1 `web-api` Service
- **Framework**: Flask (Application Factory pattern, modular Blueprints).
- **Security & Middleware**:
  - `Flask-Login` + `argon2-cffi` password hashing.
  - TOTP two-factor authentication (`pyotp`).
  - Session cookie protections: `HttpOnly`, `SameSite=Strict`, `Secure`.
  - Content Security Policy (CSP), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
  - Rate limiting via `Flask-Limiter` with Redis backend.
  - CSRF protection via `Flask-WTF`.
- **API Specification**: RESTful endpoints under `/api/v1` accompanied by interactive Swagger/OpenAPI documentation.
- **Role-Based Access Control (RBAC)**:
  - `Admin`: Full configuration, policy modification, manual firewall rule management, model rollback/promotion, user lifecycle.
  - `Analyst`: View traffic, analyze detections, resolve/escalate alerts, provide ground-truth feedback, view threat intelligence.
  - `Viewer`: Read-only operational dashboard, detection logs, and audit trails.

#### 2.2 `sensor` Service
- **Packet Ingestion**: Scapy capturing raw packets on configured host or container interfaces using Berkeley Packet Filters (BPF).
- **Flow Assembly**:
  - Bidirectional flow aggregation keyed by 5-tuple `(src_ip, src_port, dst_ip, dst_port, protocol)`.
  - Flow termination logic driven by TCP FIN/RST flags and configurable timeouts (Activity timeout: 120s, Idle timeout: 30s).
- **CICFlowMeter Feature Extraction**:
  - Extracts 80+ standard features matching the CICIDS2017 feature specification (duration, packet counts, length statistics, flow bytes/sec, flow packets/sec, inter-arrival times (IAT), TCP flags, window sizes, active/idle periods).
- **Queue Publishing**: Serializes completed flow vectors into JSON and pushes to Redis Stream `flows:raw`.
- **Host Execution Support**: On Windows, packet sniffing within containerized network namespaces requires privileged host access or raw Npcap binding. The sensor is designed to run either in Docker (Linux `network_mode: host`) or natively on Windows as a standalone agent connecting to the Redis broker.

#### 2.3 `detection-engine` Service
- **Consumer Model**: Multi-threaded or asynchronous worker polling Redis Stream `flows:raw` with consumer groups for scalable horizontal fan-out.
- **Machine Learning Inference**:
  - **Random Forest Classifier**: Multi-class categorization across 15 classes (Benign, DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest, DDoS, PortScan, FTP-Patator, SSH-Patator, Botnet, Web Attack - Brute Force, Web Attack - XSS, Web Attack - Sql Injection, Infiltration, Heartbleed).
  - **Isolation Forest**: Unsupervised anomaly detection trained purely on baseline benign traffic to flag previously unseen/zero-day signatures.
  - **Explainability**: Extracts top contributing feature deviations per detection using tree-based feature contribution heuristics.
- **Event Dispatch**: High-confidence detections exceeding configured thresholds are written to PostgreSQL and emitted to Redis Stream `detections:stream` and PubSub channels.

#### 2.4 `prevention-engine` Service
- **Policy Engine**:
  - Configurable policy mapping (confidence thresholds, minimum repeated attack detections within a sliding time window, severity assignment).
  - Mode of Operation: **Dry-Run Mode (Default)** vs. **Active Enforcement Mode**.
  - Escalation Strategy: Temporary blocks with progressive backoff (e.g., Level 1 = 5 minutes, Level 2 = 30 minutes, Level 3 = 24 hours, Level 4 = Permanent).
  - Approval Workflow: Optional "Human-in-the-Loop" requirement where blocks enter a `Pending Approval` queue for SOC Analysts/Admins.
- **Firewall Adapters**:
  - Platform abstraction (`FirewallAdapter` base class).
  - Windows: `netsh advfirewall firewall add rule ...` with strict argument separation.
  - Linux: `iptables` / `nftables` rule generation.
  - **Anti-Command-Injection**: Absolute prohibition of raw shell concatenation. All target addresses must validate strictly through Python's `ipaddress.ip_address` or `ipaddress.ip_network`.
- **Immutable Whitelist Guard**:
  - Prevents accidental denial of service of legitimate infrastructure.
  - Guaranteed immunity for: Loopback (`127.0.0.0/8`, `::1`), default gateways, local DNS resolvers, server own interfaces, and admin-defined CIDR blocks.

#### 2.5 `worker` Service (Celery + Redis)
- **Asynchronous Processing Tasks**:
  - **Threat Intelligence**: Enriches malicious IP profiles with GeoIP location, reverse DNS, and rate-limited queries to external APIs (AbuseIPDB, VirusTotal) with persistent caching.
  - **Alert Management**: Deduplicates repeated triggers using sliding window hash keys to prevent alert fatigue.
  - **Notification Dispatch**: Sends high-severity alert notifications via SMTP (Email) and webhooks (Slack/Microsoft Teams compatible payload).
  - **Audit Ledger Chaining**: Appends cryptographically verified entries to the tamper-evident audit ledger.
  - **ML Model Lifecycle & Drift**: Schedules daily drift detection audits (Kolmogorov-Smirnov statistical tests and Population Stability Index against baseline distributions) and stages retraining jobs.

#### 2.6 `realtime` Gateway
- **Real-Time Communication**: Flask-SocketIO (or gevent/eventlet engine) subscribing to Redis PubSub.
- **Broadcast Topics**:
  - `metrics:stats`: Ingestion rate, flows/second, drop rate, CPU/memory telemetry.
  - `detections:live`: Near real-time alert feed for the analyst console.
  - `prevention:action`: Real-time firewall rule activations, dry-run evaluations, and expirations.

---

### 3. Data Storage & Cryptographic Architecture

```
   +------------------------------------------------------------------------------------------+
   |                                  DATABASE SCHEMA OVERVIEW                                |
   +------------------------------------------------------------------------------------------+
   |                                                                                          |
   |   [ users ] 1 --- * [ user_sessions ]                                                    |
   |      |                                                                                   |
   |      +-------- 1 --- * [ audit_logs ] (SHA-256 Hash Chained)                             |
   |      |                                                                                   |
   |      +-------- 1 --- * [ analyst_feedback ]                                              |
   |                                                                                          |
   |   [ network_flows ] (Monthly Range Partitioned)                                          |
   |      |                                                                                   |
   |      +-------- 1 --- 1 [ detections ]                                                    |
   |                             |                                                            |
   |                             +-------- 1 --- * [ alerts ]                                 |
   |                                                                                          |
   |   [ blocked_ips ] (Status: active, expired, released, pending)                           |
   |   [ whitelist ] (Immutable & Admin CIDRs)                                                |
   |   [ threat_intel_cache ] (TTL-backed indicators)                                         |
   |   [ model_artifacts ] 1 --- * [ drift_metrics ]                                          |
   +------------------------------------------------------------------------------------------+
```

#### 3.1 High-Volume Table Partitioning
The `network_flows` and `detections` tables store continuous telemetry. To maintain indexing efficiency and support streamlined historical retention:
- Range partitioning by `timestamp` column on a monthly boundary (`network_flows_y2026m11`, etc.).
- Automated maintenance worker creates future partitions and detaches/archives partitions past retention policy limits (default: 90 days).

#### 3.2 Envelope Encryption Architecture (AES-256-GCM)
Sensitive fields—including full packet payload snippets, decrypted session tokens, and threat intelligence API credentials—are protected using envelope encryption:
1. **Key Encryption Key (KEK)**: 256-bit AES master key loaded securely from an environment variable or external secret manager (`APP_MASTER_KEK`).
2. **Data Encryption Key (DEK)**: A unique 256-bit AES key dynamically generated for each protected record.
3. **Record Storage Format**:
   - `encrypted_data`: Ciphertext produced by AES-256-GCM.
   - `encrypted_dek`: DEK encrypted under KEK using AES-256-GCM.
   - `nonce`: 96-bit initialization vector generated per encryption operation.
   - `auth_tag`: 128-bit authentication tag validating ciphertext and metadata integrity.
   - `key_version`: Identifier supporting zero-downtime KEK rotation.

#### 3.3 Tamper-Evident Hash-Chained Audit Log
All privileged administrative actions, authentication attempts, policy overrides, and firewall modifications are written to the `audit_logs` table:
$$\text{EntryHash}_n = \text{HMAC-SHA256}\Big(\text{Secret}, \ \text{EntryHash}_{n-1} \parallel \text{Timestamp} \parallel \text{UserID} \parallel \text{Action} \parallel \text{Resource} \parallel \text{PayloadDigest}\Big)$$
- If any row is modified or deleted directly in the database, the hash chain breaks.
- A built-in CLI verification command (`python run.py verify-audit-chain`) recalculates the chain from the genesis block to detect unauthorized modifications.

---

### 4. Network and Container Deployment Topology

```
             Client Browser / SOC Analyst
                          │
                          │ HTTPS :443 (TLS 1.3)
                          ▼
             +───────────────────────────+
             │    Nginx Reverse Proxy    │
             │ - TLS Termination         │
             │ - Security Headers        │
             │ - Static Asset Caching    │
             │ - Rate Limiting           │
             +──────┬─────────────┬──────+
                    │             │
       Proxy HTTP   │             │ WebSocket Upgrade
       :5000        │             │ :5001
                    ▼             ▼
             +──────────────+   +──────────────────+
             │   web-api    │   │ realtime service │
             +──────┬───────+   +────────┬─────────+
                    │                    │
                    +──────────┬─────────+
                               │
                               ▼
                        +──────────────+
                        │   Redis 7    │
                        +──────┬───────+
                               │
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
     +──────────────+   +──────────────+   +──────────────+
     │detection-eng │   │prevention-eng│   │Celery Worker │
     +──────┬───────+   +──────┬───────+   +──────┬───────+
            │                  │                  │
            └──────────────────┼──────────────────┘
                               │
                               ▼
                        +──────────────+
                        │PostgreSQL 16 │
                        +──────────────+
```
