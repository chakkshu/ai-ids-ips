# Phase 3 — ML Pipeline & Model Registry (Report)

**Status:** Complete for review. Implementation and local verification are done; real-data training is not.
**Scope:** Code-only CICIDS2017-shaped ML pipeline, disk model registry, guarded promotion/rollback, verified inference, drift measurement, dataset readiness check, CLI/Make wiring, migration `0003_phase3_ml_registry`, and tests. Built on top of the committed Phase 2 work.
**Branch:** `phase-3-ml` (all Phase 3 changes are uncommitted; `HEAD` is still the Phase 2 commit `d2f6cd2`).
**Design reference:** `docs/ml_pipeline.md`. No model has been trained or evaluated on real CICIDS2017 data in this phase.

---

## 1. What changed

### Schema and leakage controls (`ml/schema.py`, `ml/preprocess.py`)
- Single source of truth: 85 raw columns (84 features + `Label`) and 78 ordered numeric `MODEL_FEATURES`.
- Excluded identifiers/non-stationary columns: `Flow ID`, `Source IP`, `Source Port`, `Destination IP`, `Protocol`, `Timestamp`. `Destination Port` is deliberately included (documented port-bias limitation).
- Canonicalises whitespace, `Fwd Header Length.1`-style aliases, the duplicated `Fwd Header Length`, and garbled web-attack label dashes; preserves unknown labels instead of silently renaming them.
- Seeded, stratified 70/15/15 index split computed **before** resampling or scaling. Scaler, resampler, label encoder, and Isolation Forest are fitted on training rows only; the Isolation Forest anomaly threshold is chosen on validation using Youden's J. The held-out test split is used only for evaluation.
- Imbalance handling: `none` (`class_weight="balanced"`), `smote`, or `undersample` (train split only; `class_weight` disabled when resampling to avoid double correction). Rare classes (`Heartbleed`, `Infiltration`, `Web Attack - SQL Injection`) use explicit `keep` / `merge` / `drop`; counts and strategies are recorded.

### Training and evaluation (`ml/train_model.py`, `ml/evaluate.py`)
- `RandomizedSearchCV` with stratified CV, configurable iteration/fold/job budget, fixed seeds, and a saved config containing the parameter distribution, best parameters, resampling details, dataset hash, and git commit. Classes with too few samples reduce the effective fold count, which is recorded.
- Random Forest for known-attack classification; Isolation Forest fitted on benign training traffic for the anomaly signal.
- Artifacts are written to a temporary work directory and staged through the registry; training never writes to `active/` or `ml/models/`.
- Evaluation writes confusion matrix, per-class metrics, ROC/PR outputs, inference timing, and low-support flags into a caller-supplied output directory **outside** the checksum-sealed artifact tree. Classes with fewer than 20 test samples are flagged (curves are skipped). Matplotlib uses the headless `Agg` backend.

### Registry (`ml/registry/{paths,store,service,errors}.py`)
- Disk layout: `staging/`, `active/`, `archive/`, and an `active.json` pointer. Strict version/filename regexes block traversal; POSIX directories are created best-effort owner-only (`0700`).
- `stage_version` copies and seals eight required artifacts with SHA-256 (`model.joblib`, `scaler.joblib`, `encoder.joblib`, `isolation_forest.joblib`, `features.json`, `config.json`, `baseline.json`, `metrics.json`) and writes `checksums.json` + `metadata.json`.
- Promotion and rollback are explicit, verified, and archive the previous active version. There is no automatic promotion path.
- `verify_artifacts` checks every digest before any `joblib.load`; tampered or missing artifacts raise `ChecksumError`.

### Verified inference and drift (`ml/predict.py`, `ml/drift.py`)
- Feature names and order are enforced against `features.json`; missing/extra/reordered inputs are rejected. `inf` is treated as missing, NaN is imputed with training medians.
- Output: class, confidence, top-k probabilities, Isolation Forest anomaly score, combined verdict (`known attack` / `benign` / `anomaly` / `uncertain`), and top contributing features using `|scaled deviation| × feature importance`. SHAP is intentionally disabled.
- Thread-safe `ModelCache` hot-reloads when `active.json` changes.
- Drift: per-feature PSI/KS, prediction-distribution PSI, confidence PSI/KS, warn/critical levels, and persistence to `DriftMetric`. Thresholds come from `ML_DRIFT_THRESHOLD_PSI`, `ML_DRIFT_CRITICAL_PSI`, `ML_DRIFT_P_VALUE_THRESHOLD`.

### Dataset checker (`ml/check_dataset.py`)
- Read-only, chunked inspection of CICIDS2017 CSVs: size, rows, schema match, label distribution, and problems. Never writes to `data/raw/`; exits nonzero when no CSVs are found or the schema/problems are invalid.

### RBAC, audit, and persistence
- New permission `models:manage` (`Permission.MODELS_MANAGE`) granted only to `admin`; `ml.registry.service.require_model_manager` checks it before promotion/rollback. Staging does not require it but accepts an actor ID for audit attribution.
- Lifecycle events `MODEL_STAGED`, `MODEL_PROMOTED`, `MODEL_ROLLED_BACK` are appended to the hash-chained audit ledger with version and previous-active details.
- `core/models/mlops.py` gains `isolation_forest_path`, `drift_baseline_path`, `checksums_json`, `training_config_json`, `status`, `promoted_at`; migration `0003_phase3_ml_registry` adds these columns plus `ix_model_artifacts_status` and drops them on downgrade.

### Configuration, dependencies, CLI, and CI
- New settings: `ML_DRIFT_CRITICAL_PSI`, `ML_DRIFT_P_VALUE_THRESHOLD`, `ML_RANDOM_SEED`, `ML_CONFIDENCE_THRESHOLD`, `ML_ANOMALY_SCORE_THRESHOLD`, `ML_DATASET_DIR` (documented in `.env.example`).
- New runtime dependencies: `imbalanced-learn>=0.12.0`, `matplotlib>=3.8.0`; dev dependency `pytest-randomly>=3.15.0`.
- Eight new CLI commands in `run.py` and matching `make` targets: `check-dataset`, `preprocess`, `train`, `smoke-test`, `evaluate`, `registry-list`, `registry-promote`, `registry-rollback`.
- CI extended: `master` trigger, dev requirements, ML coverage, Bandit over `ml`, PostgreSQL Alembic up/current/down/up, `AI_IDS_TEST_DATABASE_URL` for the opt-in registry integration test, and cheap Argon2 parameters.

### Tests and fixtures
- `tests/unit/ml/` contains 34 collected tests across schema, preprocessing, training/evaluation smoke, prediction, registry, drift, and dataset checking. `tests/integration/test_ml_postgres.py` adds one opt-in test (skipped without `AI_IDS_TEST_DATABASE_URL`).
- `tests/fixtures/ml/` provides a deterministic synthetic CSV (194 rows, seed 1337) with deliberate real-world quirks, plus a generator and a README forbidding use as real data or production training.
- Notable assertions: checksum failure occurs before `joblib.load`, SMOTE affects training rows only, evaluation leaves staged artifacts byte-identical, path traversal is rejected, tampering is detected, RBAC denies analysts, and the audit chain stays valid after lifecycle changes.

---

## 2. Commands and actual results

All commands were run from `C:\Users\KHUSHI\Desktop\ai-ids-ips` with the project virtualenv on Windows / Python 3.13.1.

| Gate | Command | Result |
|---|---|---|
| Ruff | `.venv\Scripts\python.exe -m ruff check .` | `All checks passed!` (exit 0) |
| Black | `.venv\Scripts\python.exe -m black --check .` | `65 files would be left unchanged.` (exit 0) |
| Mypy (Makefile scope) | `.venv\Scripts\python.exe -m mypy core ml services prevention capture utils` | `Success: no issues found in 45 source files` (exit 0; two pre-existing `annotation-unchecked` notes in `auth.py`) |
| Mypy (CI scope) | `.venv\Scripts\python.exe -m mypy core services run.py` | `Success: no issues found in 29 source files` (exit 0) |
| Bandit | `.venv\Scripts\python.exe -m bandit -r core ml services prevention capture utils -ll` | `No issues identified.` — 6,021 lines scanned; metrics show 3 low, 0 medium, 0 high (low is below the `-ll` reporting threshold) (exit 0) |
| Pytest + coverage | `.venv\Scripts\python.exe -m pytest tests/ -q --cov=core --cov=ml --cov=services --cov=prevention --cov=capture --cov=utils --cov-report=term-missing` | **151 passed, 1 skipped, 1 warning** in 247.91s; total coverage **87%** (3,200 statements, 411 missed) (exit 0) |
| Alembic (SQLite, temp DB) | `alembic upgrade head` → `current` → `downgrade base` → `upgrade head` | `0003_phase3_ml_registry (head)`; all four steps exit 0 |
| Smoke pipeline | `.venv\Scripts\python.exe run.py smoke-test --n-iter 2 --cv-folds 2` | `status: staged`, version `smoke-20261118T071102`, 8 SHA-256 checksums, staged under a temp registry (exit 0) |
| Dataset check (empty raw dir) | `.venv\Scripts\python.exe run.py check-dataset --input-dir data/raw` | `CSV files: 0`, `schema_ok: false`, `no CSV files found in data\raw` (exit 1 — expected: no real data is present) |
| Registry listing | `run.py registry-list` against a freshly migrated temp SQLite DB | `[]` (exit 0) |
| Registry listing (stale dev DB) | `run.py registry-list` against the existing `ids_dev.sqlite3` | **Failed:** `no such column: model_artifacts.isolation_forest_path` — the dev DB has not had migration `0003` applied |

ML coverage highlights: `ml/registry/service.py` 96%, `ml/preprocess.py` 93%, `ml/evaluate.py` 89%, `ml/schema.py` 87%, `ml/registry/paths.py` 87%, `ml/drift.py` 85%, `ml/check_dataset.py` 83%, `ml/registry/store.py` 82%, `ml/predict.py` 80%, `ml/train_model.py` 75%.

### Synthetic smoke-run metrics (not real-data results)

```text
split=test, sample_count=28
accuracy=0.9286   macro F1=0.9296   weighted F1=0.9317
benign false-positive rate=0.0
classes: BENIGN, DDoS, Heartbleed, Infiltration, PortScan, Web Attack - Brute Force
all 6 classes flagged low-support (4-5 samples each, threshold 20)
inference: ~4,040 flows/s on 28 synthetic rows (not a performance benchmark)
```

The staged smoke artifacts live only under a temporary directory; no `.joblib` files were written to `ml/models/`.

---

## 3. Unverified items

These were **not** executed locally and are not claimed as verified:

- Training or evaluation on real CICIDS2017 CSVs. `data/raw/` contains no CSV files; all reported metrics come from the synthetic fixture.
- PostgreSQL 16 Alembic up/down and the opt-in `tests/integration/test_ml_postgres.py` registry lifecycle test. CI is configured for both, but no local PostgreSQL container was started for this report.
- GitHub Actions execution of the updated workflow.
- `pip-audit` dependency vulnerability scan (Bandit SAST was run; `pip-audit` was not).
- Live Redis, the full compose stack, production TLS/proxy termination, and multi-worker behaviour.
- Load, performance, concurrency, and end-to-end latency testing. The throughput figure above is from 28 synthetic rows.
- Browser end-to-end tests and automated accessibility auditing (carried over from Phase 2).
- Real sensor/flow-meter integration; the future flow meter must emit the 78 pinned features in exact order.
- SHAP-based explanations (intentionally disabled; the cheap importance method is used instead).

---

## 4. Pending items

1. Review and approve this Phase 3 report.
2. Commit the Phase 3 changes on `phase-3-ml` (nothing is committed yet).
3. Apply migration `0003_phase3_ml_registry` to `ids_dev.sqlite3` (`alembic upgrade head`) before using `registry-list`, `registry-promote`, or `registry-rollback` against the dev database.
4. Obtain real CICIDS2017 data, run `check-dataset` → `preprocess` → `train` → `evaluate`, and only then promote a version with an existing admin `--actor-id`.
5. Run the CI workflow (including the PostgreSQL registry integration test) on GitHub.
6. Run `pip-audit` and address any findings.
7. Carried over from Phase 2: optionally add Playwright + axe checks and remove the obsolete `version:` key from `docker/docker-compose.yml`.

---

## 5. Risks and notes

- **No deployable model exists.** There are no real-data metrics, no artifacts in `ml/models/`, and no active registry version. The synthetic smoke accuracy is a pipeline correctness signal only.
- **Stale dev database.** `ids_dev.sqlite3` predates migration `0003`; registry CLI commands that query `ModelArtifact` fail until the migration is applied. Tests and the migration check used isolated databases, so this did not affect the test result.
- **Checksums are integrity checks, not signatures.** `checksums.json` is verified against the artifacts, but an attacker with write access to the registry could replace both. Registry directory permissions and OS access control are part of the trust boundary; Windows ACLs are left to the OS.
- **Pickle deserialization.** Artifacts are joblib pickles. Checksum verification happens before loading, but the pipeline must only load artifacts it produced and sealed.
- **Port and lab bias.** `Destination Port` is included and pinned in the feature contract; the model can learn lab service-to-attack mappings. CICFlowMeter-derived features will not be bit-identical to a custom flow meter, so thresholds and drift baselines must be revalidated.
- **Rare-class instability.** Low-support classes are flagged and their metrics should not be trusted independently. The smoke run flagged every class as low support.
- **Database portability.** SQLite was used for fast local tests and migration checks. PostgreSQL is configured in CI but was not exercised locally for Phase 3.
- **Test warnings.** The suite emitted `ResourceWarning`s about unclosed SQLite connections in existing Phase 1 tests; these are not failures but should be cleaned up.
- **Formatting footprint.** Black reports the whole tree clean (65 files); Phase 3 added new modules and tests without reformatting unrelated code.
