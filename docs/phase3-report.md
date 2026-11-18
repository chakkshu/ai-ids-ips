# Phase 3 — ML Pipeline & Model Registry (Verification Report)

**Status:** Code complete, committed, and verified locally. No real-data training or evaluation was performed.
**Branch:** `phase-3-ml`
**Commits:** `d2f6cd2` (Phase 1) → `8eb43cc` (Phase 2, on `master`) → `505f560` (Phase 3) → verification-report commit.
**Design reference:** `docs/ml_pipeline.md`.

---

## 1. Commit / merge confirmation

Phase 2 is committed on `master` at `8eb43cc` and is an ancestor of `HEAD` on `phase-3-ml` (`git merge-base --is-ancestor 8eb43cc HEAD` → exit 0). All Phase 2 and Phase 3 work is committed on `phase-3-ml`; the working tree was clean before this report/ignore-rule update.

The 2FA enrollment fix and its end-to-end test are present:

```
8eb43cc fix(phase2): stabilize TOTP enrollment and complete security hardening
    - Keep a single pending TOTP secret across /setup-2fa reloads and failed codes
    - Add end-to-end enrollment HTTP-flow tests (TestTotpEnrollmentHttpFlow)
```

Located in `tests/unit/test_phase2_auth_security.py`:

```
716: class TestTotpEnrollmentHttpFlow:
719:     def test_enrollment_uses_one_secret_across_reloads_and_enables_2fa(
```

Related tests: `test_enrollment_requires_valid_code_and_shows_codes_once`, `test_forced_password_change_rotation_preserves_pending_enrollment`, `test_totp_validity_and_replay_protection`.

---

## 2. What was built

- **Schema** (`ml/schema.py`): 85 raw columns (84 features + `Label`), 78 ordered `MODEL_FEATURES`; duplicated `Fwd Header Length` canonicalised; garbled labels normalised; unknown labels preserved.
- **Preprocessing** (`ml/preprocess.py`): chunked read, whitespace/alias cleanup, `inf`→NaN, NaN/duplicate removal, seeded stratified 70/15/15 split, train-only scaler/resampler/label encoder, SHA-256 dataset fingerprint.
- **Training** (`ml/train_model.py`): `RandomizedSearchCV` Random Forest with `class_weight="balanced"` or SMOTE/undersampling on train only; Isolation Forest trained on benign train rows; threshold chosen on validation; JSON config; staging-only output.
- **Evaluation** (`ml/evaluate.py`): held-out test metrics, plots, latency, low-support flags; writes to a caller-supplied report dir outside the checksum-sealed artifact tree.
- **Inference** (`ml/predict.py`): checksum verification before any `joblib.load`, strict feature-name/order enforcement, NaN/inf handling, verdicts, top-feature explanation, hot-reload cache.
- **Registry** (`ml/registry/`): `staging/active/archive` + `active.json`, SHA-256 sealing, version/filename traversal guards, `ModelArtifact` registration, Admin-only audited promote/rollback.
- **Drift** (`ml/drift.py`): PSI/KS per feature and on predictions/confidence, warn/critical levels, `DriftMetric` persistence.
- **Dataset check** (`ml/check_dataset.py`): read-only, chunked CSV inspection with clear "no CSV files found" output.
- **Persistence/security**: `0003_phase3_ml_registry` migration, `models:manage` permission granted only to Admin, eight CLI commands, Make targets, `.env.example`, `docs/ml_pipeline.md`, 34 ML unit tests + 1 PostgreSQL integration test, synthetic TEST-ONLY fixture.

---

## 3. Commands and actual output

All commands were run from `C:\Users\KHUSHI\Desktop\ai-ids-ips`, Python 3.13.1, PostgreSQL 16.16 in Docker.

| Gate | Command | Real output |
|---|---|---|
| Ruff | `.venv\Scripts\python.exe -m ruff check .` | `All checks passed!` |
| Black | `.venv\Scripts\python.exe -m black --check .` | `65 files would be left unchanged.` |
| Mypy | `.venv\Scripts\python.exe -m mypy core ml services prevention capture utils` | `Success: no issues found in 45 source files` |
| Bandit | `.venv\Scripts\python.exe -m bandit -r core ml services prevention capture utils -ll` | `No issues identified.` (6,021 lines; 3 low below `-ll`, 0 medium, 0 high) |
| pip-audit | `.venv\Scripts\python.exe -m pip_audit` | `No known vulnerabilities found` (pip 26.3) |
| Pytest seed A (SQLite) | `python -m pytest --randomly-seed=11142026 --cov=... -q tests/` | `TOTAL 3200 413 87%` / `151 passed, 1 skipped, 4 warnings in 232.07s` |
| Pytest seed B (SQLite) | `python -m pytest --randomly-seed=20261118 -q tests/` | `151 passed, 1 skipped in 216.01s` |
| Pytest (PostgreSQL 16) | `AI_IDS_TEST_DATABASE_URL=... python -m pytest -q tests/` | `152 passed in 135.77s` — **0 skipped** |
| Registry tests on PG16 | `python -m pytest -v tests/unit/ml/test_registry.py tests/integration/test_ml_postgres.py` | `6 passed in 10.92s`; `test_registry_lifecycle_on_postgres PASSED`, no SKIPPED |
| Alembic on PG16 | `upgrade head` → `current` → `downgrade 0002` → `current` → `upgrade head` → `current` | `0003_phase3_ml_registry (head)` → `0002_phase2_security_hardening` → `0003_phase3_ml_registry (head)` |
| Smoke pipeline | `python -m ml.train_model --smoke-test` | staged version, 8 SHA-256 checksums, temp registry, no active model |
| Empty dataset check | `python run.py check-dataset --input-dir data/raw` | `CSV files: 0`, `no CSV files found in data\raw`, exit 1 |
| SQLite rebuild | delete `ids_dev.sqlite3` → `alembic upgrade head` → `run.py seed-db` | file deleted; `0003_phase3_ml_registry (head)`; admin seeded (1 audit entry) |
| Registry CLI | `python run.py registry-list` | `[]`, exit 0 |
| Audit CLI | `python run.py verify-audit-chain` | `AUDIT INTEGRITY VERIFIED: All 1 entries in the chain are cryptographically valid.`, exit 0 |

PostgreSQL was started with `docker compose -f docker/docker-compose.yml up -d db` plus a temporary override publishing host port **55432**, because a native `postgresql-x64-18` service occupies host port 5432. `SELECT version()` returned `PostgreSQL 16.16 on x86_64-pc-linux-musl`. The container and throwaway migration database were removed after verification.

### Ignore rules confirmed with `git check-ignore -v`

```
.env                                  → .gitignore:30
ids_dev.sqlite3                       → *.sqlite3
data/raw/MachineLearningCVE.csv       → data/raw/*.csv
ml/models/model.joblib                → ml/models/*
ml/models/metrics.json                → ml/models/*
ml/registry/staging/v1/model.joblib   → ml/registry/staging/
ml/registry/staging/v1/metrics.json   → ml/registry/staging/
ml/registry/active/v1/model.joblib    → ml/registry/active/
ml/registry/archive/v1/checksums.json → ml/registry/archive/
ml/registry/active.json               → ml/registry/active.json
server.pem / server.key / server.crt  → *.pem / *.key / *.crt
```

`ml/registry/paths.py` and `ml/schema.py` are **not** ignored (source code remains tracked). The previous two-level registry pattern (`ml/registry/*/*.joblib`) did not cover real `staging/<version>/` artifacts; it was replaced with whole-area rules.

---

## 4. Test coverage by requirement

| Requirement | Test |
|---|---|
| Tampered artifact refuses to load | `tests/unit/ml/test_predict.py::test_checksum_failure_refuses_before_joblib_load` (asserts `joblib.load` is never called) and `tests/unit/ml/test_registry.py::test_tampered_artifact_refuses_verification` |
| Path traversal rejection in registry | `tests/unit/ml/test_registry.py::test_path_traversal_and_invalid_names_rejected` |
| Staged model never auto-activating | `tests/unit/ml/test_registry.py::test_staged_version_is_not_active` (plus the pre-promotion assertion in `test_promote_rollback_audit_and_rbac`) |
| Promote/rollback writes audit entries | `tests/unit/ml/test_registry.py::test_promote_rollback_audit_and_rbac` and `tests/integration/test_ml_postgres.py::test_registry_lifecycle_on_postgres` |
| Scaler fitted on train rows only | `tests/unit/ml/test_preprocess.py::test_scaler_is_fitted_on_training_rows_only` |
| Resampling on train rows only | `tests/unit/ml/test_train_evaluate_smoke.py::test_smote_resamples_training_split_only` |
| Feature order enforcement | `tests/unit/ml/test_predict.py::test_feature_order_and_contract_enforcement` |

---

## 5. Verification status

| Item | Status |
|---|---|
| Phase 2 + Phase 3 committed on `phase-3-ml`; Phase 2 2FA fix/E2E test included | **Verified** |
| Schema, cleaning, leakage controls, rare-class strategies | **Verified** |
| Checksum-before-load, feature order enforcement, verdicts, hot reload | **Verified** |
| Registry path guards, staging-only, Admin-only promote/rollback, audit chain | **Verified** (SQLite + PostgreSQL 16) |
| Drift PSI/KS and `DriftMetric` persistence | **Verified** |
| Read-only dataset checker including empty directory | **Verified** |
| Migration `0003` up/down/up | **Verified** (SQLite + PostgreSQL 16) |
| `ids_dev.sqlite3` deleted, migrated, seeded; `registry-list` and `verify-audit-chain` work | **Verified** |
| Ruff, Black, Mypy, Bandit, pip-audit | **Verified** |
| Pytest in random order, two seeds | **Verified** |
| PostgreSQL 16 full suite with integration test executed, not skipped | **Verified** |
| Ignore rules for secrets, raw CSVs, model artifacts, certs | **Verified** |
| Real CICIDS2017 accuracy, per-class recall, rare-class support, PSI baselines, full-scale runtime/memory | **Written but unverified** — no dataset present |
| Port-bias and lab-to-production generalisation | **Written but unverified** — requires real data |
| GitHub Actions execution, full compose stack, Redis, web API under load | **Written but unverified** |
| `make` targets (Windows host; direct CLI commands were used instead) | **Written but unverified** |
| Browser E2E / accessibility automation | **Written but unverified** (carried from Phase 2) |
| Real dataset download/generation and real model training into `ml/models/` | **Skipped** — explicitly prohibited for this phase |
| SHAP explanations | **Skipped** — intentionally disabled; importance proxy used |

---

## 6. Low-RAM preprocessing options

All PCA-style options are on `preprocess`; `train` then consumes the saved processed bundle.

```bash
# Smaller per-chunk parse (default 100000; 0 means read whole file at once)
python run.py preprocess --input-dir data/raw --output-dir artifacts/processed --chunksize 25000

# Random 10% sample of all clean rows, deterministic for a given seed
python run.py preprocess --input-dir data/raw --output-dir artifacts/processed --sample-fraction 0.1 --seed 42

# Cap every class (applied after sample-fraction), keeping at least 2 rows per class
python run.py preprocess --input-dir data/raw --output-dir artifacts/processed --max-rows-per-class 5000

# Combine for the smallest footprint; merge ultra-rare classes to avoid unstable CV folds
python run.py preprocess --input-dir data/raw --output-dir artifacts/processed \
  --chunksize 25000 --sample-fraction 0.1 --max-rows-per-class 5000 \
  --rare-strategy merge --seed 42
```

Caveat: `--chunksize` bounds each parsed chunk, but `preprocess` currently accumulates all chunks before concatenating, so it does **not** bound peak memory by itself. Use `--sample-fraction` and/or `--max-rows-per-class` for real memory savings. `check-dataset` is chunked and read-only, so it is safe on a low-RAM host.

Reduced data changes class support and therefore CV folds/thresholds; the effective fold count and sampling parameters are recorded in the staged `config.json`. A model trained on a reduced sample is a development artefact, not the final model.

---

## 7. Risks

- **No deployable model:** all metrics so far are from the 194-row synthetic fixture; every class was flagged low-support.
- **Checksums are integrity checks, not signatures:** an attacker who can rewrite both artifacts and `checksums.json` can defeat them; registry permissions are part of the trust boundary.
- **Pickle deserialization:** load only artifacts this pipeline sealed; verification happens before `joblib.load` but unpickling is code execution.
- **Dataset age / lab bias / CICFlowMeter dependence:** 2017 traffic, lab port-to-attack mappings, and feature-exporter differences limit production validity.
- **Rare-class instability** and **port bias** are documented in `docs/ml_pipeline.md`.
- **PostgreSQL test harness is destructive:** it drops/recreates all tables per test; point `AI_IDS_TEST_DATABASE_URL` only at a disposable database.
- **Environment note:** native PostgreSQL on host 5432 required a temporary 55432 override; no repo file was changed for that workaround.

---

## 8. Next step (stop point)

Add the real CICIDS2017 CSVs to `data/raw/`, then:

```bash
python run.py check-dataset --input-dir data/raw
```

Reply `dataset added` only after the checker reports a clean schema. Phase 4 is not started.
