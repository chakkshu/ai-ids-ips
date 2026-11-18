# Phase 3 ML Pipeline — Design and Operations

This document describes the code-only Phase 3 ML pipeline. **No model has been
trained or evaluated on real CICIDS2017 data in this phase.** Only the synthetic
test fixture under `tests/fixtures/ml/` has been used, and its artifacts live in
temporary directories, never in `ml/models/`.

## 1. Single source of truth (`ml/schema.py`)

`RAW_COLUMNS` describes the 85 columns in the MachineLearningCVE CSVs: 84
feature columns plus `Label`. The published files contain a duplicated
`Fwd Header Length`; the second occurrence is canonicalised as
`Fwd Header Length_Duplicate`. Column names are stripped of leading/trailing
whitespace once, aliases such as `Fwd Header Length.1` are resolved, and the
garbled web-attack dash is normalised by stripping non-alphanumerics before a
label lookup.

`MODEL_FEATURES` contains 78 numeric flow features. Six identifier or
non-stationary columns are excluded:

| Column | Reason |
|--------|--------|
| `Flow ID` | Per-flow identifier, cannot generalise |
| `Source IP` | Network-specific identifier |
| `Source Port` | Ephemeral and dataset-specific |
| `Destination IP` | Network-specific identifier |
| `Protocol` | Constant/low-cardinality metadata in this release; excluded to match the canonical 78-feature contract |
| `Timestamp` | Leaks the collection window and day of the lab experiment |

**Destination Port decision:** included. It is present at flow creation (not a
post-hoc artefact) and carries real signal for SSH-Patator (22), web attacks
(80/443), and similar services. The trade-off is that the model can learn the
lab's port-to-attack mapping; this is listed as a known limitation and the
feature set version is pinned with every model. Changing this decision requires
a new schema version and a new model, not a silent per-request override.

The ordered feature list is saved in `features.json` inside every staged
artifact and is enforced at inference. A request with missing, extra, or
reordered features is rejected.

## 2. Leakage prevention

1. **Split before anything else.** `ml/preprocess.py` performs a stratified
   70/15/15 train/validation/test split on row indices before resampling or
   scaling and saves `split_indices.json`. The split is seeded.
2. **Train-only scaler.** `StandardScaler` (or `RobustScaler`) is fitted only on
   `split.train`; validation and test rows are transformed with that fitted
   scaler.
3. **Train-only resampling.** SMOTE and random undersampling are applied only
   to the training split. Validation and test rows are never synthesised,
   duplicated, or discarded by a sampler.
4. **Train-only label encoder.** The `LabelEncoder` is fitted on training
   labels; the mapping is saved as `encoder.joblib`.
5. **Validation used for thresholds, test used only for reporting.** The
   Isolation Forest is fitted on benign training rows; its decision threshold
   is chosen on validation rows using Youden's J statistic. The held-out test
   split is used only by `evaluate.py` and for the registry metrics.
6. **No silent class drops.** Rare classes can be `keep`, `merge` into
   `Rare/Other`, or `drop`, but the chosen strategy and resulting counts are
   recorded in `preprocessing.json` and in the training config.

## 3. Imbalance strategy

CICIDS2017 is highly imbalanced (Heartbleed, Infiltration, and SQL Injection
are extremely rare). The pipeline supports:

- `none` — `class_weight="balanced"` on the Random Forest;
- `smote` — synthetic minority oversampling on the training split only;
- `undersample` — random undersampling of majority classes on the training
  split only.

When resampling is enabled, `class_weight` is disabled to avoid double
correction. The rare-class option is independent: `keep` preserves the original
classes; `merge` combines the documented rare classes into `Rare/Other`;
`drop` removes them with an explicit count. `merge` improves per-class support
but loses attack-type granularity; `drop` avoids unstable CV folds but creates
blind spots; `keep` is the default and is the most faithful to the source.

Classes with fewer than the requested CV folds automatically reduce the fold
count, with the effective value recorded in `config.json`. Classes with fewer
than 20 held-out samples are flagged as low-support in evaluation output.

## 4. Training and staging

`ml/train_model.py` uses `RandomizedSearchCV` with stratified CV, a configurable
iteration budget and `n_jobs`, fixed seeds, and a saved JSON config containing
the parameter distribution, best parameters, resampling details, dataset hash,
and git commit. A Random Forest is trained for known-attack classification; an
Isolation Forest is trained only on benign training traffic for the anomaly
signal.

Training writes artifacts to a temporary work directory and then calls
`ml.registry.store.stage_version`, which copies them under
`<registry>/staging/<version>/` and seals them with SHA-256 checksums. Training
never writes to `active/` or `ml/models/`. A staged model remains staged until
an explicit Admin call promotes it.

## 5. Registry, RBAC, and promotion

`ml/registry/` provides disk versioning (`staging/`, `active/`, `archive/`, and
`active.json`) plus `ModelArtifact` rows from Phase 1. Paths are validated with
strict version and filename regular expressions to prevent traversal; registry
directories are created owner-only on POSIX.

`register_staged_version` records checksums, ordered features, metrics, dataset
hash, git commit, and training config. `promote_version` and `rollback_version`
are only reachable through `ml.registry.service`, which requires the
`models:manage` permission. That permission is granted only to `admin` in
`core/rbac.py`. Every lifecycle change calls `log_security_event`, so the
hash-chained audit ledger records the actor, version, and previous active
version. There is no automatic promotion path.

## 6. Verified inference (`ml/predict.py`)

- `checksums.json` is verified against every artifact before any `joblib.load`
  call; a tampered pickle is refused.
- Feature names and order are checked against `features.json`.
- `inf` is treated as missing and NaN is imputed with training-split medians.
- Output includes predicted class, confidence, top-k probabilities, Isolation
  Forest anomaly score, a combined verdict (`known attack`, `benign`,
  `anomaly`, or `uncertain`), and top contributing features.
- Top features use a deliberately cheap method: `|scaled deviation| × feature
  importance`, ranked per flow. SHAP is optional and intentionally disabled.
- `ModelCache` is thread-safe and reloads automatically when `active.json`
  points to a different version.

## 7. Drift (`ml/drift.py`)

Training saves a drift baseline (`baseline.json`) with per-feature quantile
statistics, a bounded 500-row KS reference sample, validation prediction
distribution, and validation confidence distribution. `compute_drift` reports
PSI and KS per feature, prediction-distribution PSI, confidence PSI and KS, and
warn/critical levels. `record_drift` writes the summary to `DriftMetric`. The
default thresholds are configurable through `ML_DRIFT_THRESHOLD_PSI`,
`ML_DRIFT_CRITICAL_PSI`, and `ML_DRIFT_P_VALUE_THRESHOLD`.

## 8. Read-only dataset checker

`ml/check_dataset.py` (CLI: `check-dataset`) lists CSV files, sizes, row counts,
schema match, label distribution, and problems. It opens files only for
reading, uses chunked label counts, and never writes to `data/raw/`.

## 9. Commands

```bash
python run.py check-dataset --input-dir data/raw
python run.py preprocess --input-dir data/raw --output-dir artifacts/processed --rare-strategy keep
python run.py train --processed-dir artifacts/processed --version rf-20261117 --actor-id 1
python run.py evaluate --processed-dir artifacts/processed --artifact-dir ml/registry/staging/rf-20261117 --output-dir reports/rf-20261117
python run.py registry-list
python run.py registry-promote --version rf-20261117 --actor-id 1
python run.py registry-rollback --version rf-20261116 --actor-id 1

# No real data required; uses tests/fixtures/ml/ and temp directories:
python run.py smoke-test --n-iter 2 --cv-folds 2
make smoke-test
```

Promotion and rollback require an existing Admin user ID because the service
layer checks `models:manage` before touching the registry.

## 10. Mapping to a later custom flow meter

The sensor's future flow meter must emit the 78 `MODEL_FEATURES` in the exact
saved order. `Destination Port`, packet/byte counts, lengths, IAT statistics,
flag counts, and bulk/subflow/active/idle statistics are all derivable from a
5-tuple-keyed flow table at flow expiry. Identifiers are used for correlation
and prevention decisions but never as model inputs until the schema is
explicitly versioned. A schema adapter in a later phase must validate feature
presence and order before calling `predict_batch`; it must not reorder silently.

## 11. Known limitations

- **Dataset age:** CICIDS2017 (2017) does not represent modern protocols, TLS
  patterns, or encryption behaviour.
- **Lab-to-production gap:** attack volumes, background traffic, and label
  quality differ from a live enterprise network.
- **CICFlowMeter dependence:** the source features were produced by CICFlowMeter;
  a custom sensor flow meter will not be bit-identical. Thresholds and drift
  baselines must be revalidated after migration.
- **Rare-class instability:** even with stratification, very rare attacks yield
  few test examples; low-support classes are flagged and their metrics should
  not be trusted independently.
- **Port bias:** including Destination Port can overfit the lab's service ports.
- **No real-data results in Phase 3:** metrics in this repository come only from
  the synthetic test fixture smoke run.
