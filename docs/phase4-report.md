# Phase 4 — Destination Port ablation on CICIDS2017

Status: **complete**. Both model versions are staged and registered as
`staged` / `is_active=false`. **Neither model was activated.**
`ml/registry/active.json` does not exist.

## Objective

Train and evaluate two like-for-like Random Forest variants on the same
cleaned rows and split:

| Variant | Version | Features | Question |
| --- | --- | ---: | --- |
| `full` | `cicids-80k-full` | 78 | Does the known-good contract benefit from `Destination Port`? |
| `no_destination_port` | `cicids-80k-no-port` | 77 | Does performance survive removal of a lab-port-biased feature? |

## Input verification

`python run.py check-dataset --input-dir data/raw` reported:

- 8 CSV files, 2,830,743 rows, `Schema OK: True`, `Problems: none`.
- All 78 model features present after alias resolution.
- The 6 identifier columns (Flow ID, Source IP, Source Port, Destination IP,
  Protocol, Timestamp) are absent from the supplied CSVs and are not model
  inputs; their absence is informational, not a schema failure.

## Sampling disclosure

| Stage | Sampling applied |
| --- | --- |
| Raw scan | Every row of all 8 CSVs was read. |
| Preprocessing | Deterministic reservoir cap of **80,000 rows per class**, applied while streaming. Only BENIGN, DDoS, DoS Hulk and PortScan exceeded the cap. All smaller classes kept every row. **No SMOTE and no undersampling.** |
| Cleaned bundle | 359,616 capped rows → 309,651 after cleaning (49,492 exact duplicates and 473 NaN rows dropped). |
| Train / validation / test | One shared stratified **70/15/15** split of the capped bundle, reused for both variants: **216,755 / 46,448 / 46,448**. |
| Held-out test distribution | **Not natural** for the four capped classes. All test metrics below reflect the capped mix. |
| Training class balancing | `class_weight="balanced"` only; no synthetic or duplicate rows were added. |
| Natural FPR check | Seeded reservoir sample of **20,000 raw BENIGN rows** across all 8 CSVs, scanned from all 2,830,743 rows. These rows never enter training/validation/test and are never capped. |

## Memory-safe configuration and guard log

- float32 features, scaled matrices and scaler statistics end-to-end.
- Chunked streaming with per-class reservoir (peak bounded by class caps plus
  one chunk).
- `RandomizedSearchCV`: 8 iterations, 3-fold stratified CV, `n_jobs=2`,
  threaded backend (no duplicated forests in worker processes).
- Forest ceiling: ≤200 trees, depth ≤12, `min_samples_leaf` ≥2.
- Background memory sampling every 15 s with caller-checked hard stops.

| Run | Threshold | Samples | Lowest available RAM seen | Max process RSS | Breach |
| --- | ---: | ---: | ---: | ---: | --- |
| `cicids-80k-full` training | 0.40 GB | 89 | **0.5607 GB** | 0.6163 GB | No |
| `cicids-80k-no-port` training (successful) | 0.15 GB | 125 | **0.3293 GB** | 0.6506 GB | No |
| Natural FPR, full | 0.30 GB | 64 | 0.3885 GB | 0.3027 GB | No |
| Natural FPR, no-port | 0.15 GB | 65 | 0.6016 GB | 0.3150 GB | No |

Notes on aborted attempts (all stopped safely, no artifacts written):

- First no-port attempt was cancelled by a server restart.
- Second no-port attempt breached its 0.30 GB threshold at **0.2667 GB**
  available and raised `MemoryError`; it was rerun with a 0.15 GB stop.
- Preprocessing ran before the JSONL memory logger was added. Its in-process
  guard was active at 0.40 GB and never breached, but no minimum was persisted.

## Held-out test results (capped test split, n = 46,448 per variant)

| Metric | `full` | `no_destination_port` | Delta (no-port − full) |
| --- | ---: | ---: | ---: |
| Accuracy | 0.990785 | 0.990915 | +0.000130 |
| Macro F1 | 0.854972 | 0.853172 | **−0.001800** |
| Weighted F1 | 0.991669 | 0.991824 | +0.000155 |
| Benign FPR (capped test mix) | 0.004760 | 0.004645 | −0.000115 |
| Best trees | 200 | 100 | −100 |
| Best `max_depth` | 12 | 12 | 0 |
| CV folds used | 3 | 3 | 0 |

### Per-class precision / recall / F1 with support

Support counts are identical for both variants because they share the same
held-out rows. F1 delta is `no-port − full`.

| Class | Support | Precision full | Recall full | F1 full | Precision no-port | Recall no-port | F1 no-port | F1 delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BENIGN | 11785 | 0.9967 | 0.9860 | 0.9913 | 0.9949 | 0.9863 | 0.9906 | -0.0007 |
| Bot | 292 | 0.7766 | 1.0000 | 0.8743 | 0.7268 | 0.9932 | 0.8394 | **-0.0349** |
| DDoS | 11999 | 0.9997 | 0.9986 | 0.9991 | 0.9996 | 0.9987 | 0.9991 | +0.0000 |
| DoS GoldenEye | 1543 | 0.9967 | 0.9689 | 0.9826 | 0.9934 | 0.9754 | 0.9843 | +0.0017 |
| DoS Hulk | 9077 | 0.9936 | 0.9959 | 0.9948 | 0.9971 | 0.9959 | 0.9965 | +0.0018 |
| DoS Slowhttptest | 784 | 0.9962 | 0.9923 | 0.9942 | 0.9962 | 0.9923 | 0.9942 | +0.0000 |
| DoS slowloris | 808 | 0.9703 | 0.9703 | 0.9703 | 0.9912 | 0.9703 | 0.9806 | +0.0103 |
| FTP-Patator | 889 | 0.9966 | 1.0000 | 0.9983 | 1.0000 | 0.9989 | 0.9994 | +0.0011 |
| Heartbleed | 2 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | +0.0000 |
| Infiltration | 6 | 1.0000 | 0.6667 | 0.8000 | 1.0000 | 0.6667 | 0.8000 | +0.0000 |
| PortScan | 8459 | 0.9994 | 0.9991 | 0.9992 | 0.9994 | 0.9989 | 0.9992 | -0.0001 |
| SSH-Patator | 483 | 0.9959 | 1.0000 | 0.9979 | 1.0000 | 0.9959 | 0.9979 | -0.0000 |
| Web Attack - Brute Force | 220 | 0.8013 | 0.5500 | 0.6523 | 0.7987 | 0.5409 | 0.6450 | -0.0073 |
| Web Attack - SQL Injection | 3 | 0.0169 | 0.3333 | 0.0323 | 0.0172 | 0.3333 | 0.0328 | +0.0005 |
| Web Attack - XSS | 98 | 0.4062 | 0.7959 | 0.5379 | 0.4096 | 0.7857 | 0.5385 | +0.0005 |

### Low-support warnings

The evaluation flags classes with fewer than 20 test rows as **not
trustworthy**:

- **Heartbleed**: 2 test rows — F1 1.0000 in both variants is meaningless.
- **Web Attack - SQL Injection**: 3 test rows — F1 ≈ 0.032 in both variants;
  precision is near zero because almost every benign flow is a negative.
- **Infiltration**: 6 test rows — recall 0.6667 in both variants.

Additional honest warnings even though support exceeds the 20-row threshold:

- **Web Attack - Brute Force** (220 rows): F1 0.6523 → 0.6450; weak recall
  (~0.55) in both variants.
- **Web Attack - XSS** (98 rows): F1 ≈ 0.538; precision ≈ 0.41.
- **Bot** (292 rows): the only material regression when removing the port,
  F1 0.8743 → 0.8394.

No class was absent from the test split.

## Natural-distribution Benign FPR

Computed on a 20,000-row seeded reservoir sample of raw BENIGN traffic across
all 8 CSVs (all 2,273,097 BENIGN rows eligible). This corrects for the capped
test mix.

| Variant | False positives / scored | Natural Benign FPR |
| --- | ---: | ---: |
| `full` | 261 / 20,000 | **0.01305** |
| `no_destination_port` | 247 / 20,000 | **0.01235** |

The no-port model produced 14 fewer false positives on the identical sample,
a relative reduction of about 5.4%, but the difference is small in absolute
terms (0.70 percentage points).

## Full vs no-port comparison

- **Overall performance is effectively unchanged.** Accuracy (+0.00013) and
  weighted F1 (+0.00016) are marginally better without the port; macro F1 is
  marginally worse (−0.0018).
- **The macro-F1 drop is concentrated in Bot** (−0.0349 F1), with a smaller
  regression on Web Attack - Brute Force (−0.0073). Most other classes differ
  by ≤0.002 F1.
- **False positives improve slightly without the port** on both the capped test
  split (0.004760 → 0.004645) and the natural BENIGN sample (0.01305 →
  0.01235).
- The no-port search selected 100 trees versus 200 for full, so the result is
  not a pure one-feature swap at identical hyperparameters; both searches used
  the same distribution and budget.
- Interpretation: `Destination Port` adds little beyond lab-specific signal.
  Removing it slightly reduces benign false positives and removes the port-bias
  risk, at the cost of a small Bot recall/F1 loss. Either version would be
  defensible; **no promotion decision has been made**.

## Registry verification

Both versions were recorded in `ModelArtifact` without activation:

```json
[
  {
    "algorithm": "RandomForestClassifier",
    "is_active": false,
    "is_staged": true,
    "status": "staged",
    "version": "cicids-80k-no-port"
  },
  {
    "algorithm": "RandomForestClassifier",
    "is_active": false,
    "is_staged": true,
    "status": "staged",
    "version": "cicids-80k-full"
  }
]
```

`Test-Path ml/registry/active.json` → **False**. No promotion or rollback was
called at any point.

## Reproducibility

- Branch: `phase-4-training`
- Dataset fingerprint: `d08ae06a39b9562f8a0795ebeaaac9429a506f602238aeb8ab7759c3da4d9668`
- Processed bundle: `artifacts/processed/cicids-80k`
- Staged artifacts: `ml/registry/staging/cicids-80k-full`,
  `ml/registry/staging/cicids-80k-no-port`
- Memory logs: `artifacts/memory-full.jsonl`, `artifacts/memory-no-port.jsonl`,
  `artifacts/memory-fpr-full.jsonl`, `artifacts/memory-fpr-no-port.jsonl`
- Natural-FPR reports: `reports/natural-fpr-full.json`,
  `reports/natural-fpr-no-port.json`

Artifacts, reports and registry files are gitignored; only source, tests and
this report are committed.
