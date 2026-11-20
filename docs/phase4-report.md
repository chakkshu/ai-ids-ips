# Phase 4 — Destination Port ablation on CICIDS2017

Status: **complete**. Both model versions are staged and registered as `staged` / `is_active=false`. **Neither model was activated.**
`ml/registry/active.json` exists: **False**.

## Objective

Train and evaluate two like-for-like Random Forest variants on the same cleaned rows, split, seed, resampling policy and search budget.

| Variant | Version | Features | Question |
| --- | --- | ---: | --- |
| `full` | `cicids-80k-full` | 78 | Does the known-good contract benefit from `Destination Port`? |
| `no_destination_port` | `cicids-80k-no-port` | 77 | Does performance survive removal of a lab-port-biased feature? |

## Input verification

`python run.py check-dataset --input-dir data/raw` reported:

- 8 CSV files, 2,830,743 rows, `Schema OK: True`, `Problems: none`.
- All 78 model features are present after alias resolution.
- The 6 identifier columns (Flow ID, Source IP, Source Port, Destination IP, Protocol, Timestamp) are absent from the supplied CSVs and are not model inputs; their absence is informational, not a schema failure.

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

## Like-for-like training settings

Both variants used the same processed bundle (`artifacts/processed/cicids-80k`), seed 42, `resampling=none`, 8 `RandomizedSearchCV` iterations, 3-fold stratified CV, `n_jobs=2`, ≤200 trees, float32 features/scaled matrices, bounded depth and leaf sizes, and a **0.40 GB training memory guard**. No guard, cap or search setting was lowered for either variant.

The final no-port retry was started after the PC restart with Splunk and other heavy apps closed. Preflight `psutil` reported 7.7467 GB total and **1.7011 GB available (78.0% used)**. It used the same 0.40 GB guard and completed without a guard breach.

## Memory guard log — lowest available RAM seen

| Run | Threshold | Samples | Lowest available RAM seen | Max process RSS | Breach |
| --- | ---: | ---: | ---: | ---: | --- |
| Full training | 0.4000 GB | 89 | **0.5607 GB** | 0.6163 GB | No |
| No-port retry training (0.40 GB) | 0.4000 GB | 77 | **0.5894 GB** | 0.6382 GB | No |
| Natural FPR, full | 0.3000 GB | 64 | **0.3885 GB** | 0.3027 GB | No |
| Natural FPR, no-port | 0.4000 GB | 62 | **0.8052 GB** | 0.3110 GB | No |

History of failed or superseded no-port attempts (none produced final staging artifacts):

- An early attempt was cancelled by a server restart before staging.
- A 0.30 GB attempt tripped at **0.2667 GB** available and raised `MemoryError`; it was superseded by a 0.15 GB run.
- The 0.15 GB run completed and was staged, but is **superseded**: it is not like-for-like with the full variant's 0.40 GB training guard. Its metrics must not be used for the final comparison.
- A first 0.40 GB retry after the PC restart tripped its guard at **0.2217 GB** available (minimum **0.1898 GB**) during scaling. It produced no staging artifacts. Its sticky warning persisted even after RAM recovered to 1.32 GB; the run was treated as failed, not accepted.
- A subsequent CLI invocation exited immediately with code 2 because `--work-dir` was not forwarded by `run.py`. No training started and no memory log was written. The CLI passthrough was fixed before the final retry; no training setting was changed.
- Preprocessing ran before JSONL memory logging was added. Its in-process guard was active at 0.40 GB and never breached, but no minimum was persisted.

## Held-out test results (capped test split, n = 46,448 per variant)

| Metric | `full` | `no_destination_port` | Delta (no-port − full) |
| --- | ---: | ---: | ---: |
| Accuracy | 0.990785 | 0.990915 | +0.000129 |
| Macro F1 | 0.854972 | 0.853172 | -0.001800 |
| Weighted F1 | 0.991669 | 0.991824 | +0.000156 |
| Benign FPR (capped test mix) | 0.004760 | 0.004645 | -0.000115 |
| Best trees | 200 | 100 | -100 |
| Best `max_depth` | 12 | 12 | 0 |
| CV folds used | 3 | 3 | 0 |

### Per-class precision / recall / F1 with support

Support counts are identical for both variants because they share the same held-out rows. F1 delta is `no-port − full`.

| Class | Support | Precision full | Recall full | F1 full | Precision no-port | Recall no-port | F1 no-port | F1 delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BENIGN | 11785 | 0.9967 | 0.9860 | 0.9913 | 0.9949 | 0.9863 | 0.9906 | -0.0007 |
| Bot | 292 | 0.7766 | 1.0000 | 0.8743 | 0.7268 | 0.9932 | 0.8394 | -0.0349 |
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

Classes flagged by the evaluator as having fewer than 20 test rows: **Heartbleed**, **Infiltration**, **Web Attack - SQL Injection**. Their scores are not trustworthy.

- **Heartbleed**: 2 test rows; F1 1.0000 (full) vs 1.0000 (no-port).
- **Infiltration**: 6 test rows; F1 0.8000 (full) vs 0.8000 (no-port).
- **Web Attack - SQL Injection**: 3 test rows; F1 0.0323 (full) vs 0.0328 (no-port).

Additional caveats despite support above the 20-row threshold:

- **Bot** (292 rows): F1 0.8743 → 0.8394; recall 1.0000 → 0.9932.
- **Web Attack - Brute Force** (220 rows): F1 0.6523 → 0.6450; recall 0.5500 → 0.5409.
- **Web Attack - XSS** (98 rows): F1 0.5379 → 0.5385; recall 0.7959 → 0.7857.

Classes absent from the test split: none.

## Natural-distribution Benign FPR

Computed on a 20,000-row seeded reservoir sample of raw BENIGN traffic across all 8 CSVs (all 2,273,097 BENIGN rows eligible). This corrects for the capped test mix.

| Variant | False positives / scored | Natural Benign FPR | Rows scanned |
| --- | ---: | ---: | ---: |
| `full` | 261 / 20000 | **0.01305** | 2830743 |
| `no_destination_port` | 247 / 20000 | **0.01235** | 2830743 |

Sampling method: seeded reservoir sample of raw BENIGN rows across all input CSVs; no per-class cap and no train/validation/test reuse. Seed: 42. The full natural-FPR scan was completed earlier under a 0.30 GB guard because of external memory pressure; the reservoir algorithm and sample are identical for both variants.

## Full vs no-port comparison

- Overall performance is effectively unchanged: accuracy 0.990785 → 0.990915 (+0.000129), weighted F1 0.991669 → 0.991824 (+0.000156), macro F1 0.854972 → 0.853172 (-0.001800).
- The macro-F1 movement is concentrated in **Bot** (F1 0.8743 → 0.8394, -0.0349), with smaller changes elsewhere.
- False positives improve slightly without the port on both the capped test mix (0.004760 → 0.004645) and the natural BENIGN sample (0.01305 → 0.01235).
- The searches selected 200 trees for full and 100 for no-port. Both used the same search distribution and budget, so this is not a pure one-feature swap at identical selected hyperparameters.
- Interpretation: `Destination Port` adds little beyond lab-specific signal. Removing it slightly reduces benign false positives and removes lab port-bias risk, with a small Bot F1 loss. **No promotion decision has been made.**

## Registry verification

`python run.py registry-list` returned:

```json
[
  {
    "algorithm": "RandomForestClassifier",
    "created_at": "2026-11-20 18:01:47.753252",
    "dataset_hash": "d08ae06a39b9562f8a0795ebeaaac9429a506f602238aeb8ab7759c3da4d9668",
    "is_active": false,
    "is_staged": true,
    "status": "staged",
    "version": "cicids-80k-no-port"
  },
  {
    "algorithm": "RandomForestClassifier",
    "created_at": "2026-11-18 14:17:03.716967",
    "dataset_hash": "d08ae06a39b9562f8a0795ebeaaac9429a506f602238aeb8ab7759c3da4d9668",
    "is_active": false,
    "is_staged": true,
    "status": "staged",
    "version": "cicids-80k-full"
  }
]
```

`Test-Path ml/registry/active.json` → **False**. No promotion or rollback was called at any point.

## Reproducibility

- Branch: `phase-4-training`
- Dataset fingerprint: `d08ae06a39b9562f8a0795ebeaaac9429a506f602238aeb8ab7759c3da4d9668`
- Processed bundle: `artifacts/processed/cicids-80k`
- Staged artifacts: `ml/registry/staging/cicids-80k-full`, `ml/registry/staging/cicids-80k-no-port`
- Memory logs: `artifacts/memory-full.jsonl`, `artifacts/memory-no-port-0p4b.jsonl`, `artifacts/memory-fpr-full.jsonl`, `artifacts/memory-fpr-no-port.jsonl`
- Natural-FPR reports: `reports/natural-fpr-full.json`, `reports/natural-fpr-no-port.json`
- Preserved training work dir: `artifacts/work-no-port-0p4b`
Artifacts, reports and registry files are gitignored; only source, tests and this report are committed.
