# Phase 4 — Destination Port ablation on CICIDS2017

Status: **in progress** — both models are staged only; neither is active.

## Objective

Train and evaluate two like-for-like Random Forest variants on the same cleaned
rows and split:

| Variant | Features | Question |
| --- | ---: | --- |
| `full` | 78 | Does the known-good feature contract benefit from `Destination Port`? |
| `no_destination_port` | 77 | Does performance survive removal of a lab-port-biased feature? |

No model has been promoted or activated.

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
| Raw scan | Every row of all 8 CSVs is read. |
| Preprocessing | Deterministic reservoir cap of **80,000 rows per class**, applied while streaming. Only BENIGN, DDoS, DoS Hulk and PortScan exceed the cap. All smaller classes are kept in full. No SMOTE and no undersampling. |
| Train / validation / test | One shared stratified 70/15/15 split of the capped bundle is reused for both variants. |
| Held-out test distribution | **Not natural** for the four capped classes. Per-class metrics below reflect the capped mix. |
| Natural FPR check | Separate uniform sample of **20,000 raw BENIGN rows**, drawn from the original CSVs, never seen in training/validation/test and never capped. |
| Training class balancing | `class_weight="balanced"` only; no synthetic or duplicate rows. |

## Memory-safe configuration

- float32 features, scaled matrices and statistics end-to-end.
- Chunked streaming with a per-class reservoir (peak bounded by the sum of
  class caps plus one chunk).
- `RandomizedSearchCV`: 8 iterations, 3-fold stratified CV, `n_jobs=2`,
  threaded backend (no duplicated forests in worker processes).
- Forest ceiling: ≤200 trees, depth ≤12, `min_samples_leaf` ≥2.
- Background memory sampling every 15 s with a hard stop at 0.4 GB available
  RAM, checked at chunk and phase boundaries.

Estimated peak RSS: <1.2 GB per variant; variants run sequentially. See the
`artifacts/preprocess-80k.log` and per-version training logs for the observed
memory guard snapshots.

## Results

Results will be filled from the staged artifacts after both runs complete.

## Low-support warnings

Classes with fewer than 20 held-out rows are flagged as low-support; their
precision/recall/F1 are reported but are not statistically trustworthy.

## Conclusion

Pending.
