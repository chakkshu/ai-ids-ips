# Synthetic ML test fixtures (TEST ONLY)

`TEST_ONLY_synthetic_cicids.csv` is a tiny, deterministic, synthetic CSV shaped
like the CICIDS2017 `MachineLearningCVE` release. It exists **only** for unit
and smoke tests in this repository.

- Do **not** copy it into `data/raw/`.
- Do **not** use it to train or evaluate a production model.
- Do **not** place artifacts produced from it in `ml/models/`.

The fixture deliberately contains:

- padded column names;
- two `Fwd Header Length` columns;
- `inf` and empty/NaN values in rate columns;
- exact duplicate rows;
- the garbled `Web Attack â€“ Brute Force` label variant;
- padded ` BENIGN ` labels.

Regenerate it with:

```bash
python tests/fixtures/ml/generate_test_fixture.py
```
