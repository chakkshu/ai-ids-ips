"""TEST FIXTURE ONLY - regenerate the tiny synthetic CICIDS2017-shaped CSV.

This generator exists solely for Phase 3 unit/smoke tests. Its output must
never be placed in ``data/raw/`` and must never be used to produce a model in
``ml/models/``. It deliberately includes the source-data quirks the pipeline
must handle: padded column names, a duplicate Fwd Header Length column,
Infinity/NaN values, exact duplicate rows, and a garbled web-attack label.
"""

from __future__ import annotations

import csv
import random
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ml.schema import MODEL_FEATURES, RAW_FEATURE_NAMES

CLASSES = (
    "BENIGN",
    "DDoS",
    "PortScan",
    "Web Attack - Brute Force",
    "Heartbleed",
    "Infiltration",
)
ROWS_PER_CLASS = 32
SEED = 1337


def build_header() -> list[str]:
    header: list[str] = []
    for column in RAW_FEATURE_NAMES:
        if column == "Fwd Header Length_Duplicate":
            # The real release repeats the literal header, not our canonical name.
            header.append(" Fwd Header Length ")
        elif column in {"Flow Duration", "Total Fwd Packets", "Flow Bytes/s"}:
            header.append(f"  {column}  ")
        else:
            header.append(column)
    header.append(" Label ")
    return header


def main() -> None:
    rng = random.Random(SEED)
    output = Path(__file__).with_name("TEST_ONLY_synthetic_cicids.csv")
    header = build_header()
    rows: list[list[str]] = []

    for class_index, label in enumerate(CLASSES):
        for row_index in range(ROWS_PER_CLASS):
            values: dict[str, str] = {}
            for feature in MODEL_FEATURES:
                base = rng.gauss(0.0, 1.0)
                if feature == "Destination Port":
                    ports = {
                        "BENIGN": 443,
                        "DDoS": 80,
                        "PortScan": 22,
                        "Web Attack - Brute Force": 80,
                        "Heartbleed": 443,
                        "Infiltration": 4444,
                    }
                    values[feature] = str(ports[label])
                elif feature in {"Flow Duration", "Total Fwd Packets", "Flow Bytes/s"}:
                    values[feature] = f"{base * 100 + class_index * 10:.4f}"
                elif feature == "Fwd Header Length":
                    values[feature] = f"{20 + class_index * 2 + row_index % 3}"
                else:
                    values[feature] = f"{base + class_index * 0.75:.4f}"

            values["Flow ID"] = (
                f"192.168.10.{row_index + 1}-10.0.0.{class_index + 1}-80-6"
            )
            values["Source IP"] = f"192.168.10.{row_index + 1}"
            values["Source Port"] = str(50000 + row_index)
            values["Destination IP"] = f"10.0.0.{class_index + 1}"
            values["Protocol"] = "6"
            values["Timestamp"] = f"17/03/2026 {row_index % 24:02d}:00:00"

            row = [values[column.strip()] for column in header[:-1]]
            raw_label = label
            if label == "Web Attack - Brute Force" and row_index % 2 == 0:
                raw_label = "Web Attack â€“ Brute Force"
            elif label == "BENIGN" and row_index % 5 == 0:
                raw_label = " BENIGN "
            row.append(raw_label)
            rows.append(row)

    # Known data quirks, applied after generation.
    for row in rows[:3]:
        row[header.index("  Flow Bytes/s  ")] = "inf"
    for row in rows[3:6]:
        row[
            (
                header.index("  Flow Packets/s  ")
                if "  Flow Packets/s  " in header
                else header.index("Flow Packets/s")
            )
        ] = ""
    # Use clean rows so the duplicates survive the NaN-dropping step and are
    # actually removed by drop_duplicates.
    rows.extend([list(rows[10]), list(rows[11])])

    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)
    print(f"Wrote {len(rows)} synthetic test-only rows to {output}")


if __name__ == "__main__":
    main()
