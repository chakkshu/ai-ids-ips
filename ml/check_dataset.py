"""Read-only readiness check for CICIDS2017 CSV files in ``data/raw/``.

This command only opens files for reading. It never downloads, generates,
renames, moves, or deletes data. Header inspection and row/label counting are
chunked so a full MachineLearningCVE release can be checked on low-RAM hosts.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from core.config import settings
from ml.schema import (
    LABEL_COLUMN,
    RAW_COLUMNS,
    canonicalize_columns,
    is_known_label,
    normalize_label,
)

CHUNK_SIZE = 100_000


@dataclass
class FileInspection:
    name: str
    size_bytes: int
    row_count: int
    columns_match: bool
    missing_columns: list[str]
    extra_columns: list[str]
    label_counts: dict[str, int]
    problems: list[str]


@dataclass
class DatasetReport:
    directory: str
    csv_count: int
    total_rows: int
    files: list[FileInspection]
    combined_label_counts: dict[str, int]
    problems: list[str]
    schema_ok: bool

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["files"] = [asdict(item) for item in self.files]
        return payload


def _inspect_file(path: Path) -> FileInspection:
    problems: list[str] = []
    row_count = 0
    counts: Counter[str] = Counter()
    missing: list[str] = []
    extra: list[str] = []
    columns_match = False

    try:
        header = pd.read_csv(path, nrows=0, encoding_errors="replace")
        raw_columns = [str(column) for column in header.columns]
        canonical = canonicalize_columns(raw_columns)
        missing = sorted(set(RAW_COLUMNS).difference(canonical))
        extra = sorted(set(canonical).difference(RAW_COLUMNS))
        columns_match = not missing and not extra
        if missing:
            problems.append(f"missing columns: {', '.join(missing)}")
        if extra:
            problems.append(f"unexpected columns: {', '.join(extra)}")

        label_header = next(
            (column for column in raw_columns if column.strip() == LABEL_COLUMN),
            None,
        )
        if label_header is None:
            problems.append("Label column not found")
            usecols = [raw_columns[0]] if raw_columns else None
        else:
            usecols = [label_header]

        if usecols is not None:
            for chunk in pd.read_csv(
                path,
                chunksize=CHUNK_SIZE,
                usecols=usecols,
                low_memory=False,
                encoding_errors="replace",
            ):
                row_count += len(chunk)
                if label_header is not None:
                    for raw_label in chunk[label_header]:
                        counts[normalize_label(raw_label)] += 1
        if row_count == 0:
            problems.append("file contains no data rows")

        unknown = sorted(
            label for label in counts if label and not is_known_label(label)
        )
        if unknown:
            problems.append(f"unmapped labels: {', '.join(unknown)}")
    except (OSError, ValueError, pd.errors.ParserError) as exc:
        problems.append(f"unreadable CSV: {exc}")

    return FileInspection(
        name=path.name,
        size_bytes=path.stat().st_size if path.exists() else 0,
        row_count=row_count,
        columns_match=columns_match,
        missing_columns=missing,
        extra_columns=extra,
        label_counts=dict(sorted(counts.items())),
        problems=problems,
    )


def inspect_dataset(directory: Path | str) -> DatasetReport:
    """Inspect every CSV in ``directory`` without modifying the filesystem."""

    base = Path(directory)
    paths = sorted(base.glob("*.csv")) if base.is_dir() else []
    files = [_inspect_file(path) for path in paths]
    combined: Counter[str] = Counter()
    problems: list[str] = []
    for item in files:
        combined.update(item.label_counts)
        problems.extend(f"{item.name}: {problem}" for problem in item.problems)
    if not paths:
        problems.append(f"no CSV files found in {base}")

    return DatasetReport(
        directory=str(base),
        csv_count=len(paths),
        total_rows=sum(item.row_count for item in files),
        files=files,
        combined_label_counts=dict(sorted(combined.items())),
        problems=problems,
        schema_ok=bool(files) and all(item.columns_match for item in files),
    )


def format_report(report: DatasetReport) -> str:
    """Render a compact human-readable summary followed by full JSON."""

    lines = [
        "CICIDS2017 dataset readiness check (read-only)",
        f"Directory: {report.directory}",
        f"CSV files: {report.csv_count}",
        f"Total rows: {report.total_rows}",
        f"Schema OK: {report.schema_ok}",
    ]
    for item in report.files:
        lines.append(
            f"  - {item.name}: {item.row_count} rows, "
            f"{item.size_bytes} bytes, schema_match={item.columns_match}"
        )
    if report.problems:
        lines.append("Problems:")
        lines.extend(f"  - {problem}" for problem in report.problems)
    else:
        lines.append("Problems: none")
    lines.append("")
    lines.append(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check CICIDS2017 CSV readiness (read-only)"
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path(settings.ML_DATASET_DIR),
        help="Directory containing the MachineLearningCVE CSV files",
    )
    args = parser.parse_args(argv)
    report = inspect_dataset(args.input_dir)
    print(format_report(report))
    return 0 if report.schema_ok and not report.problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
