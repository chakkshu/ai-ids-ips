"""Read-only dataset checker tests on synthetic fixtures."""

from __future__ import annotations

from pathlib import Path

from ml.check_dataset import format_report, inspect_dataset

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "ml"


def test_inspect_fixture_reports_schema_labels_and_problems() -> None:
    before = {path.name: path.stat().st_mtime_ns for path in FIXTURE_DIR.iterdir()}
    report = inspect_dataset(FIXTURE_DIR)
    after = {path.name: path.stat().st_mtime_ns for path in FIXTURE_DIR.iterdir()}

    assert before == after  # read-only
    assert report.csv_count == 1
    assert report.total_rows == 194
    assert report.schema_ok
    assert not report.problems
    fixture = report.files[0]
    assert fixture.name == "TEST_ONLY_synthetic_cicids.csv"
    assert fixture.columns_match
    assert "BENIGN" in fixture.label_counts
    assert "Web Attack - Brute Force" in fixture.label_counts
    assert "Heartbleed" in fixture.label_counts
    assert "  Flow Bytes/s  " not in fixture.missing_columns
    assert "Reachability" in format_report(report) or "readiness" in format_report(
        report
    )


def test_inspect_empty_directory_reports_problem(tmp_path: Path) -> None:
    report = inspect_dataset(tmp_path)
    assert report.csv_count == 0
    assert report.total_rows == 0
    assert not report.schema_ok
    assert any("no CSV files" in problem for problem in report.problems)
