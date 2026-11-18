"""Single source of truth for the CICIDS2017 MachineLearningCVE schema.

This module describes the *raw* CSV layout, the canonical names used inside the
pipeline, and the ordered feature contract that every saved model must carry.
It contains no dataset and performs no I/O.

Known source-data quirks handled here:

* Column names in the published CSVs have leading/trailing whitespace.
* ``Fwd Header Length`` appears twice; the second occurrence is canonicalised
  as ``Fwd Header Length_Duplicate``.
* ``Flow Bytes/s`` and ``Flow Packets/s`` contain ``inf``/``nan`` values.
  They are replaced in :mod:`ml.preprocess`, never here.
* Web-attack labels contain a garbled dash/en-dash character. Label keys are
  normalised to alphanumerics before lookup.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

LABEL_COLUMN = "Label"
BENIGN_LABEL = "BENIGN"

# Canonical raw columns, in the order used by the MachineLearningCVE release.
# The duplicated Fwd Header Length column is represented explicitly.
RAW_FEATURE_NAMES: tuple[str, ...] = (
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length_Duplicate",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
)

RAW_COLUMNS: tuple[str, ...] = (*RAW_FEATURE_NAMES, LABEL_COLUMN)

# Identifier / non-stationary columns are never model inputs. Timestamps leak
# the collection window; IPs and Flow ID are per-flow identifiers. Source Port
# is ephemeral and dataset-specific. Protocol is flow metadata encoded as a
# small integer in this dataset and is excluded to match the canonical 78
# numeric flow features. Destination Port IS kept: it is available at flow
# creation and carries real signal (SSH-Patator on 22, web attacks on 80/443).
# The trade-off (possible dataset bias toward those ports) is recorded in
# docs/ml_pipeline.md and can be revisited without changing the raw schema.
IDENTIFIER_COLUMNS: frozenset[str] = frozenset(
    {
        "Flow ID",
        "Source IP",
        "Source Port",
        "Destination IP",
        "Protocol",
        "Timestamp",
    }
)

MODEL_FEATURES: tuple[str, ...] = tuple(
    name for name in RAW_FEATURE_NAMES if name not in IDENTIFIER_COLUMNS
)

# Column aliases seen in the published CSVs (whitespace-stripped).
COLUMN_ALIASES: dict[str, str] = {
    "Fwd Header Length.1": "Fwd Header Length_Duplicate",
    "Fwd Header Length.2": "Fwd Header Length_Duplicate",
    "Fwd Header Length_1": "Fwd Header Length_Duplicate",
    "Flow Bytes/s": "Flow Bytes/s",
    "Flow Packets/s": "Flow Packets/s",
}

# Normalised label key -> canonical class name. The garbled dash in the source
# ("Web Attack \x96 Brute Force", often decoded as "â€“") is handled by the
# key normaliser below, which strips all non-alphanumeric characters.
LABEL_NORMALIZATION: dict[str, str] = {
    "benign": "BENIGN",
    "bot": "Bot",
    "ddos": "DDoS",
    "dos goldeneye": "DoS GoldenEye",
    "dos hulk": "DoS Hulk",
    "dos slowhttptest": "DoS Slowhttptest",
    "dos slowloris": "DoS slowloris",
    "ftp patator": "FTP-Patator",
    "ssh patator": "SSH-Patator",
    "portscan": "PortScan",
    "web attack brute force": "Web Attack - Brute Force",
    "web attack xss": "Web Attack - XSS",
    "web attack sql injection": "Web Attack - SQL Injection",
    "infiltration": "Infiltration",
    "heartbleed": "Heartbleed",
}

CANONICAL_LABELS: tuple[str, ...] = tuple(dict.fromkeys(LABEL_NORMALIZATION.values()))

RARE_CLASS_LABELS: frozenset[str] = frozenset(
    {"Heartbleed", "Infiltration", "Web Attack - SQL Injection"}
)

RARE_GROUP_LABEL = "Rare/Other"
DRIFT_BASELINE_LABEL = "__BASELINE__"


def normalise_label_key(raw: str) -> str:
    """Return a punctuation-insensitive, lowercase key for a raw label."""

    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", str(raw).lower())).strip()


def normalize_label(raw: str | float | None) -> str:
    """Map a raw CICIDS label to its canonical class name.

    Unknown labels are returned trimmed rather than silently coerced to
    BENIGN; :mod:`ml.preprocess` reports them as a dataset problem.
    """

    if raw is None:
        return ""
    text = str(raw).strip()
    if not text:
        return ""
    return LABEL_NORMALIZATION.get(normalise_label_key(text), text)


def is_known_label(raw: str | float | None) -> bool:
    """Return True when ``raw`` maps to one of the documented class names."""

    return normalize_label(raw) in CANONICAL_LABELS


def canonicalize_columns(columns: Iterable[str]) -> list[str]:
    """Strip whitespace and resolve duplicate/aliased column names once."""

    canonical: list[str] = []
    seen: dict[str, int] = {}
    for raw in columns:
        name = str(raw).strip()
        name = COLUMN_ALIASES.get(name, name)
        if name in seen:
            seen[name] += 1
            renamed = (
                "Fwd Header Length_Duplicate"
                if name == "Fwd Header Length"
                else f"{name}_Dup{seen[name]}"
            )
            # Reserve the renamed slot too, otherwise a genuine canonical
            # column later in the header can collide with it.
            seen[renamed] = 1
            name = renamed
        else:
            seen[name] = 1
        canonical.append(name)
    return canonical


def assert_schema_consistency() -> None:
    """Fail fast if the single source of truth was edited inconsistently."""

    if len(RAW_COLUMNS) != len(set(RAW_COLUMNS)):
        raise ValueError("RAW_COLUMNS contains duplicate canonical names")
    if len(MODEL_FEATURES) != len(set(MODEL_FEATURES)):
        raise ValueError("MODEL_FEATURES contains duplicate names")
    if not set(MODEL_FEATURES).issubset(set(RAW_COLUMNS)):
        raise ValueError("MODEL_FEATURES must be a subset of RAW_COLUMNS")
    if LABEL_COLUMN in MODEL_FEATURES:
        raise ValueError("The label must never be a model feature")
    if not set(IDENTIFIER_COLUMNS).isdisjoint(MODEL_FEATURES):
        raise ValueError("Identifier columns must not be model features")


assert_schema_consistency()
