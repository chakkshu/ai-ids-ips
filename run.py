#!/usr/bin/env python3
"""AI-IDS/IPS Enterprise Platform Central Management CLI.

Provides unified administrative entrypoints for service execution, database migrations,
audit ledger verification, and initial deployment bootstrapping.
"""

from __future__ import annotations

import argparse
import json
import sys

from core.config import settings
from core.logging import get_logger, setup_logging
from ml.schema import FEATURE_VARIANTS

logger = get_logger("run")


def cmd_seed_db(args: argparse.Namespace) -> int:
    """Initialize default administrator account and immutable whitelist entries."""
    setup_logging(level="INFO", json_format=False)
    logger.info("Initializing database seeding...")

    from core.db import Base, engine, get_db_session
    from core.models import User, UserRole, Whitelist
    from core.security import (
        audit_details,
        hash_password,
        log_security_event,
        record_password_history,
    )

    # Ensure all tables exist in database schema
    Base.metadata.create_all(engine)

    with get_db_session() as session:
        # 1. Check or create default admin
        admin_user = (
            session.query(User)
            .filter_by(username=settings.INITIAL_ADMIN_USERNAME)
            .first()
        )
        if not admin_user:
            logger.info(
                "Creating default administrator: '%s'",
                settings.INITIAL_ADMIN_USERNAME,
            )
            admin_user = User(
                username=settings.INITIAL_ADMIN_USERNAME,
                email=settings.INITIAL_ADMIN_EMAIL,
                password_hash=hash_password(settings.INITIAL_ADMIN_PASSWORD),
                role=UserRole.ADMIN,
                is_active=True,
                must_change_password=settings.INITIAL_ADMIN_FORCE_PASSWORD_CHANGE,
            )
            session.add(admin_user)
            session.flush()
            record_password_history(admin_user, admin_user.password_hash, session)

            log_security_event(
                action="INITIAL_ADMIN_SEED",
                resource_type="USER",
                resource_id=str(admin_user.id),
                user_id=admin_user.id,
                username="system",
                status="SUCCESS",
                details=audit_details(
                    target_user=admin_user.username,
                    force_password_change=admin_user.must_change_password,
                ),
                db_session=session,
            )
            logger.info(
                "Admin account created. The seeded password must be changed at first login."
            )
        else:
            logger.info("Administrator account already exists. Skipping creation.")

        # 2. Seed immutable CIDR whitelists
        default_whitelists = [
            ("127.0.0.1/32", "IPv4 Loopback (Untouchable)", True),
            ("::1/128", "IPv6 Loopback (Untouchable)", True),
            ("192.168.1.1/32", "Default Gateway / Router (Protected)", True),
            ("10.0.0.1/32", "Internal Network Gateway (Protected)", True),
        ]

        for cidr, desc, immutable in default_whitelists:
            existing = session.query(Whitelist).filter_by(cidr=cidr).first()
            if not existing:
                logger.info("Seeding whitelist rule: %s (%s)", cidr, desc)
                wl_entry = Whitelist(
                    cidr=cidr,
                    description=desc,
                    is_immutable=immutable,
                    created_by_user_id=admin_user.id if admin_user else None,
                )
                session.add(wl_entry)

    logger.info("Database seeding completed successfully.")
    return 0


def cmd_verify_audit_chain(args: argparse.Namespace) -> int:
    """Cryptographically verify the integrity of the HMAC-SHA256 audit ledger."""
    setup_logging(level="INFO", json_format=False)
    logger.info("Beginning cryptographic verification of audit ledger...")

    from core.db import get_db_session
    from core.models import AuditLog

    with get_db_session() as session:
        logs = session.query(AuditLog).order_by(AuditLog.id.asc()).all()
        if not logs:
            logger.info("Audit log ledger is empty. Chain is pristine.")
            return 0

        broken_ids = AuditLog.verify_chain(settings.AUDIT_HMAC_SECRET, logs)
        if not broken_ids:
            logger.info(
                "AUDIT INTEGRITY VERIFIED: All %s entries in the chain are cryptographically valid.",
                len(logs),
            )
            return 0

        logger.critical(
            "AUDIT CHAIN INTEGRITY BREACHED: Tamper detected at entry ID %s.",
            broken_ids[0],
        )
        return 1


def cmd_web_api(args: argparse.Namespace) -> int:
    """Launch the Web API & SOC Dashboard."""
    logger.info(f"Starting Web API server on {args.host}:{args.port}...")
    # Placeholder for Phase 2/7 full Flask web application factory
    from services.web_api import create_app

    app, socketio = create_app()
    socketio.run(app, host=args.host, port=args.port, debug=settings.APP_DEBUG)
    return 0


def cmd_sensor(args: argparse.Namespace) -> int:
    """Launch the real-time packet capture sensor agent."""
    logger.info("Starting packet capture sensor...")
    from services.sensor import run_sensor

    run_sensor(interface=args.interface, bpf_filter=args.bpf)
    return 0


def cmd_detection(args: argparse.Namespace) -> int:
    """Launch the machine learning detection engine."""
    logger.info("Starting ML detection engine worker...")
    from services.detection_engine import run_detection_engine

    run_detection_engine()
    return 0


def cmd_prevention(args: argparse.Namespace) -> int:
    """Launch the safe automated prevention policy engine."""
    logger.info("Starting prevention engine worker...")
    from services.prevention_engine import run_prevention_engine

    run_prevention_engine()
    return 0


def cmd_worker(args: argparse.Namespace) -> int:
    """Launch Celery background worker fleet."""
    logger.info("Starting Celery asynchronous worker...")
    from services.worker import celery_app

    celery_app.worker_main(["worker", "--loglevel=INFO", "-E"])
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    """Launch the CICIDS2017 traffic replay simulation generator."""
    logger.info(f"Starting traffic replay simulator (rate: {args.rate} flows/sec)...")
    from capture.replay_simulator import run_simulator

    run_simulator(speed=args.rate, loop=args.loop)
    return 0


def cmd_check_dataset(args: argparse.Namespace) -> int:
    """Read-only inspection of data/raw/ CSV readiness."""

    from ml.check_dataset import main as check_main

    return check_main(["--input-dir", str(args.input_dir)])


def cmd_preprocess(args: argparse.Namespace) -> int:
    """Clean CICIDS2017 CSVs into an immutable processed bundle."""

    from ml.preprocess import main as preprocess_main

    argv = [
        "--input-dir",
        str(args.input_dir),
        "--output-dir",
        str(args.output_dir),
        "--chunksize",
        str(args.chunksize),
        "--rare-strategy",
        args.rare_strategy,
        "--scaler",
        args.scaler,
        "--seed",
        str(args.seed),
    ]
    if args.sample_fraction is not None:
        argv.extend(["--sample-fraction", str(args.sample_fraction)])
    if args.max_rows_per_class is not None:
        argv.extend(["--max-rows-per-class", str(args.max_rows_per_class)])
    if args.stream_sample:
        argv.append("--stream-sample")
    argv.extend(["--min-available-gb", str(args.min_available_gb)])
    argv.extend(["--memory-interval", str(args.memory_interval)])
    if args.memory_log is not None:
        argv.extend(["--memory-log", str(args.memory_log)])
    return preprocess_main(argv)


def cmd_train(args: argparse.Namespace) -> int:
    """Train a model and write it only to the registry staging area."""

    from ml.train_model import main as train_main

    argv = [
        "--processed-dir",
        str(args.processed_dir),
        "--registry-root",
        str(args.registry_root),
        "--seed",
        str(args.seed),
        "--n-iter",
        str(args.n_iter),
        "--cv-folds",
        str(args.cv_folds),
        "--n-jobs",
        str(args.n_jobs),
        "--resampling",
        args.resampling,
        "--feature-variant",
        args.feature_variant,
        "--max-trees",
        str(args.max_trees),
        "--min-available-gb",
        str(args.min_available_gb),
        "--memory-interval",
        str(args.memory_interval),
    ]
    if args.memory_log is not None:
        argv.extend(["--memory-log", str(args.memory_log)])
    if args.work_dir is not None:
        argv.extend(["--work-dir", str(args.work_dir)])
    if args.version:
        argv.extend(["--version", args.version])
    if args.no_register:
        argv.append("--no-register")
    if args.actor_id is not None:
        argv.extend(["--actor-id", str(args.actor_id)])
    return train_main(argv)


def cmd_smoke_test(args: argparse.Namespace) -> int:
    """Exercise the full training pipeline on the synthetic test fixture."""

    from ml.train_model import main as train_main

    argv = [
        "--smoke-test",
        "--n-iter",
        str(args.n_iter),
        "--cv-folds",
        str(args.cv_folds),
        "--resampling",
        args.resampling,
    ]
    if args.registry_root is not None:
        argv.extend(["--registry-root", str(args.registry_root)])
    if args.work_dir is not None:
        argv.extend(["--work-dir", str(args.work_dir)])
    if args.fixture is not None:
        argv.extend(["--fixture", str(args.fixture)])
    return train_main(argv)


def cmd_evaluate(args: argparse.Namespace) -> int:
    """Evaluate a staged model on the saved held-out test split."""

    from ml.evaluate import main as evaluate_main

    return evaluate_main(
        [
            "--processed-dir",
            str(args.processed_dir),
            "--artifact-dir",
            str(args.artifact_dir),
            "--output-dir",
            str(args.output_dir),
        ]
    )


def cmd_natural_fpr(args: argparse.Namespace) -> int:
    """Score a natural-distribution BENIGN sample from raw CSVs."""

    from ml.natural_fpr import main as natural_fpr_main

    argv = [
        "--input-dir",
        str(args.input_dir),
        "--artifact-dir",
        str(args.artifact_dir),
        "--max-rows",
        str(args.max_rows),
        "--chunksize",
        str(args.chunksize),
        "--min-available-gb",
        str(args.min_available_gb),
        "--memory-interval",
        str(args.memory_interval),
    ]
    if args.memory_log is not None:
        argv.extend(["--memory-log", str(args.memory_log)])
    if args.output is not None:
        argv.extend(["--output", str(args.output)])
    return natural_fpr_main(argv)


def cmd_registry_record(args: argparse.Namespace) -> int:
    """Record an already-staged artifact in ModelArtifact; never activates it."""

    import json
    from pathlib import Path

    from core.db import get_db_session
    from core.models.mlops import ModelArtifact
    from ml.registry import store
    from ml.registry.service import record_staged_version

    root = Path(args.registry_root)
    version = args.version
    directory = store.version_directory(version, root, area="staging")
    checksums = json.loads(
        (directory / store.CHECKSUMS_FILE).read_text(encoding="utf-8")
    )
    metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))

    with get_db_session() as session:
        existing = session.query(ModelArtifact).filter_by(version=version).one_or_none()
        if existing is not None:
            payload = {
                "version": version,
                "status": existing.status,
                "already_recorded": True,
            }
        else:
            artifact = record_staged_version(
                version,
                checksums,
                metadata,
                session,
                actor_user_id=args.actor_id,
            )
            payload = {
                "version": artifact.version,
                "status": artifact.status,
                "already_recorded": False,
            }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_registry_list(args: argparse.Namespace) -> int:
    """List registered ML model artifacts and their lifecycle states."""

    from core.db import get_db_session
    from ml.registry.service import list_artifacts

    with get_db_session() as session:
        rows = list_artifacts(session)
        payload = [
            {
                "version": row.version,
                "status": row.status,
                "is_active": row.is_active,
                "is_staged": row.is_staged,
                "algorithm": row.algorithm,
                "dataset_hash": row.dataset_hash,
                "created_at": str(row.created_at),
            }
            for row in rows
        ]
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_registry_promote(args: argparse.Namespace) -> int:
    """Promote a staged version; Admin permission is enforced by the service."""

    from core.db import get_db_session
    from ml.registry.service import promote_version

    with get_db_session() as session:
        artifact = promote_version(
            args.version,
            args.actor_id,
            session,
            root=args.registry_root,
        )
    print(
        json.dumps(
            {"version": artifact.version, "status": artifact.status},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_registry_rollback(args: argparse.Namespace) -> int:
    """Restore an archived version to active; Admin permission is enforced."""

    from core.db import get_db_session
    from ml.registry.service import rollback_version

    with get_db_session() as session:
        artifact = rollback_version(
            args.actor_id,
            session,
            target_version=args.version,
            root=args.registry_root,
        )
    print(
        json.dumps(
            {"version": artifact.version, "status": artifact.status},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def main() -> int:
    """Main CLI command dispatcher."""
    parser = argparse.ArgumentParser(
        prog="ai-ids-ips",
        description="AI-Powered Intrusion Detection & Prevention Enterprise System",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Database seeding
    seed_p = subparsers.add_parser(
        "seed-db", help="Seed default administrator and immutable whitelists"
    )
    seed_p.set_defaults(func=cmd_seed_db)

    # Audit chain verification
    audit_p = subparsers.add_parser(
        "verify-audit-chain", help="Cryptographically audit the tamper-evident ledger"
    )
    audit_p.set_defaults(func=cmd_verify_audit_chain)

    # Web API
    api_p = subparsers.add_parser("web-api", help="Run Flask REST API & SOC Dashboard")
    api_p.add_argument("--host", default="0.0.0.0", help="Binding host address")
    api_p.add_argument("--port", type=int, default=5000, help="Binding TCP port")
    api_p.set_defaults(func=cmd_web_api)

    # Sensor
    sensor_p = subparsers.add_parser("sensor", help="Run packet capture agent")
    sensor_p.add_argument(
        "--interface",
        default=settings.SENSOR_INTERFACE,
        help="Network interface to monitor",
    )
    sensor_p.add_argument(
        "--bpf",
        default=settings.SENSOR_BPF_FILTER,
        help="Berkeley Packet Filter string",
    )
    sensor_p.set_defaults(func=cmd_sensor)

    # Detection Engine
    det_p = subparsers.add_parser("detection-engine", help="Run ML detection engine")
    det_p.set_defaults(func=cmd_detection)

    # Prevention Engine
    prev_p = subparsers.add_parser(
        "prevention-engine", help="Run automated prevention policy engine"
    )
    prev_p.set_defaults(func=cmd_prevention)

    # Celery Worker
    worker_p = subparsers.add_parser(
        "worker", help="Run Celery asynchronous background worker"
    )
    worker_p.set_defaults(func=cmd_worker)

    # Traffic Replay Simulator
    replay_p = subparsers.add_parser(
        "replay", help="Run CICIDS2017 traffic replay simulator"
    )
    replay_p.add_argument(
        "--rate", type=float, default=10.0, help="Replay flow speed multiplier"
    )
    replay_p.add_argument(
        "--loop", action="store_true", help="Continuously loop dataset"
    )
    replay_p.set_defaults(func=cmd_replay)

    # Phase 3: ML pipeline
    check_p = subparsers.add_parser(
        "check-dataset", help="Read-only CICIDS2017 CSV readiness check"
    )
    check_p.add_argument(
        "--input-dir",
        default=settings.ML_DATASET_DIR,
        help="Directory with MachineLearningCVE CSV files (default: data/raw)",
    )
    check_p.set_defaults(func=cmd_check_dataset)

    preprocess_p = subparsers.add_parser(
        "preprocess", help="Clean and split CICIDS2017 CSV files"
    )
    preprocess_p.add_argument("--input-dir", default=settings.ML_DATASET_DIR)
    preprocess_p.add_argument("--output-dir", required=True)
    preprocess_p.add_argument("--chunksize", type=int, default=100_000)
    preprocess_p.add_argument("--sample-fraction", type=float, default=None)
    preprocess_p.add_argument("--max-rows-per-class", type=int, default=None)
    preprocess_p.add_argument(
        "--rare-strategy", choices=("keep", "merge", "drop"), default="keep"
    )
    preprocess_p.add_argument(
        "--scaler", choices=("standard", "robust"), default="standard"
    )
    preprocess_p.add_argument("--seed", type=int, default=settings.ML_RANDOM_SEED)
    preprocess_p.add_argument(
        "--stream-sample",
        action="store_true",
        help="sample/cap each CSV chunk immediately to bound peak RAM",
    )
    preprocess_p.add_argument("--min-available-gb", type=float, default=0.5)
    preprocess_p.add_argument("--memory-interval", type=float, default=15.0)
    preprocess_p.add_argument("--memory-log", default=None)
    preprocess_p.set_defaults(func=cmd_preprocess)

    train_p = subparsers.add_parser(
        "train", help="Train and stage a model (never activates it)"
    )
    train_p.add_argument("--processed-dir", required=True)
    train_p.add_argument("--registry-root", default=settings.ML_MODEL_REGISTRY_PATH)
    train_p.add_argument("--work-dir", default=None)
    train_p.add_argument("--version", default=None)
    train_p.add_argument("--seed", type=int, default=settings.ML_RANDOM_SEED)
    train_p.add_argument("--n-iter", type=int, default=8)
    train_p.add_argument("--cv-folds", type=int, default=3)
    train_p.add_argument("--n-jobs", type=int, default=2)
    train_p.add_argument("--max-trees", type=int, default=200)
    train_p.add_argument("--min-available-gb", type=float, default=0.5)
    train_p.add_argument("--memory-interval", type=float, default=15.0)
    train_p.add_argument("--memory-log", default=None)
    train_p.add_argument(
        "--resampling", choices=("none", "smote", "undersample"), default="none"
    )
    train_p.add_argument(
        "--feature-variant",
        choices=sorted(FEATURE_VARIANTS),
        default="full",
        help="feature contract to train; both variants share the processed rows",
    )
    train_p.add_argument("--no-register", action="store_true")
    train_p.add_argument("--actor-id", type=int, default=None)
    train_p.set_defaults(func=cmd_train)

    smoke_p = subparsers.add_parser(
        "smoke-test", help="End-to-end training on synthetic test fixtures only"
    )
    smoke_p.add_argument("--registry-root", default=None)
    smoke_p.add_argument("--work-dir", default=None)
    smoke_p.add_argument("--fixture", default=None)
    smoke_p.add_argument("--n-iter", type=int, default=2)
    smoke_p.add_argument("--cv-folds", type=int, default=2)
    smoke_p.add_argument(
        "--resampling", choices=("none", "smote", "undersample"), default="none"
    )
    smoke_p.set_defaults(func=cmd_smoke_test)

    evaluate_p = subparsers.add_parser(
        "evaluate", help="Evaluate a staged model on the held-out test split"
    )
    evaluate_p.add_argument("--processed-dir", required=True)
    evaluate_p.add_argument("--artifact-dir", required=True)
    evaluate_p.add_argument("--output-dir", required=True)
    evaluate_p.set_defaults(func=cmd_evaluate)

    natural_p = subparsers.add_parser(
        "natural-fpr",
        help="Measure FPR on a natural-distribution BENIGN sample from raw CSVs",
    )
    natural_p.add_argument("--input-dir", default=settings.ML_DATASET_DIR)
    natural_p.add_argument("--artifact-dir", required=True)
    natural_p.add_argument("--output", default=None)
    natural_p.add_argument("--max-rows", type=int, default=20_000)
    natural_p.add_argument("--chunksize", type=int, default=50_000)
    natural_p.add_argument("--min-available-gb", type=float, default=0.5)
    natural_p.add_argument("--memory-interval", type=float, default=15.0)
    natural_p.add_argument("--memory-log", default=None)
    natural_p.set_defaults(func=cmd_natural_fpr)

    record_p = subparsers.add_parser(
        "registry-record", help="Record an already-staged version (never activates)"
    )
    record_p.add_argument("--version", required=True)
    record_p.add_argument("--registry-root", default=settings.ML_MODEL_REGISTRY_PATH)
    record_p.add_argument("--actor-id", type=int, default=None)
    record_p.set_defaults(func=cmd_registry_record)

    list_p = subparsers.add_parser(
        "registry-list", help="List registered model versions and statuses"
    )
    list_p.set_defaults(func=cmd_registry_list)

    promote_p = subparsers.add_parser(
        "registry-promote", help="Admin-only: promote a staged version to active"
    )
    promote_p.add_argument("--version", required=True)
    promote_p.add_argument("--actor-id", type=int, required=True)
    promote_p.add_argument("--registry-root", default=settings.ML_MODEL_REGISTRY_PATH)
    promote_p.set_defaults(func=cmd_registry_promote)

    rollback_p = subparsers.add_parser(
        "registry-rollback", help="Admin-only: restore an archived version to active"
    )
    rollback_p.add_argument("--version", default=None)
    rollback_p.add_argument("--actor-id", type=int, required=True)
    rollback_p.add_argument("--registry-root", default=settings.ML_MODEL_REGISTRY_PATH)
    rollback_p.set_defaults(func=cmd_registry_rollback)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
