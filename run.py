#!/usr/bin/env python3
"""AI-IDS/IPS Enterprise Platform Central Management CLI.

Provides unified administrative entrypoints for service execution, database migrations,
audit ledger verification, and initial deployment bootstrapping.
"""

from __future__ import annotations

import argparse
import sys

from core.config import settings
from core.logging import get_logger, setup_logging

logger = get_logger("run")


def cmd_seed_db(args: argparse.Namespace) -> int:
    """Initialize default administrator account and immutable whitelist entries."""
    setup_logging(level="INFO", json_format=False)
    logger.info("Initializing database seeding...")
    
    from argon2 import PasswordHasher

    from core.db import Base, engine, get_db_session
    from core.models import GENESIS_HASH, AuditLog, User, UserRole, Whitelist
    
    # Ensure all tables exist in database schema
    Base.metadata.create_all(engine)
    
    ph = PasswordHasher()
    
    with get_db_session() as session:
        # 1. Check or create default admin
        admin_user = session.query(User).filter_by(username=settings.INITIAL_ADMIN_USERNAME).first()
        if not admin_user:
            logger.info(f"Creating default administrator: '{settings.INITIAL_ADMIN_USERNAME}'")
            hashed_pwd = ph.hash(settings.INITIAL_ADMIN_PASSWORD)
            admin_user = User(
                username=settings.INITIAL_ADMIN_USERNAME,
                email=settings.INITIAL_ADMIN_EMAIL,
                password_hash=hashed_pwd,
                role=UserRole.ADMIN,
                is_active=True,
                must_change_password=True,
            )
            session.add(admin_user)
            session.flush()

            # Record in audit log
            audit_entry = AuditLog.create_entry(
                hmac_key=settings.AUDIT_HMAC_SECRET,
                prev_hash=GENESIS_HASH,
                user_id=admin_user.id,
                username="system",
                action="INITIAL_ADMIN_SEED",
                resource_type="USER",
                resource_id=str(admin_user.id),
                status="SUCCESS",
                details='{"action": "seed_admin_account"}',
            )
            session.add(audit_entry)
            logger.info("Admin account created successfully. Default password must be changed upon first login.")
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
                logger.info(f"Seeding whitelist rule: {cidr} ({desc})")
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
    from core.models import GENESIS_HASH, AuditLog

    with get_db_session() as session:
        logs = session.query(AuditLog).order_by(AuditLog.id.asc()).all()
        if not logs:
            logger.info("Audit log ledger is empty. Chain is pristine.")
            return 0

        expected_prev_hash = GENESIS_HASH
        corrupted_count = 0

        for idx, entry in enumerate(logs):
            # Check previous hash pointer
            if entry.previous_hash != expected_prev_hash:
                logger.error(
                    f"TAMPER DETECTED at Log ID {entry.id}! Previous hash mismatch: "
                    f"Expected '{expected_prev_hash}', Found '{entry.previous_hash}'"
                )
                corrupted_count += 1
                break

            # Recompute entry hash
            recomputed = AuditLog.compute_hash(
                hmac_key=settings.AUDIT_HMAC_SECRET,
                prev_hash=entry.previous_hash,
                timestamp=entry.timestamp,
                user_id=entry.user_id,
                action=entry.action,
                resource_type=entry.resource_type,
                resource_id=entry.resource_id,
                status=entry.status,
                details_json=entry.details,
            )

            if recomputed != entry.entry_hash:
                logger.error(
                    f"TAMPER DETECTED at Log ID {entry.id}! Recomputed hash '{recomputed}' "
                    f"does not match entry hash '{entry.entry_hash}'"
                )
                corrupted_count += 1
                break

            expected_prev_hash = entry.entry_hash

        if corrupted_count == 0:
            logger.info(f"AUDIT INTEGRITY VERIFIED: All {len(logs)} entries in the chain are cryptographically valid.")
            return 0
        else:
            logger.critical(f"AUDIT CHAIN INTEGRITY BREACHED: Detected {corrupted_count} compromised records!")
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


def main() -> int:
    """Main CLI command dispatcher."""
    parser = argparse.ArgumentParser(
        prog="ai-ids-ips",
        description="AI-Powered Intrusion Detection & Prevention Enterprise System",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Database seeding
    seed_p = subparsers.add_parser("seed-db", help="Seed default administrator and immutable whitelists")
    seed_p.set_defaults(func=cmd_seed_db)

    # Audit chain verification
    audit_p = subparsers.add_parser("verify-audit-chain", help="Cryptographically audit the tamper-evident ledger")
    audit_p.set_defaults(func=cmd_verify_audit_chain)

    # Web API
    api_p = subparsers.add_parser("web-api", help="Run Flask REST API & SOC Dashboard")
    api_p.add_argument("--host", default="0.0.0.0", help="Binding host address")
    api_p.add_argument("--port", type=int, default=5000, help="Binding TCP port")
    api_p.set_defaults(func=cmd_web_api)

    # Sensor
    sensor_p = subparsers.add_parser("sensor", help="Run packet capture agent")
    sensor_p.add_argument("--interface", default=settings.SENSOR_INTERFACE, help="Network interface to monitor")
    sensor_p.add_argument("--bpf", default=settings.SENSOR_BPF_FILTER, help="Berkeley Packet Filter string")
    sensor_p.set_defaults(func=cmd_sensor)

    # Detection Engine
    det_p = subparsers.add_parser("detection-engine", help="Run ML detection engine")
    det_p.set_defaults(func=cmd_detection)

    # Prevention Engine
    prev_p = subparsers.add_parser("prevention-engine", help="Run automated prevention policy engine")
    prev_p.set_defaults(func=cmd_prevention)

    # Celery Worker
    worker_p = subparsers.add_parser("worker", help="Run Celery asynchronous background worker")
    worker_p.set_defaults(func=cmd_worker)

    # Traffic Replay Simulator
    replay_p = subparsers.add_parser("replay", help="Run CICIDS2017 traffic replay simulator")
    replay_p.add_argument("--rate", type=float, default=10.0, help="Replay flow speed multiplier")
    replay_p.add_argument("--loop", action="store_true", help="Continuously loop dataset")
    replay_p.set_defaults(func=cmd_replay)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
