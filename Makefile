# AI-IDS/IPS Enterprise Makefile
.PHONY: help install install-dev lint format test test-cov security-audit docker-up docker-down run-api run-sensor run-detection run-prevention run-worker run-simulator migrate seed clean check-dataset preprocess train smoke-test evaluate registry-list registry-promote registry-rollback

PYTHON ?= python
PIP ?= pip
DOCKER_COMPOSE ?= docker-compose

help:
	@echo "AI-IDS/IPS Development & Operational Commands:"
	@echo "  make install         Install production dependencies"
	@echo "  make install-dev     Install development and testing dependencies"
	@echo "  make lint            Run ruff and mypy linters"
	@echo "  make format          Format code with black and ruff"
	@echo "  make test            Execute test suite via pytest"
	@echo "  make test-cov        Execute tests with HTML coverage report"
	@echo "  make security-audit  Execute Bandit SAST and pip-audit"
	@echo "  make docker-up       Start PostgreSQL and Redis via docker-compose"
	@echo "  make docker-down     Stop docker-compose services"
	@echo "  make run-api         Start Web API & SOC Dashboard"
	@echo "  make run-sensor      Run Packet Capture Sensor (requires Admin on Windows)"
	@echo "  make run-detection   Run Detection Engine"
	@echo "  make run-prevention  Run Prevention Engine"
	@echo "  make run-worker      Run Celery Worker"
	@echo "  make run-simulator   Run CICIDS2017 Traffic Replay Simulator"
	@echo "  make migrate         Apply database migrations via Alembic"
	@echo "  make seed            Seed initial administrator and default policies"
	@echo "  make clean           Clean cache and temporary test files"
	@echo "  make check-dataset   Read-only CICIDS2017 readiness check"
	@echo "  make preprocess      Clean and split CSVs (use ARGS='--output-dir ...')"
	@echo "  make train           Train and stage a model from a processed bundle"
	@echo "  make smoke-test      End-to-end training on synthetic test fixtures only"
	@echo "  make evaluate        Evaluate a staged model on the held-out test split"
	@echo "  make registry-list   List model artifact versions and statuses"
	@echo "  make registry-promote   Admin-only promotion (ARGS='--version ... --actor-id 1')"
	@echo "  make registry-rollback  Admin-only rollback (ARGS='--actor-id 1')"

install:
	$(PIP) install -r requirements.txt

install-dev:
	$(PIP) install -r requirements-dev.txt

lint:
	ruff check .
	mypy core ml services prevention capture utils

format:
	black .
	ruff check --fix .

test:
	pytest tests/

test-cov:
	pytest --cov=core --cov=ml --cov=services --cov=prevention --cov=capture --cov=utils --cov-report=html tests/

security-audit:
	bandit -r core ml services prevention capture utils -ll
	pip-audit

docker-up:
	$(DOCKER_COMPOSE) up -d db redis

docker-down:
	$(DOCKER_COMPOSE) down

run-api:
	$(PYTHON) run.py web-api

run-sensor:
	$(PYTHON) run.py sensor

run-detection:
	$(PYTHON) run.py detection-engine

run-prevention:
	$(PYTHON) run.py prevention-engine

run-worker:
	$(PYTHON) run.py worker

run-simulator:
	$(PYTHON) run.py replay

migrate:
	alembic upgrade head

seed:
	$(PYTHON) run.py seed-db

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache htmlcov .coverage

check-dataset:
	$(PYTHON) run.py check-dataset $(ARGS)

preprocess:
	$(PYTHON) run.py preprocess $(ARGS)

train:
	$(PYTHON) run.py train $(ARGS)

smoke-test:
	$(PYTHON) run.py smoke-test $(ARGS)

evaluate:
	$(PYTHON) run.py evaluate $(ARGS)

registry-list:
	$(PYTHON) run.py registry-list $(ARGS)

registry-promote:
	$(PYTHON) run.py registry-promote $(ARGS)

registry-rollback:
	$(PYTHON) run.py registry-rollback $(ARGS)
