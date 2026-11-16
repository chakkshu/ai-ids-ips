# AI-IDS/IPS Enterprise Makefile
.PHONY: help install install-dev lint format test test-cov security-audit docker-up docker-down run-api run-sensor run-detection run-prevention run-worker run-simulator migrate seed clean

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
