.PHONY: help install dev-install run-web run-api test test-unit test-integration lint format typecheck migrate seed docker-up docker-down clean

help:
	@echo "Common targets: install, dev-install, run-web, run-api, test, lint, format, typecheck, migrate, seed, docker-up, docker-down, clean"

install:
	pip install -r requirements.txt

dev-install:
	pip install -r requirements-dev.txt
	pre-commit install

run-web:
	streamlit run apps/web/Home.py

run-api:
	uvicorn apps.api.main:app --reload --port 8000

test:
	pytest tests/unit tests/integration

test-unit:
	pytest tests/unit -m unit

test-integration:
	pytest tests/integration -m integration

lint:
	ruff check .

format:
	ruff format .

typecheck:
	mypy core

migrate:
	bash scripts/run_migrations.sh

seed:
	python scripts/seed_sample_data.py

docker-up:
	docker compose up -d

docker-down:
	docker compose down

clean:
	find . -type d -name "__pycache__" -not -path "./.venv/*" -exec rm -rf {} +
	rm -rf .pytest_cache .mypy_cache .ruff_cache
