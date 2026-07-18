#!/usr/bin/env bash
# Thin wrapper around Alembic so `make migrate` is the one documented way to
# apply schema changes (docs/deployment-guide.md — never run alembic by hand
# against a shared database).
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f "core/db/migrations/alembic.ini" ] && [ ! -f "alembic.ini" ]; then
  echo "No alembic.ini found yet. This script becomes runnable once the" >&2
  echo "initial migration is added in Milestone M0/M1 (docs/roadmap.md)." >&2
  exit 1
fi

alembic upgrade head
