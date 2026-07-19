"""Unit tests for scripts/mitre/import_attack_bundle.py — real SQLite,
mirroring tests/unit/test_db_mitre_repository.py's pattern."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from scripts.mitre.import_attack_bundle import import_dataset

from core.config import Settings
from core.db import Base, Database
from core.db.mitre_repository import MitreTechniqueRepository
from core.knowledge.mitre.models import (
    MitreDataset,
    MitreGroup,
    MitreMitigation,
    MitreSoftware,
    MitreTactic,
    MitreTechnique,
)

VERSION = "1.0-test"


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


def _dataset() -> MitreDataset:
    return MitreDataset(
        attack_spec_version=VERSION,
        tactics=(
            MitreTactic(
                tactic_id="TA0006",
                name="Credential Access",
                shortname="credential-access",
                description="...",
                attack_spec_version=VERSION,
            ),
        ),
        techniques=(
            MitreTechnique(
                technique_id="T1110",
                name="Brute Force",
                description="...",
                tactic_shortnames=("credential-access",),
                attack_spec_version=VERSION,
            ),
        ),
        software=(
            MitreSoftware(
                software_id="S0002",
                name="Mimikatz",
                description="...",
                is_malware=False,
                attack_spec_version=VERSION,
            ),
        ),
        groups=(
            MitreGroup(
                group_id="G0007", name="APT28", description="...", attack_spec_version=VERSION
            ),
        ),
        mitigations=(
            MitreMitigation(
                mitigation_id="M1032", name="MFA", description="...", attack_spec_version=VERSION
            ),
        ),
    )


@pytest.mark.unit
async def test_import_dataset_inserts_every_object_type(database: Database) -> None:
    counts = await import_dataset(database, _dataset())
    assert counts == {"tactics": 1, "techniques": 1, "software": 1, "groups": 1, "mitigations": 1}


@pytest.mark.unit
async def test_import_dataset_is_idempotent(database: Database) -> None:
    await import_dataset(database, _dataset())
    second_counts = await import_dataset(database, _dataset())
    assert second_counts == {
        "tactics": 0,
        "techniques": 0,
        "software": 0,
        "groups": 0,
        "mitigations": 0,
    }


@pytest.mark.unit
async def test_import_dataset_persists_queryable_technique(database: Database) -> None:
    await import_dataset(database, _dataset())
    async with database.session_factory() as session:
        repo = MitreTechniqueRepository(session)
        found = await repo.find_by_technique_id("T1110", VERSION)
        assert found is not None
        assert found.name == "Brute Force"
