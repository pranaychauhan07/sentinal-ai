"""Unit tests for core/db/models/mitre_*.py + core/db/mitre_repository.py —
real SQLite, mirroring tests/unit/test_db_ioc_repository.py's pattern."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from core.config import Settings
from core.db import Base, Database
from core.db.mitre_repository import (
    MitreGroupRepository,
    MitreMitigationRepository,
    MitreSoftwareRepository,
    MitreTacticRepository,
    MitreTechniqueRepository,
)
from core.db.models.mitre_group import MitreGroup
from core.db.models.mitre_mitigation import MitreMitigation
from core.db.models.mitre_software import MitreSoftware
from core.db.models.mitre_tactic import MitreTactic
from core.db.models.mitre_technique import MitreTechnique

VERSION = "15.1"


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


@pytest.mark.unit
async def test_technique_repository_find_by_technique_id(database: Database) -> None:
    async with database.session_factory() as session:
        repo = MitreTechniqueRepository(session)
        await repo.add(
            MitreTechnique(
                technique_id="T1110",
                name="Brute Force",
                description="...",
                tactic_shortnames_json="[]",
                platforms_json="[]",
                attack_spec_version=VERSION,
            )
        )
        await session.commit()

        found = await repo.find_by_technique_id("T1110", VERSION)
        assert found is not None
        assert found.name == "Brute Force"

        assert await repo.find_by_technique_id("T1110", "99.0") is None


@pytest.mark.unit
async def test_technique_repository_find_by_version(database: Database) -> None:
    async with database.session_factory() as session:
        repo = MitreTechniqueRepository(session)
        await repo.add(
            MitreTechnique(
                technique_id="T1110",
                name="Brute Force",
                description="...",
                tactic_shortnames_json="[]",
                platforms_json="[]",
                attack_spec_version=VERSION,
            )
        )
        await repo.add(
            MitreTechnique(
                technique_id="T1059",
                name="Command and Scripting Interpreter",
                description="...",
                tactic_shortnames_json="[]",
                platforms_json="[]",
                attack_spec_version="99.0",
            )
        )
        await session.commit()

        results = await repo.find_by_version(VERSION)
        assert [t.technique_id for t in results] == ["T1110"]


@pytest.mark.unit
async def test_tactic_repository_find_by_tactic_id(database: Database) -> None:
    async with database.session_factory() as session:
        repo = MitreTacticRepository(session)
        await repo.add(
            MitreTactic(
                tactic_id="TA0006",
                name="Credential Access",
                shortname="credential-access",
                description="...",
                attack_spec_version=VERSION,
            )
        )
        await session.commit()
        found = await repo.find_by_tactic_id("TA0006", VERSION)
        assert found is not None
        assert found.shortname == "credential-access"


@pytest.mark.unit
async def test_software_repository_find_by_software_id(database: Database) -> None:
    async with database.session_factory() as session:
        repo = MitreSoftwareRepository(session)
        await repo.add(
            MitreSoftware(
                software_id="S0002",
                name="Mimikatz",
                description="...",
                is_malware=False,
                attack_spec_version=VERSION,
            )
        )
        await session.commit()
        found = await repo.find_by_software_id("S0002", VERSION)
        assert found is not None
        assert found.name == "Mimikatz"


@pytest.mark.unit
async def test_group_repository_find_by_group_id(database: Database) -> None:
    async with database.session_factory() as session:
        repo = MitreGroupRepository(session)
        await repo.add(
            MitreGroup(
                group_id="G0007", name="APT28", description="...", attack_spec_version=VERSION
            )
        )
        await session.commit()
        found = await repo.find_by_group_id("G0007", VERSION)
        assert found is not None
        assert found.name == "APT28"


@pytest.mark.unit
async def test_mitigation_repository_find_by_mitigation_id(database: Database) -> None:
    async with database.session_factory() as session:
        repo = MitreMitigationRepository(session)
        await repo.add(
            MitreMitigation(
                mitigation_id="M1032", name="MFA", description="...", attack_spec_version=VERSION
            )
        )
        await session.commit()
        found = await repo.find_by_mitigation_id("M1032", VERSION)
        assert found is not None
        assert found.name == "MFA"


@pytest.mark.unit
async def test_unique_constraint_prevents_duplicate_technique_version_pair(
    database: Database,
) -> None:
    async with database.session_factory() as session:
        repo = MitreTechniqueRepository(session)
        await repo.add(
            MitreTechnique(
                technique_id="T1110",
                name="Brute Force",
                description="...",
                tactic_shortnames_json="[]",
                platforms_json="[]",
                attack_spec_version=VERSION,
            )
        )
        await session.commit()

    async with database.session_factory() as session:
        repo = MitreTechniqueRepository(session)
        with pytest.raises(Exception):  # noqa: B017 - IntegrityError, backend-dependent
            await repo.add(
                MitreTechnique(
                    technique_id="T1110",
                    name="Brute Force (dup)",
                    description="...",
                    tactic_shortnames_json="[]",
                    platforms_json="[]",
                    attack_spec_version=VERSION,
                )
            )
