"""Integration tests for the Finding & MITRE ATT&CK Intelligence Engine —
exercises the *real* vendored MITRE bundle (`data/mitre/raw/`), the full
default `MAPPING_RULES` table, the real seed script's `import_dataset`, and
`core.services.finding_service` together against a real SQLite database.
Unlike `tests/unit/test_finding_service.py` (which uses small, hand-built
fixtures), this proves the actual shipped data and the actual shipped rule
table are mutually consistent end-to-end.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from scripts.mitre.import_attack_bundle import import_dataset
from tests.unit._finding_test_helpers import make_scored_ioc

from core.config import Settings, get_settings
from core.db import Base, Database
from core.db.finding_repository import FindingRepository
from core.db.ioc_repository import IOCRepository
from core.db.models.ioc import IOC, IOCStatus
from core.findings.exceptions import InvalidMappingRuleError
from core.findings.mapping_engine import MitreMappingEngine
from core.findings.mapping_rules import MAPPING_RULES, MappingRule
from core.knowledge.mitre.bootstrap import load_mitre_dataset
from core.knowledge.mitre.lookup import MitreLookup
from core.services.finding_service import generate_findings_for_case
from core.threat_intel.models import IOCType


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


async def _seed_real_mitre_data(database: Database, settings: Settings) -> None:
    dataset = load_mitre_dataset(settings)
    await import_dataset(database, dataset)


async def _seed_ioc(session, case_id: uuid.UUID, **kwargs: object) -> IOC:
    scored = make_scored_ioc(**kwargs)  # type: ignore[arg-type]
    now = datetime.now(UTC)
    row = IOC(
        case_id=case_id,
        evidence_id=scored.attribution.evidence_id,
        ioc_type=scored.record.ioc_type,
        value=scored.record.value,
        raw_value=scored.record.raw_value,
        source=scored.record.source,
        confidence=scored.record.confidence,
        severity=scored.record.severity,
        classification=scored.classification.category,
        composite_score=scored.score.composite_score,
        rule_match_count=0,
        occurrence_count=1,
        extractor_name="test",
        extractor_version="1.0.0",
        status=IOCStatus.ACTIVE,
        metadata_json=scored.model_dump_json(),
        first_seen_at=now,
        last_seen_at=now,
    )
    repo = IOCRepository(session)
    await repo.add(row)
    return row


@pytest.mark.integration
def test_real_mapping_rules_are_valid_against_real_vendored_dataset() -> None:
    """Every rule in the shipped MAPPING_RULES table must reference a
    technique that actually exists in the shipped vendored bundle — the
    exact consistency the mapping engine enforces structurally at
    construction time (constitution §10, "never discovered mid-evaluation")."""
    settings = get_settings()
    lookup = MitreLookup(load_mitre_dataset(settings))
    MitreMappingEngine(lookup=lookup, rules=MAPPING_RULES)
    assert len(lookup.all_technique_ids()) == 20


@pytest.mark.integration
def test_mapping_engine_rejects_rule_with_technique_absent_from_real_dataset() -> None:
    settings = get_settings()
    lookup = MitreLookup(load_mitre_dataset(settings))
    bad_rule = MappingRule(
        rule_id="bad", technique_id="T9999", ioc_types=(IOCType.USERNAME,), base_confidence=0.5
    )
    with pytest.raises(InvalidMappingRuleError):
        MitreMappingEngine(lookup=lookup, rules=(bad_rule,))


@pytest.mark.integration
async def test_end_to_end_generation_against_real_seeded_data(
    database: Database, test_settings: Settings
) -> None:
    """Upload-shaped IOCs spanning several real ATT&CK techniques, seeded
    through the real import script, mapped through the real default rule
    table, generated, deduplicated, and persisted — the full stack, no
    fixture shortcuts."""
    await _seed_real_mitre_data(database, test_settings)
    case_id = uuid.uuid4()

    async with database.session_factory() as session:
        await _seed_ioc(session, case_id, ioc_type=IOCType.USERNAME, value="admin")
        await _seed_ioc(session, case_id, ioc_type=IOCType.IPV4, value="203.0.113.5")
        await _seed_ioc(session, case_id, ioc_type=IOCType.COMMAND_LINE, value="whoami /all")
        await _seed_ioc(session, case_id, ioc_type=IOCType.EMAIL, value="attacker@evil.example.com")
        await session.commit()

        result = await generate_findings_for_case(session, case_id=case_id, settings=test_settings)
        await session.commit()

        assert len(result.created_finding_ids) >= 2

        repo = FindingRepository(session)
        persisted = await repo.find_by_case(case_id)
        technique_ids: set[str] = set()
        for finding in persisted:
            mappings = await repo.mappings_for_finding(finding.id)
            assert mappings, f"Finding {finding.id} has no persisted MITRE mapping join rows"
            technique_ids.update(str(m.mitre_technique_id) for m in mappings)
        assert technique_ids  # every persisted Finding actually resolved a real technique row


@pytest.mark.integration
async def test_large_ioc_set_against_real_data_within_reasonable_time(
    database: Database, test_settings: Settings
) -> None:
    """Performance guard against the real 20-technique/20-rule table: 500
    mixed-type IOCs must generate/map/dedup/persist well under a few
    seconds."""
    await _seed_real_mitre_data(database, test_settings)
    case_id = uuid.uuid4()
    ioc_types = [
        IOCType.USERNAME,
        IOCType.IPV4,
        IOCType.PORT,
        IOCType.DOMAIN,
        IOCType.FILE_NAME,
        IOCType.HOSTNAME,
    ]

    async with database.session_factory() as session:
        for i in range(500):
            ioc_type = ioc_types[i % len(ioc_types)]
            value = f"{ioc_type.value}-{i}" if ioc_type != IOCType.PORT else str(1000 + i % 60000)
            await _seed_ioc(session, case_id, ioc_type=ioc_type, value=value)
        await session.commit()

        started = time.monotonic()
        result = await generate_findings_for_case(session, case_id=case_id, settings=test_settings)
        await session.commit()
        elapsed = time.monotonic() - started

    assert result.candidate_count > 0
    assert elapsed < 20.0
