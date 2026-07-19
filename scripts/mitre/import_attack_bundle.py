#!/usr/bin/env python3
"""Import a vendored MITRE ATT&CK STIX bundle into the five reference
tables (`mitre_tactics`, `mitre_techniques`, `mitre_software`,
`mitre_groups`, `mitre_mitigations`) — the **only** supported way new
ATT&CK data enters this application, per
`docs/adr/0013-finding-mitre-intelligence-engine-shape.md` point 4.

Never fetches anything over the network — `--bundle` must already be a
local file (see `data/mitre/README.md`). Idempotent: re-running with the
same `--bundle`/`--version` skips rows that already exist for that
`(business_id, attack_spec_version)` pair rather than erroring or
duplicating them.

Usage:
    python -m scripts.mitre.import_attack_bundle \\
        --bundle data/mitre/raw/attack-enterprise-15.1.json \\
        --version 15.1
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from core.config import get_settings
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
from core.db.session import Database
from core.knowledge.mitre.loader import load_bundle_from_path
from core.knowledge.mitre.models import MitreDataset


async def import_dataset(database: Database, dataset: MitreDataset) -> dict[str, int]:
    """Seeds every reference table from `dataset`, skipping rows whose
    `(business_id, attack_spec_version)` pair is already present. Returns a
    per-table count of rows actually inserted, for the CLI summary."""
    counts = {"tactics": 0, "techniques": 0, "software": 0, "groups": 0, "mitigations": 0}

    async with database.session_factory() as session:
        tactic_repo = MitreTacticRepository(session)
        for tactic in dataset.tactics:
            if await tactic_repo.find_by_tactic_id(tactic.tactic_id, tactic.attack_spec_version):
                continue
            await tactic_repo.add(
                MitreTactic(
                    tactic_id=tactic.tactic_id,
                    name=tactic.name,
                    shortname=tactic.shortname,
                    description=tactic.description,
                    attack_spec_version=tactic.attack_spec_version,
                )
            )
            counts["tactics"] += 1

        technique_repo = MitreTechniqueRepository(session)
        for technique in dataset.techniques:
            if await technique_repo.find_by_technique_id(
                technique.technique_id, technique.attack_spec_version
            ):
                continue
            await technique_repo.add(
                MitreTechnique(
                    technique_id=technique.technique_id,
                    name=technique.name,
                    description=technique.description,
                    tactic_shortnames_json=_to_json(technique.tactic_shortnames),
                    platforms_json=_to_json(technique.platforms),
                    attack_spec_version=technique.attack_spec_version,
                )
            )
            counts["techniques"] += 1

        software_repo = MitreSoftwareRepository(session)
        for software in dataset.software:
            if await software_repo.find_by_software_id(
                software.software_id, software.attack_spec_version
            ):
                continue
            await software_repo.add(
                MitreSoftware(
                    software_id=software.software_id,
                    name=software.name,
                    description=software.description,
                    is_malware=software.is_malware,
                    attack_spec_version=software.attack_spec_version,
                )
            )
            counts["software"] += 1

        group_repo = MitreGroupRepository(session)
        for group in dataset.groups:
            if await group_repo.find_by_group_id(group.group_id, group.attack_spec_version):
                continue
            await group_repo.add(
                MitreGroup(
                    group_id=group.group_id,
                    name=group.name,
                    description=group.description,
                    attack_spec_version=group.attack_spec_version,
                )
            )
            counts["groups"] += 1

        mitigation_repo = MitreMitigationRepository(session)
        for mitigation in dataset.mitigations:
            if await mitigation_repo.find_by_mitigation_id(
                mitigation.mitigation_id, mitigation.attack_spec_version
            ):
                continue
            await mitigation_repo.add(
                MitreMitigation(
                    mitigation_id=mitigation.mitigation_id,
                    name=mitigation.name,
                    description=mitigation.description,
                    attack_spec_version=mitigation.attack_spec_version,
                )
            )
            counts["mitigations"] += 1

        await session.commit()

    return counts


def _to_json(values: tuple[str, ...]) -> str:
    return json.dumps(list(values))


async def _main(bundle_path: Path, version: str | None) -> int:
    settings = get_settings()
    dataset = load_bundle_from_path(bundle_path, attack_spec_version=version)
    database = Database(settings)
    try:
        counts = await import_dataset(database, dataset)
    finally:
        await database.dispose()

    print(
        f"Imported ATT&CK bundle {bundle_path} (attack_spec_version="
        f"{dataset.attack_spec_version!r}) against {settings.database_url}:"
    )
    for table, count in counts.items():
        print(f"  {table}: {count} new row(s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bundle",
        type=Path,
        required=True,
        help="Path to a local, vendored STIX 2.1 bundle (never a URL).",
    )
    parser.add_argument(
        "--version",
        type=str,
        default=None,
        help=(
            "attack_spec_version override. If omitted, the bundle's own "
            "'x_mitre_attack_spec_version' field is used."
        ),
    )
    args = parser.parse_args(argv)
    return asyncio.run(_main(args.bundle, args.version))


if __name__ == "__main__":
    sys.exit(main())
