"""Explicit, injectable MITRE dataset loading — the one place
`Settings.mitre_attack_data_path`/`mitre_attack_version` are turned into a
loaded `MitreDataset`. Deliberately not a module-level cached singleton
(constitution §2, "avoid global state"): callers (today, only
`core/services/finding_service.py` and `scripts/mitre/import_attack_bundle.py`)
construct one `MitreDataset` explicitly and pass it to
`core.knowledge.mitre.source.MitreAttackSource`/
`core.knowledge.mitre.lookup.MitreLookup` themselves.
"""

from __future__ import annotations

from pathlib import Path

from core.config import Settings
from core.knowledge.mitre.exceptions import UnsupportedAttackVersionError
from core.knowledge.mitre.loader import load_bundle_from_path
from core.knowledge.mitre.models import MitreDataset


def load_mitre_dataset(settings: Settings) -> MitreDataset:
    """Load the vendored MITRE ATT&CK bundle configured by
    `Settings.mitre_attack_data_path`, asserting it matches
    `Settings.mitre_attack_version` (a mismatch is a configuration error,
    not a silently-tolerated drift)."""
    path = Path(settings.mitre_attack_data_path)
    dataset = load_bundle_from_path(path)
    if dataset.attack_spec_version != settings.mitre_attack_version:
        raise UnsupportedAttackVersionError(
            f"Configured MITRE_ATTACK_VERSION={settings.mitre_attack_version!r} does not "
            f"match the vendored bundle's version {dataset.attack_spec_version!r} at {path}.",
            details={
                "configured_version": settings.mitre_attack_version,
                "bundle_version": dataset.attack_spec_version,
                "path": str(path),
            },
        )
    return dataset


__all__ = ["MitreDataset", "load_mitre_dataset"]
