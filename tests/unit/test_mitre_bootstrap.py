"""Unit tests for core/knowledge/mitre/bootstrap.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.knowledge.mitre.bootstrap import load_mitre_dataset
from core.knowledge.mitre.exceptions import UnsupportedAttackVersionError


def _bundle(version: str) -> dict:
    return {
        "type": "bundle",
        "spec_version": "2.1",
        "x_mitre_attack_spec_version": version,
        "objects": [],
    }


@pytest.mark.unit
def test_load_mitre_dataset_succeeds_when_versions_match(test_settings, tmp_path: Path) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(_bundle("2.5")), encoding="utf-8")
    test_settings.mitre_attack_data_path = bundle_path
    test_settings.mitre_attack_version = "2.5"
    dataset = load_mitre_dataset(test_settings)
    assert dataset.attack_spec_version == "2.5"


@pytest.mark.unit
def test_load_mitre_dataset_rejects_version_mismatch(test_settings, tmp_path: Path) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(_bundle("2.5")), encoding="utf-8")
    test_settings.mitre_attack_data_path = bundle_path
    test_settings.mitre_attack_version = "3.0"
    with pytest.raises(UnsupportedAttackVersionError):
        load_mitre_dataset(test_settings)
