"""Unit tests for core/findings/mapping_rules.py — the tightened,
tag-gated/co-occurrence-gated rules a real investigation report found
firing as false positives. See `core/findings/mapping_engine.py`'s
`map_candidates` for how `match_tags`/`require_co_occurrence` are enforced;
these tests pin the rule *data* itself.
"""

from __future__ import annotations

import pytest

from core.findings.mapping_rules import MAPPING_RULES
from core.threat_intel.models import IOCType

pytestmark = pytest.mark.unit

_RULES_BY_TECHNIQUE = {rule.technique_id: rule for rule in MAPPING_RULES}

#: Techniques a real SSH-auth-log investigation found mapping as false
#: positives before this session's tightening — every one of them must now
#: require either a `match_tags` value or `require_co_occurrence`, so a bare
#: IOC-type-alone candidate set can never satisfy them.
_TIGHTENED_TECHNIQUE_IDS = ("T1046", "T1082", "T1036", "T1027", "T1090", "T1018")


@pytest.mark.parametrize("technique_id", _TIGHTENED_TECHNIQUE_IDS)
def test_tightened_rules_require_match_tags(technique_id: str) -> None:
    rule = _RULES_BY_TECHNIQUE[technique_id]
    assert rule.match_tags, f"{rule.rule_id} must require match_tags to gate false positives"


def test_t1204_user_execution_requires_email_co_occurrence() -> None:
    rule = _RULES_BY_TECHNIQUE["T1204"]
    assert rule.require_co_occurrence is True
    assert IOCType.EMAIL in rule.co_occurrence_ioc_types


def test_brute_force_and_valid_accounts_remain_untagged() -> None:
    """The two techniques a real brute-force/valid-account scenario
    genuinely supports must not have been over-tightened into requiring
    tags nothing produces yet."""
    for technique_id in ("T1110", "T1078"):
        rule = _RULES_BY_TECHNIQUE[technique_id]
        assert rule.match_tags == ()
        assert rule.require_co_occurrence is False


def test_every_rule_has_a_non_empty_rationale() -> None:
    for rule in MAPPING_RULES:
        assert rule.rationale, f"{rule.rule_id} has no rationale text"


@pytest.mark.parametrize("technique_id", _TIGHTENED_TECHNIQUE_IDS)
def test_tightened_rules_have_an_explicit_rationale_template(technique_id: str) -> None:
    """Tag-gated rules explain *why* they're gated, not just that they are —
    task requirement: 'show exactly why each technique was selected.'"""
    rule = _RULES_BY_TECHNIQUE[technique_id]
    assert rule.rationale_template
