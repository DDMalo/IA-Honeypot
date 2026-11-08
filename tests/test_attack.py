"""Tests for the pinned ATT&CK catalogue.

Two things matter. The committed file must say what the official release
says — checked here against facts of release 20.1 that an older mental model
gets wrong. And a technique that no longer exists must be refused, loudly,
with its replacement where there is one.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from honeypot_ai.attack.build import derive, dumps
from honeypot_ai.attack.catalogue import (
    PINNED_VERSION,
    RetiredTechnique,
    UnknownTechnique,
    load,
    parse,
)

# --- The committed catalogue -------------------------------------------------


def test_the_pinned_release_is_the_one_loaded() -> None:
    catalogue = load()
    assert catalogue.version == PINNED_VERSION == "20.1"
    assert catalogue.modified == "2026-11-05"
    assert len(catalogue.source_sha256) == 64


def test_it_holds_every_technique_with_its_status() -> None:
    statuses = [t.status for t in load().techniques.values()]
    assert len(statuses) == 867
    assert statuses.count("active") == 706


def test_release_20_renamed_defense_evasion() -> None:
    """The change most likely to be wrong in a mapping written from memory."""
    shortnames = [t.shortname for t in load().tactics]
    assert "stealth" in shortnames
    assert "defense-impairment" in shortnames
    assert "defense-evasion" not in shortnames
    assert load().require("T1027").tactics == ("stealth",)


def test_tactics_come_in_matrix_order() -> None:
    names = [t.shortname for t in load().tactics]
    assert names[0] == "reconnaissance"
    assert names.index("execution") < names.index("persistence") < names.index("impact")


def test_a_current_sub_technique_is_accepted() -> None:
    technique = load().require("T1059.004")
    assert technique.name == "Unix Shell"
    assert technique.parent == "T1059"
    assert technique.url == "https://attack.mitre.org/techniques/T1059/004"


def test_a_revoked_technique_is_refused_with_its_replacement() -> None:
    with pytest.raises(RetiredTechnique, match="T1562 .*revoked.*use T1685"):
        load().require("T1562")


def test_a_deprecated_technique_is_refused() -> None:
    with pytest.raises(RetiredTechnique, match="deprecated"):
        load().require("T1043")


def test_an_invented_technique_is_refused() -> None:
    """What a language model writes when it is guessing."""
    with pytest.raises(UnknownTechnique):
        load().require("T9999")


def test_the_committed_file_is_sorted_and_has_no_duplicates() -> None:
    ids = list(load().techniques)
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))


def test_the_attribution_travels_with_the_data() -> None:
    assert "reproduced and distributed with the permission of The MITRE Corporation" in (
        load().attribution
    )


# --- Building it from a bundle ----------------------------------------------


def ref(external_id: str) -> list[dict[str, str]]:
    return [{"source_name": "mitre-attack", "external_id": external_id}]


def bundle() -> dict[str, Any]:
    return {
        "objects": [
            {
                "type": "x-mitre-collection",
                "id": "col",
                "x_mitre_version": "99.0",
                "modified": "2030-01-02T00:00:00Z",
            },
            {"type": "x-mitre-matrix", "id": "mat", "tactic_refs": ["tac-b", "tac-a"]},
            {
                "type": "x-mitre-tactic",
                "id": "tac-a",
                "x_mitre_shortname": "impact",
                "name": "Impact",
                "external_references": ref("TA0040"),
            },
            {
                "type": "x-mitre-tactic",
                "id": "tac-b",
                "x_mitre_shortname": "execution",
                "name": "Execution",
                "external_references": ref("TA0002"),
            },
            {
                "type": "attack-pattern",
                "id": "ap-new",
                "name": "New",
                "external_references": ref("T2000"),
                "kill_chain_phases": [{"phase_name": "impact"}],
            },
            {
                "type": "attack-pattern",
                "id": "ap-old",
                "name": "Old",
                "revoked": True,
                "external_references": ref("T1000"),
            },
            {
                "type": "attack-pattern",
                "id": "ap-dep",
                "name": "Gone",
                "x_mitre_deprecated": True,
                "external_references": ref("T1500"),
            },
            {"type": "attack-pattern", "id": "ap-noid", "name": "No ID"},
            {
                "type": "relationship",
                "id": "rel",
                "relationship_type": "revoked-by",
                "source_ref": "ap-old",
                "target_ref": "ap-new",
            },
        ]
    }


def test_a_bundle_becomes_a_catalogue() -> None:
    catalogue = parse(derive(bundle(), "f" * 64))
    assert catalogue.version == "99.0"
    assert [t.shortname for t in catalogue.tactics] == ["execution", "impact"]
    assert list(catalogue.techniques) == ["T1000", "T1500", "T2000"]
    assert catalogue.techniques["T1000"].revoked_by == "T2000"
    assert catalogue.techniques["T1500"].status == "deprecated"
    assert catalogue.require("T2000").tactics == ("impact",)


def test_the_written_file_reads_back_as_the_same_catalogue() -> None:
    derived = derive(bundle(), "f" * 64)
    assert json.loads(dumps(derived)) == derived


# --- Behaviours to techniques -------------------------------------------------


def test_every_behaviour_has_a_decision() -> None:
    """A behaviour added to the taxonomy must be mapped, or explicitly not."""
    from honeypot_ai.attack.mapping import MAPPING
    from honeypot_ai.classify.taxonomy import Behaviour

    assert set(MAPPING) == set(Behaviour)
    assert all(row.why for row in MAPPING.values())


def test_every_mapped_technique_is_current_in_the_pinned_release() -> None:
    from honeypot_ai.attack.mapping import MAPPING

    for row in MAPPING.values():
        for technique_id in row.techniques:
            load().require(technique_id)


def test_a_heredoc_dropper_maps_to_tool_transfer_and_decoding() -> None:
    from honeypot_ai.attack.mapping import techniques_for
    from honeypot_ai.classify.taxonomy import Behaviour

    found = techniques_for(
        [Behaviour.PAYLOAD_WRITE, Behaviour.BASE64_DECODE, Behaviour.CPU_PROFILING]
    )
    assert [t.id for t in found] == ["T1082", "T1105", "T1140"]


def test_two_behaviours_with_the_same_technique_report_it_once() -> None:
    from honeypot_ai.attack.mapping import techniques_for
    from honeypot_ai.classify.taxonomy import Behaviour

    found = techniques_for([Behaviour.SSH_DIR_RESET, Behaviour.AUTHORIZED_KEYS_WRITE])
    assert [t.id for t in found] == ["T1098.004"]


def test_a_mapping_gone_stale_raises_instead_of_reporting() -> None:
    """What happens when the catalogue moves to a release that revoked one."""
    from honeypot_ai.attack.mapping import techniques_for
    from honeypot_ai.classify.taxonomy import Behaviour

    stale = parse(
        {
            "attack": {"version": "x", "modified": "x", "source_sha256": "x"},
            "attribution": "x",
            "tactics": [],
            "techniques": [
                {
                    "id": "T1105",
                    "name": "Ingress Tool Transfer",
                    "tactics": [],
                    "status": "revoked",
                    "revoked_by": "T9000",
                },
            ],
        }
    )
    with pytest.raises(RetiredTechnique, match="use T9000"):
        techniques_for([Behaviour.PAYLOAD_DOWNLOAD], stale)
