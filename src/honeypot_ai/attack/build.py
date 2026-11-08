"""Derive the compact catalogue from MITRE's official STIX bundle.

The bundle for one ATT&CK release is about 55 MB: techniques, groups, malware,
detection analytics and twenty thousand relationships. This project needs one
thing from it — which technique IDs exist, what they are called, which tactics
they belong to, and whether they are still current — and that fits in a file
small enough to commit, read in review and load without a network.

The derived file records the release, its publication date and the SHA-256 of
the bundle it was built from, so anyone can fetch the same bundle from
`mitre-attack/attack-stix-data` and rebuild it byte for byte.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SOURCE = "https://github.com/mitre-attack/attack-stix-data"

#: Required by the ATT&CK terms of use, and carried in the derived file itself
#: so it travels with the data rather than living only in a README.
ATTRIBUTION = (
    "© 2026 The MITRE Corporation. This work is reproduced and distributed with the "
    "permission of The MITRE Corporation. The MITRE Corporation (MITRE) hereby grants "
    "you a non-exclusive, royalty-free license to use ATT&CK® for research, development, "
    "and commercial purposes. Any copy you make for such purposes is authorized provided "
    "that you reproduce MITRE's copyright designation and this license in any such copy. "
    "MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation. "
    "Derived here from the official STIX bundle; only technique and tactic identifiers, "
    "names and status are kept."
)


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return str(ref.get("external_id"))
    return None


def derive(bundle: dict[str, Any], source_sha256: str) -> dict[str, Any]:
    """The compact catalogue for one Enterprise ATT&CK bundle."""
    objects: list[dict[str, Any]] = bundle["objects"]
    by_stix = {obj["id"]: obj for obj in objects}

    collection = next(obj for obj in objects if obj["type"] == "x-mitre-collection")
    matrix = next(obj for obj in objects if obj["type"] == "x-mitre-matrix")

    # Matrix order, the order the ATT&CK website shows them in, so a report
    # that groups by tactic reads left to right like the matrix does.
    tactics = []
    for ref in matrix["tactic_refs"]:
        tactic = by_stix[ref]
        tactics.append(
            {
                "id": _external_id(tactic),
                "shortname": tactic["x_mitre_shortname"],
                "name": tactic["name"],
            }
        )

    revoked_by: dict[str, str] = {}
    for obj in objects:
        if obj["type"] == "relationship" and obj["relationship_type"] == "revoked-by":
            target = _external_id(by_stix[obj["target_ref"]])
            if target:
                revoked_by[obj["source_ref"]] = target

    techniques = []
    for obj in objects:
        if obj["type"] != "attack-pattern":
            continue
        technique_id = _external_id(obj)
        if technique_id is None:
            continue
        if obj.get("revoked"):
            status = "revoked"
        elif obj.get("x_mitre_deprecated"):
            status = "deprecated"
        else:
            status = "active"
        techniques.append(
            {
                "id": technique_id,
                "name": obj["name"],
                "tactics": [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])],
                "status": status,
                "revoked_by": revoked_by.get(obj["id"]),
            }
        )
    techniques.sort(key=lambda t: t["id"])

    return {
        "attack": {
            "domain": "enterprise-attack",
            "version": collection["x_mitre_version"],
            "modified": collection["modified"][:10],
            "source": SOURCE,
            "source_sha256": source_sha256,
        },
        "attribution": ATTRIBUTION,
        "tactics": tactics,
        "techniques": techniques,
    }


def dumps(catalogue: dict[str, Any]) -> str:
    """One technique per line, so a new ATT&CK release diffs as a list of
    techniques that changed rather than as one enormous line."""
    head = {key: catalogue[key] for key in ("attack", "attribution", "tactics")}
    lines = json.dumps(head, ensure_ascii=False, indent=1)[:-2]
    rows = ",\n  ".join(json.dumps(t, ensure_ascii=False) for t in catalogue["techniques"])
    return f'{lines},\n "techniques": [\n  {rows}\n ]\n}}\n'


def build(bundle_path: Path, out_dir: Path) -> Path:
    raw = bundle_path.read_bytes()
    catalogue = derive(json.loads(raw), hashlib.sha256(raw).hexdigest())
    out = out_dir / f"enterprise-attack-{catalogue['attack']['version']}.json"
    out.write_text(dumps(catalogue), encoding="utf-8")
    return out
