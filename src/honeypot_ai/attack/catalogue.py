"""Which ATT&CK techniques exist, and which of them may still be used.

Everything in this project that names a technique goes through here. The
architecture promises that an invented technique ID is rejected against the
official data rather than published, and that promise is only as good as the
data: ATT&CK changes under its users. Release 20 renamed the "Defense Evasion"
tactic to `stealth`, added a `defense-impairment` tactic, and revoked T1562
(Impair Defenses) in favour of T1685. A mapping written from memory of an
older release would still look plausible and would be wrong.

So the catalogue is pinned to one release, committed, and loaded without a
network, and a technique is accepted only if it exists in that release and is
still current. A revoked one is refused with the ID that replaced it, which is
the fix rather than just the complaint.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any

#: The release this project maps against. Changing it is a deliberate act:
#: rebuild the file with `python -m honeypot_ai.attack build`, rerun the tests,
#: and read what the new release revoked.
PINNED_VERSION = "20.1"


class UnknownTechnique(ValueError):
    """Not an ATT&CK technique in the pinned release."""


class RetiredTechnique(ValueError):
    """A technique that exists but has been revoked or deprecated."""


@dataclass(frozen=True)
class Tactic:
    id: str
    shortname: str
    name: str


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    status: str
    revoked_by: str | None

    @property
    def current(self) -> bool:
        return self.status == "active"

    @property
    def parent(self) -> str | None:
        """T1059.004 → T1059. None for a technique that is not a sub-technique."""
        return self.id.split(".")[0] if "." in self.id else None

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/")


@dataclass(frozen=True)
class Catalogue:
    version: str
    modified: str
    source_sha256: str
    attribution: str
    tactics: tuple[Tactic, ...]
    techniques: dict[str, Technique]

    def get(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id)

    def require(self, technique_id: str) -> Technique:
        """The technique, if it exists in this release and is still current."""
        technique = self.techniques.get(technique_id)
        if technique is None:
            raise UnknownTechnique(f"{technique_id} is not in ATT&CK {self.version}")
        if technique.status == "revoked":
            raise RetiredTechnique(
                f"{technique_id} ({technique.name}) was revoked in ATT&CK {self.version}"
                + (f"; use {technique.revoked_by}" if technique.revoked_by else "")
            )
        if technique.status == "deprecated":
            raise RetiredTechnique(
                f"{technique_id} ({technique.name}) is deprecated in ATT&CK {self.version}"
            )
        return technique

    def tactic(self, shortname: str) -> Tactic:
        return next(t for t in self.tactics if t.shortname == shortname)


def parse(data: dict[str, Any]) -> Catalogue:
    return Catalogue(
        version=data["attack"]["version"],
        modified=data["attack"]["modified"],
        source_sha256=data["attack"]["source_sha256"],
        attribution=data["attribution"],
        tactics=tuple(Tactic(**t) for t in data["tactics"]),
        techniques={
            t["id"]: Technique(
                id=t["id"],
                name=t["name"],
                tactics=tuple(t["tactics"]),
                status=t["status"],
                revoked_by=t["revoked_by"],
            )
            for t in data["techniques"]
        },
    )


@lru_cache(maxsize=1)
def load(version: str = PINNED_VERSION) -> Catalogue:
    """The committed catalogue for `version`. Read once per process."""
    name = f"enterprise-attack-{version}.json"
    text = resources.files("honeypot_ai.attack").joinpath("releases", name).read_text("utf-8")
    return parse(json.loads(text))
