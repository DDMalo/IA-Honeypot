"""Rebuild the committed ATT&CK catalogue from MITRE's official bundle.

    git clone --depth 1 --filter=blob:none --no-checkout \\
        https://github.com/mitre-attack/attack-stix-data
    git -C attack-stix-data checkout HEAD -- enterprise-attack/enterprise-attack-20.1.json
    python -m honeypot_ai.attack build \\
        attack-stix-data/enterprise-attack/enterprise-attack-20.1.json

Only needed when moving to a new ATT&CK release. Nothing at runtime downloads
anything.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from honeypot_ai.attack.build import build

# Not `data/`: the repository ignores every directory of that name, because
# that is where raw honeypot logs live, and a catalogue there would silently
# never be committed.
DATA_DIR = Path(__file__).parent / "releases"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m honeypot_ai.attack")
    commands = parser.add_subparsers(dest="command", required=True)
    rebuild = commands.add_parser("build", help="derive the catalogue from a STIX bundle")
    rebuild.add_argument("bundle", type=Path)
    rebuild.add_argument("--out-dir", type=Path, default=DATA_DIR)
    args = parser.parse_args(argv)

    out = build(args.bundle, args.out_dir)
    print(f"Written {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
