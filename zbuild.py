#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import sys


def is_forge_root(candidate: Path) -> bool:
    """Return whether a directory is a usable zeta_forge checkout."""

    return (
        (candidate / "common" / "zeta_forge" / "config.py").is_file()
        and (candidate / "builder").is_dir()
        and (candidate / "3rd").is_dir()
    )


def expand_path(raw_path: str) -> Path:
    """Expand shell-style variables and return an absolute path."""

    return Path(os.path.expandvars(os.path.expanduser(raw_path))).resolve()


def find_forge_root(start: Path) -> Path:
    """Locate zeta_forge from the workspace or nearby directories."""

    candidates: list[Path] = []
    zetax_root_raw = os.environ.get("ZETAX_ROOT")
    if zetax_root_raw:
        candidates.append(expand_path(zetax_root_raw) / "zeta_forge")

    for candidate in [start, *start.parents]:
        candidates.append(candidate)
        candidates.append(candidate / "zeta_forge")

    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if is_forge_root(resolved):
            return resolved

    raise RuntimeError(
        "Unable to locate zeta_forge root. "
        "Set ZETAX_ROOT=/path/to/workspace and ensure "
        "$ZETAX_ROOT/zeta_forge exists, or place zeta_vault next to "
        "zeta_forge."
    )


SCRIPT_PATH = Path(__file__).resolve()
FORGE_ROOT = find_forge_root(SCRIPT_PATH.parent)
sys.path.insert(0, str(FORGE_ROOT / "common"))

from builder.zeta_vault import cli


if __name__ == "__main__":
    raise SystemExit(cli(SCRIPT_PATH, source_dir_default=SCRIPT_PATH.parent))
