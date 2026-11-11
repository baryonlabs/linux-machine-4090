#!/usr/bin/env python3
"""Resolve operational config paths outside the public repository.

The repository ships anonymized examples. A live deployment keeps its real
`users.yaml` / `acl.hujson` outside the tree (e.g. /etc/labops or ~/.config/labops)
and points the console at them with env vars.
"""

from __future__ import annotations

import os
import pathlib

BASE_DIR = pathlib.Path(__file__).parent.parent
REPO_USERS = BASE_DIR / "labops" / "users.yaml"
REPO_ACL = BASE_DIR / "headscale" / "acl.hujson"


def _first_existing(candidates) -> pathlib.Path | None:
    for c in candidates:
        if not c:
            continue
        p = pathlib.Path(c).expanduser()
        if p.exists():
            return p
    return None


def users_yaml_path() -> pathlib.Path:
    return (
        _first_existing([
            os.environ.get("LABOPS_USERS_YAML"),
            "/etc/labops/users.yaml",
            pathlib.Path.home() / ".config/labops/users.yaml",
        ])
        or REPO_USERS
    )


def acl_path() -> pathlib.Path:
    return (
        _first_existing([
            os.environ.get("LABOPS_ACL"),
            "/etc/labops/acl.hujson",
            pathlib.Path.home() / ".config/labops/acl.hujson",
        ])
        or REPO_ACL
    )


def user_names(role: str | None = None) -> list[str]:
    """Minimal parser for the restricted users.yaml (one `- name:` per user)."""
    path = users_yaml_path()
    if not path.exists():
        return []
    names, current_role = [], None
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s.startswith("- name:"):
            current_role = None
            names.append(s.split(":", 1)[1].strip().strip('"'))
        elif s.startswith("role:"):
            current_role = s.split(":", 1)[1].strip()
            if role and names and current_role != role:
                names.pop()
    return names
