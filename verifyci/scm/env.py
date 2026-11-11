"""Zero-dependency Git environment scrubbing and hardened command helpers."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Sequence

from verifyci.contracts.canonical import is_hex40


_SCRUB_EXACT = frozenset(
    {
        "VERIFYCI_RELEASE_SIGNING_KEY",
        "VERIFYCI_RELEASE_VALIDATION_PATH",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GIT_ASKPASS",
        "SSH_AUTH_SOCK",
    }
)
_SCRUB_PATTERNS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "SIGNING_KEY",
    "PRIVATE_KEY",
)


def scrubbed_git_env() -> dict[str, str]:
    """Return a copy of the process environment scrubbed of credentials and hardened for Git."""
    env = os.environ.copy()
    for key in list(env.keys()):
        upper = key.upper()
        if (
            key in _SCRUB_EXACT
            or upper.endswith(("_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_PASSWD", "_CREDENTIAL"))
            or any(part in upper for part in _SCRUB_PATTERNS)
        ):
            env.pop(key, None)
    env.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "LC_ALL": "C",
        }
    )
    return env


def hardened_git_command(repo_path: str | Path, args: Sequence[str]) -> list[str]:
    """Build a hardened Git CLI command targeting ``repo_path``."""
    return [
        "git",
        "-C",
        str(repo_path),
        "--no-pager",
        "-c",
        "core.quotepath=false",
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.safecrlf=false",
        "-c",
        "core.hooksPath=",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.attributesFile={os.devnull}",
        *args,
    ]


__all__ = ["hardened_git_command", "is_hex40", "scrubbed_git_env"]
