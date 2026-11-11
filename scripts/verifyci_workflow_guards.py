#!/usr/bin/env python3
"""Workflow input guards for the VerifyCI release pipelines (stdlib only).

Each subcommand-style flag validates one value and exits:
  0 - valid
  1 - invalid (reason on stderr)

Used by .github/workflows/{build_worker_image,release_measurements,
publish_release_evidence,release}.yml before any build/push/publish action so
that hostile input (newline injection, shell metacharacters, traversal, option
injection) fails closed instead of reaching docker/git/gh commands.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

BRANCH_RE = re.compile(r"^evidence/[A-Za-z0-9._/-]{1,80}$")
RUN_ID_RE = re.compile(r"^[0-9]{1,20}$")
IMAGE_TAG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
WORKER_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/_.-]{0,100}@sha256:[0-9a-f]{64}$")
REV_HEX_RE = re.compile(r"^[0-9a-f]{7,64}$")
TAG_RE = re.compile(r"^v[0-9][A-Za-z0-9._-]{0,60}$")
COMMIT40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

BRANCH_EXACT_DENY = ("main", "release-authority")

EVIDENCE_REL_PATH = Path("evidence") / "release" / "release_validation.json"


class InvalidInput(ValueError):
    """Raised when a guard validation fails; CLI maps it to exit 1 + stderr."""


def _check(value: str, pattern: re.Pattern[str], what: str) -> str:
    if not pattern.fullmatch(value):
        raise InvalidInput(
            f"invalid {what}: {value[:120]!r} ({len(value)} chars) does not match {pattern.pattern}"
        )
    return value


def validate_branch(value: str) -> str:
    """Evidence branch name: evidence/<safe charset>, no traversal/denylist."""
    if value in BRANCH_EXACT_DENY or value.startswith("refs/") or ".." in value:
        raise InvalidInput(f"rejected branch name: {value[:120]!r}")
    return _check(value, BRANCH_RE, "branch")


def validate_run_id(value: str) -> str:
    return _check(value, RUN_ID_RE, "run id")


def validate_image_tag(value: str) -> str:
    return _check(value, IMAGE_TAG_RE, "image tag")


def validate_worker_image(value: str) -> str:
    return _check(value, WORKER_IMAGE_RE, "worker image (must be digest-pinned)")


def validate_rev(value: str) -> str:
    if REV_HEX_RE.fullmatch(value) or TAG_RE.fullmatch(value):
        return value
    raise InvalidInput(
        f"invalid rev: {value[:120]!r} is neither 7-64 lowercase hex nor a v-tag"
    )


def validate_tag(value: str) -> str:
    return _check(value, TAG_RE, "release tag")


def validate_commit_sha40(value: str) -> str:
    return _check(value, COMMIT40_RE, "commit SHA (40-hex)")


def validate_hex_pubkey(value: str, what: str) -> str:
    if len(value) < 32 or len(value) % 2 != 0 or not HEX_RE.fullmatch(value):
        raise InvalidInput(
            f"invalid {what} public key: expected even-length hex of at least 32 chars, got {len(value)} chars"
        )
    return value


def validate_hex_pubkey_pair(embedded: str, pinned: str) -> None:
    """Embedded attestation key must byte-equal the pinned authority key."""
    validate_hex_pubkey(embedded, "embedded")
    validate_hex_pubkey(pinned, "pinned")
    if embedded.casefold() != pinned.casefold():
        raise InvalidInput(
            "attestation-embedded public key does not match pinned RELEASE_AUTHORITY key"
        )


def require_evidence_commit(repo: str, commit: str) -> None:
    """Fail unless <repo>/evidence/release/release_validation.json pins `commit`."""
    validate_commit_sha40(commit)
    evidence_path = Path(repo) / EVIDENCE_REL_PATH
    if not evidence_path.is_file():
        raise InvalidInput(
            f"signed release evidence not found: {evidence_path} (tag without matching evidence commit cannot publish)"
        )
    try:
        data = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InvalidInput(f"release evidence unreadable/invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise InvalidInput("release evidence JSON is not an object")
    stored = data.get("commit_sha")
    if not isinstance(stored, str) or not COMMIT40_RE.fullmatch(stored):
        raise InvalidInput(
            f"release evidence commit_sha is not 40-hex: {stored!r}"
        )
    if stored.casefold() != commit.casefold():
        raise InvalidInput(
            f"release evidence commit_sha {stored[:12]}... does not match requested commit {commit[:12]}..."
        )
    fingerprint = data.get("implementation_fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint.startswith("sha256:"):
        raise InvalidInput(
            f"release evidence implementation_fingerprint must start with 'sha256:', got {fingerprint!r}"
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VerifyCI workflow input guards (exit 0 valid / exit 1 invalid)"
    )
    parser.add_argument("--branch", help="evidence branch name")
    parser.add_argument("--run-id", help="numeric GitHub run id")
    parser.add_argument("--image-tag", help="container image tag")
    parser.add_argument("--worker-image", help="digest-pinned worker image reference")
    parser.add_argument("--rev", help="commit SHA (7-64 hex) or v-tag")
    parser.add_argument("--tag", help="release tag (v<digit>...)")

    require_group = parser.add_argument_group("evidence commit gate")
    require_group.add_argument(
        "--require-evidence-commit",
        metavar="REPO",
        help="repo root expected to contain evidence/release/release_validation.json",
    )
    require_group.add_argument(
        "--commit", metavar="SHA", help="40-hex commit the evidence must pin"
    )

    parser.add_argument(
        "--verify-pubkey",
        nargs=2,
        metavar=("EMBEDDED", "PINNED"),
        help="attestation-embedded public key and pinned authority key (hex)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    validators = [
        (args.branch, validate_branch, "--branch"),
        (args.run_id, validate_run_id, "--run-id"),
        (args.image_tag, validate_image_tag, "--image-tag"),
        (args.worker_image, validate_worker_image, "--worker-image"),
        (args.rev, validate_rev, "--rev"),
        (args.tag, validate_tag, "--tag"),
    ]
    if (args.require_evidence_commit is None) != (args.commit is None):
        parser.error("--require-evidence-commit and --commit must be used together")
    if args.require_evidence_commit is None and args.verify_pubkey is None:
        if all(value is None for value, _, _ in validators):
            parser.error("no validation flag provided")

    try:
        for value, validate, flag in validators:
            if value is not None:
                validate(value)
        if args.require_evidence_commit is not None:
            require_evidence_commit(args.require_evidence_commit, args.commit)
        if args.verify_pubkey is not None:
            validate_hex_pubkey_pair(args.verify_pubkey[0], args.verify_pubkey[1])
    except InvalidInput as exc:
        print(f"workflow guard rejected input: {exc}", file=sys.stderr)
        return 1

    print("workflow guard: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
