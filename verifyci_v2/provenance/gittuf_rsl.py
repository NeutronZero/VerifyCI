from __future__ import annotations

import msgspec
import json
from pathlib import Path
import subprocess
import time
import os
import re
from typing import Protocol

from verifyci_v2.contracts.attestation import (
    DSSEEnvelope,
    DSSESignature,
    RSLReferenceEntry,
)
from verifyci_v2.contracts.canonical import canonical_digest, canonical_jcs_str


class RSLTamperDetectedError(RuntimeError):
    """Raised when the gittuf Reference State Log hash chain or parent pointer is broken."""


class GitPlumbingProtocol(Protocol):
    def resolve_commit(self, target: str) -> str: ...
    def publish_rsl(self, payload: bytes, *, target_commit_sha: str, ref_name: str, entry_id: str, ussa_merkle_root: str, envelope_digest: str, envelope_json: str) -> str | None: ...


class InMemoryGitPlumbingAdapter:
    """Explicit test adapter for synthetic commit identifiers; never selected for a real repo."""
    def resolve_commit(self, target: str) -> str:
        return target

    def publish_rsl(self, payload: bytes, *, target_commit_sha: str, ref_name: str, entry_id: str, ussa_merkle_root: str, envelope_digest: str, envelope_json: str) -> str | None:
        return None


class SubprocessGitPlumbingAdapter:
    """Strict Git object/reference adapter. Target commits are always validated."""
    def __init__(self, repo_path: str | Path):
        self.repo_path = Path(repo_path).resolve()

    def _run(self, args: list[str], *, input_bytes: bytes | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
        proc = subprocess.run(args, cwd=str(self.repo_path), input=input_bytes, capture_output=True, check=False, env=env)
        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", errors="replace")
            raise RSLTamperDetectedError(f"Git command {' '.join(args)} failed: {stderr.strip()}")
        return proc

    def resolve_commit(self, target: str) -> str:
        if not target or target.startswith("-") or any(ch.isspace() for ch in target):
            raise RSLTamperDetectedError("Target commit identifier is malformed")
        proc = self._run(["git", "rev-parse", "--verify", f"{target}^{{commit}}"])
        sha = proc.stdout.decode("ascii", errors="strict").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{40,64}", sha):
            raise RSLTamperDetectedError("Git did not resolve target to an immutable commit SHA")
        return sha

    def publish_rsl(self, payload: bytes, *, target_commit_sha: str, ref_name: str, entry_id: str, ussa_merkle_root: str, envelope_digest: str, envelope_json: str) -> str | None:
        resolved_target = self.resolve_commit(target_commit_sha)
        if not re.fullmatch(r"refs/[A-Za-z0-9._/-]+", ref_name) or ".." in ref_name or ref_name.endswith("/"):
            raise RSLTamperDetectedError(f"Invalid Git ref name: {ref_name!r}")
        blob_sha = self._run(["git", "hash-object", "-w", "--stdin"], input_bytes=payload).stdout.decode("ascii").strip()
        tree_input = f"100644 blob {blob_sha}\treference-state-log.jsonl\n".encode("ascii")
        tree_sha = self._run(["git", "mktree"], input_bytes=tree_input).stdout.decode("ascii").strip()
        ref = "refs/gittuf/reference-state-log"
        parent_proc = subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], cwd=str(self.repo_path), capture_output=True, check=False)
        parent = parent_proc.stdout.decode("ascii").strip() if parent_proc.returncode == 0 else None
        msg = (f"RSL Reference Entry\n\nrefName: {ref_name}\ntargetID: {resolved_target}\nussaMerkleRoot: {ussa_merkle_root}\ndsseEnvelopeDigest: {envelope_digest}\nentryID: {entry_id}\n").encode("utf-8")
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "VerifyCI v2 RSL",
            "GIT_AUTHOR_EMAIL": "rsl@verifyci.local",
            "GIT_COMMITTER_NAME": "VerifyCI v2 RSL",
            "GIT_COMMITTER_EMAIL": "rsl@verifyci.local",
        }
        cmd = ["git", "commit-tree", tree_sha]
        if parent:
            cmd.extend(["-p", parent])
        new_sha = self._run(cmd, input_bytes=msg, env=env).stdout.decode("ascii").strip()
        expected_old = parent or ("0" * len(new_sha))
        # Bind this exact envelope to this exact RSL commit, not merely to the
        # target source commit (which may appear in multiple RSL entries).
        self._run(["git", "notes", "--ref", "refs/notes/verifyci", "add", "-f", "-F", "-", "--", resolved_target], input_bytes=envelope_json.encode("utf-8"))
        self._run(["git", "notes", "--ref", "refs/notes/verifyci", "add", "-f", "-F", "-", "--", new_sha], input_bytes=envelope_json.encode("utf-8"))
        self._run(["git", "update-ref", ref, new_sha, expected_old])
        return new_sha


class GittufRSLLedger:
    """
    Layer 7 Forge-Independent Provenance Ledger (`verifyci_v2/provenance/gittuf_rsl.py`).
    Maintains a hash-chained Reference State Log (`refs/gittuf/reference-state-log`) and
    notes map persisted to Git objects/refs to defend against branch/tag rollbacks,
    force-pushes, and replay attacks across stateless CI runners.
    """

    def __init__(
        self,
        repo_path: str | Path | None = None,
        *,
        git_adapter: GitPlumbingProtocol | None = None,
    ) -> None:
        self.repo_path = Path(repo_path).resolve() if repo_path else None
        if git_adapter is not None:
            self.git_adapter = git_adapter
        elif self.repo_path is not None:
            self.git_adapter = SubprocessGitPlumbingAdapter(self.repo_path)
        else:
            raise ValueError(
                "GittufRSLLedger requires repo_path for Git-backed validation or an "
                "explicit git_adapter for isolated in-memory/test use."
            )
        self._rsl_chain: list[RSLReferenceEntry] = []
        self._git_notes_by_commit: dict[str, DSSEEnvelope] = {}
        self._git_notes_by_entry: dict[str, DSSEEnvelope] = {}
        self._rsl_commit_by_entry: dict[str, str] = {}

        if self.repo_path:
            self._load_from_repo()
            self.verify_rsl_lineage()

    def _get_storage_paths(self) -> tuple[Path, Path]:
        assert self.repo_path is not None
        vci_dir = self.repo_path / ".verifyci" / "rsl"
        vci_dir.mkdir(parents=True, exist_ok=True)
        rsl_file = vci_dir / "reference-state-log.jsonl"
        notes_file = vci_dir / "notes.jsonl"
        return rsl_file, notes_file

    def _load_from_repo(self) -> None:
        assert self.repo_path is not None
        rsl_file, notes_file = self._get_storage_paths()

        # The Git ref is authoritative when present. The JSONL file is only a
        # local cache: never let a stale/tampered cache override the RSL commit.
        rsl_lines: list[str] = []
        git_ref_present = False
        git_dir_check = subprocess.run(
            ["git", "rev-parse", "--git-dir"], cwd=str(self.repo_path),
            capture_output=True, text=True, check=False,
        )
        if git_dir_check.returncode == 0:
            ref_check = subprocess.run(
                ["git", "rev-parse", "--verify", "--quiet", "refs/gittuf/reference-state-log^{commit}"],
                cwd=str(self.repo_path), capture_output=True, text=True, check=False,
            )
            if ref_check.returncode == 0:
                git_ref_present = True
                proc = subprocess.run(
                    ["git", "show", "refs/gittuf/reference-state-log:reference-state-log.jsonl"],
                    cwd=str(self.repo_path), capture_output=True, text=True, check=False,
                )
                if proc.returncode != 0:
                    raise RSLTamperDetectedError("RSL ref exists but its canonical log blob cannot be read")
                rsl_lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
                # Restore the convenience journal from the authoritative ref. A
                # stale cache must not alter lineage semantics.
                rsl_file.write_text("".join(line + "\n" for line in rsl_lines), encoding="utf-8")

        if not git_ref_present and rsl_file.exists():
            rsl_lines = [
                line_str.strip()
                for line_str in rsl_file.read_text(encoding="utf-8").splitlines()
                if line_str.strip()
            ]

        # Legacy file-ref check is used only when the modern Git ref is absent.
        legacy_rsl = self.repo_path / ".git" / "refs" / "gittuf" / "reference-state-log"
        if not rsl_lines and not git_ref_present and legacy_rsl.exists():
            try:
                rsl_lines = [
                    line_str.strip()
                    for line_str in legacy_rsl.read_text(encoding="utf-8").splitlines()
                    if line_str.strip()
                ]
            except Exception:
                pass

        for line in rsl_lines:
            data = json.loads(line)
            self._rsl_chain.append(
                RSLReferenceEntry(
                    entry_id=data["entry_id"],
                    parent_entry_id=data["parent_entry_id"],
                    ref_name=data["ref_name"],
                    target_commit_sha=data["target_commit_sha"],
                    ussa_merkle_root=data["ussa_merkle_root"],
                    dsse_envelope_digest=data["dsse_envelope_digest"],
                    timestamp_epoch=data["timestamp_epoch"],
                )
            )

        # Git notes are bound to the RSL commit that introduced each entry. The
        # local JSONL file is only a cache and is not trusted when the Git ref exists.
        notes_lines: list[str] = []
        if git_ref_present:
            commits_proc = subprocess.run(
                ["git", "rev-list", "--reverse", "refs/gittuf/reference-state-log"],
                cwd=str(self.repo_path), capture_output=True, text=True, check=False,
            )
            if commits_proc.returncode != 0:
                raise RSLTamperDetectedError("Could not enumerate RSL commit history")
            entry_by_id = {entry.entry_id: entry for entry in self._rsl_chain}
            sidecar: list[dict[str, object]] = []
            for commit_sha in commits_proc.stdout.splitlines():
                if not commit_sha:
                    continue
                tail_proc = subprocess.run(
                    ["git", "show", f"{commit_sha}:reference-state-log.jsonl"],
                    cwd=str(self.repo_path), capture_output=True, text=True, check=False,
                )
                if tail_proc.returncode != 0:
                    raise RSLTamperDetectedError(f"RSL commit {commit_sha} lacks its canonical log")
                tail_lines = [line for line in tail_proc.stdout.splitlines() if line.strip()]
                if not tail_lines:
                    raise RSLTamperDetectedError(f"RSL commit {commit_sha} contains an empty log")
                try:
                    tail_id = json.loads(tail_lines[-1])["entry_id"]
                except Exception as exc:
                    raise RSLTamperDetectedError(f"Malformed RSL entry in commit {commit_sha}: {exc}") from exc
                entry = entry_by_id.get(tail_id)
                if entry is None:
                    raise RSLTamperDetectedError(f"RSL commit {commit_sha} introduces an unknown entry {tail_id}")
                note_proc = subprocess.run(
                    ["git", "notes", "--ref", "refs/notes/verifyci", "show", commit_sha],
                    cwd=str(self.repo_path), capture_output=True, text=True, check=False,
                )
                if note_proc.returncode != 0:
                    raise RSLTamperDetectedError(f"RSL entry {entry.entry_id} has no Git-bound DSSE envelope")
                try:
                    raw_env = json.loads(note_proc.stdout)
                    envelope = DSSEEnvelope(
                        payloadType=raw_env["payloadType"],
                        payload=raw_env["payload"],
                        signatures=tuple(DSSESignature(**sig) for sig in raw_env.get("signatures", ())),
                    )
                except Exception as exc:
                    raise RSLTamperDetectedError(f"Malformed DSSE envelope for RSL entry {entry.entry_id}: {exc}") from exc
                if canonical_digest(envelope, domain="verifyci.v2.dsse.envelope") != entry.dsse_envelope_digest:
                    raise RSLTamperDetectedError(f"DSSE envelope digest mismatch for RSL entry {entry.entry_id}")
                self._rsl_commit_by_entry[entry.entry_id] = commit_sha
                self._git_notes_by_entry[entry.entry_id] = envelope
                self._git_notes_by_commit[entry.target_commit_sha] = envelope
                sidecar.append({
                    "entry_id": entry.entry_id,
                    "target_commit_sha": entry.target_commit_sha,
                    "envelope": msgspec.to_builtins(envelope),
                })
            notes_file.write_text("".join(canonical_jcs_str(item) + "\n" for item in sidecar), encoding="utf-8")
        else:
            if notes_file.exists():
                notes_lines = [line.strip() for line in notes_file.read_text(encoding="utf-8").splitlines() if line.strip()]
            else:
                legacy_notes = self.repo_path / ".git" / "refs" / "notes" / "verifyci"
                if legacy_notes.exists():
                    try:
                        notes_lines = [line.strip() for line in legacy_notes.read_text(encoding="utf-8").splitlines() if line.strip()]
                    except Exception:
                        pass
            for line in notes_lines:
                data = json.loads(line)
                target_sha = data.get("target_commit_sha", "")
                raw_env = data["envelope"]
                envelope = DSSEEnvelope(
                    payloadType=raw_env["payloadType"], payload=raw_env["payload"],
                    signatures=tuple(DSSESignature(**sig) for sig in raw_env.get("signatures", ())),
                )
                if data.get("entry_id"):
                    entry = next((e for e in self._rsl_chain if e.entry_id == data["entry_id"]), None)
                    if entry is None or canonical_digest(envelope, domain="verifyci.v2.dsse.envelope") != entry.dsse_envelope_digest:
                        raise RSLTamperDetectedError("Local DSSE sidecar does not match its RSL entry")
                    self._git_notes_by_entry[entry.entry_id] = envelope
                self._git_notes_by_commit[target_sha] = envelope

    @property
    def latest_entry(self) -> RSLReferenceEntry | None:
        return self._rsl_chain[-1] if self._rsl_chain else None

    def append_reference_entry(
        self,
        *,
        ref_name: str,
        target_commit_sha: str,
        ussa_merkle_root: str,
        dsse_envelope: DSSEEnvelope,
        timestamp_epoch: int | None = None,
    ) -> RSLReferenceEntry:
        # Validate the target before mutating local or persistent state. Real-repo
        # adapters never bypass object validation based on SHA string shape.
        resolved_target = self.git_adapter.resolve_commit(target_commit_sha)
        parent_id = self._rsl_chain[-1].entry_id if self._rsl_chain else None
        env_digest = canonical_digest(dsse_envelope, domain="verifyci.v2.dsse.envelope")
        ts = timestamp_epoch if timestamp_epoch is not None else int(time.time())
        payload_to_hash = {
            "parent_entry_id": parent_id,
            "ref_name": ref_name,
            "target_commit_sha": resolved_target,
            "ussa_merkle_root": ussa_merkle_root,
            "dsse_envelope_digest": env_digest,
            "timestamp_epoch": ts,
        }
        entry_id = canonical_digest(payload_to_hash, domain="verifyci.v2.gittuf.rsl")
        entry = RSLReferenceEntry(
            entry_id=entry_id, parent_entry_id=parent_id, ref_name=ref_name,
            target_commit_sha=resolved_target, ussa_merkle_root=ussa_merkle_root,
            dsse_envelope_digest=env_digest, timestamp_epoch=ts,
        )
        candidate_chain = [*self._rsl_chain, entry]
        candidate_notes_by_entry = {**self._git_notes_by_entry, entry.entry_id: dsse_envelope}
        candidate_notes_by_commit = {**self._git_notes_by_commit, resolved_target: dsse_envelope}
        if self.repo_path:
            rsl_file, notes_file = self._get_storage_paths()
            rsl_payload = "".join(canonical_jcs_str(msgspec.to_builtins(item)) + "\n" for item in candidate_chain).encode("utf-8")
            note_records = [
                {
                    "entry_id": item.entry_id,
                    "target_commit_sha": item.target_commit_sha,
                    "envelope": msgspec.to_builtins(candidate_notes_by_entry[item.entry_id]),
                }
                for item in candidate_chain if item.entry_id in candidate_notes_by_entry
            ]
            notes_payload = "".join(canonical_jcs_str(row) + "\n" for row in note_records).encode("utf-8")
            # Git adapter validates the source commit, binds DSSE to the RSL commit,
            # then performs an atomic compare-and-swap of the RSL ref.
            envelope_json = canonical_jcs_str(msgspec.to_builtins(dsse_envelope))
            rsl_commit_sha = self.git_adapter.publish_rsl(
                rsl_payload, target_commit_sha=resolved_target, ref_name=ref_name,
                entry_id=entry_id, ussa_merkle_root=ussa_merkle_root,
                envelope_digest=env_digest, envelope_json=envelope_json,
            )
            for target, payload in ((rsl_file, rsl_payload), (notes_file, notes_payload)):
                tmp = target.with_suffix(target.suffix + ".tmp")
                tmp.write_bytes(payload)
                os.replace(tmp, target)
            if rsl_commit_sha:
                self._rsl_commit_by_entry[entry.entry_id] = rsl_commit_sha
        self._rsl_chain = candidate_chain
        self._git_notes_by_entry = candidate_notes_by_entry
        self._git_notes_by_commit = candidate_notes_by_commit
        return entry

    def verify_rsl_lineage(self, expected_head_commit: str | None = None) -> bool:
        """
        Cryptographically verifies every link in the Reference State Log from genesis to head
        and checks that the current branch tip matches the latest RSL entry.
        """
        prev_id: str | None = None
        for entry in self._rsl_chain:
            if self.repo_path is not None:
                resolved_target = self.git_adapter.resolve_commit(entry.target_commit_sha)
                if resolved_target != entry.target_commit_sha.lower():
                    raise RSLTamperDetectedError(f"RSL target commit identity mismatch for entry {entry.entry_id}")
            if entry.parent_entry_id != prev_id:
                raise RSLTamperDetectedError(
                    f"RSL parent link mismatch at entry {entry.entry_id}: "
                    f"expected {prev_id}, got {entry.parent_entry_id}"
                )
            recomputed = canonical_digest(
                {
                    "parent_entry_id": entry.parent_entry_id,
                    "ref_name": entry.ref_name,
                    "target_commit_sha": entry.target_commit_sha,
                    "ussa_merkle_root": entry.ussa_merkle_root,
                    "dsse_envelope_digest": entry.dsse_envelope_digest,
                    "timestamp_epoch": entry.timestamp_epoch,
                },
                domain="verifyci.v2.gittuf.rsl",
            )
            if recomputed != entry.entry_id:
                raise RSLTamperDetectedError(
                    f"RSL entry digest tampered: {entry.entry_id}"
                )
            prev_id = entry.entry_id

        if expected_head_commit is not None:
            if not self._rsl_chain:
                raise RSLTamperDetectedError(
                    f"RSL ledger is empty: cannot verify expected head commit {expected_head_commit}"
                )
            if self._rsl_chain[-1].target_commit_sha != expected_head_commit:
                raise RSLTamperDetectedError(
                    f"Rollback/force-push attack detected: RSL head is "
                    f"{self._rsl_chain[-1].target_commit_sha}, but ref points to {expected_head_commit}"
                )
        return True

    def get_note_for_commit(self, commit_sha: str) -> DSSEEnvelope | None:
        return self._git_notes_by_commit.get(commit_sha)
