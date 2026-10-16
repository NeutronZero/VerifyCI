from __future__ import annotations

import msgspec
import json
from pathlib import Path
import subprocess
import time

from verifyci_v2.contracts.attestation import (
    DSSEEnvelope,
    DSSESignature,
    RSLReferenceEntry,
)
from verifyci_v2.contracts.canonical import canonical_digest, canonical_jcs_str


class RSLTamperDetectedError(RuntimeError):
    """Raised when the gittuf Reference State Log hash chain or parent pointer is broken."""


class GittufRSLLedger:
    """
    Layer 7 Forge-Independent Provenance Ledger (`verifyci_v2/provenance/gittuf_rsl.py`).
    Maintains a hash-chained Reference State Log (`refs/gittuf/reference-state-log`) and
    notes map persisted to Git objects/refs to defend against branch/tag rollbacks,
    force-pushes, and replay attacks across stateless CI runners.
    """

    def __init__(self, repo_path: str | Path | None = None) -> None:
        self.repo_path = Path(repo_path) if repo_path else None
        self._rsl_chain: list[RSLReferenceEntry] = []
        self._git_notes_by_commit: dict[str, DSSEEnvelope] = {}

        if self.repo_path:
            self._load_from_repo()

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

        # Load RSL entries from persistent journal or git ref
        rsl_lines: list[str] = []
        if rsl_file.exists():
            rsl_lines = [
                line_str.strip()
                for line_str in rsl_file.read_text(encoding="utf-8").splitlines()
                if line_str.strip()
            ]
        elif (self.repo_path / ".git").exists():
            # Read from the RSL commit tree (`refs/gittuf/reference-state-log:reference-state-log.jsonl`)
            # with fallback to direct blob ref for backward compatibility
            try:
                proc = subprocess.run(
                    [
                        "git",
                        "cat-file",
                        "-p",
                        "refs/gittuf/reference-state-log:reference-state-log.jsonl",
                    ],
                    cwd=str(self.repo_path),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if proc.returncode != 0:
                    proc = subprocess.run(
                        ["git", "cat-file", "-p", "refs/gittuf/reference-state-log"],
                        cwd=str(self.repo_path),
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                if proc.returncode == 0 and proc.stdout.strip():
                    rsl_lines = [
                        line_str.strip()
                        for line_str in proc.stdout.splitlines()
                        if line_str.strip().startswith("{")
                    ]
            except Exception:
                pass

        # Legacy backward-compatibility check
        legacy_rsl = self.repo_path / ".git" / "refs" / "gittuf" / "reference-state-log"
        if not rsl_lines and legacy_rsl.exists():
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

        # Load notes from journal
        notes_lines: list[str] = []
        if notes_file.exists():
            notes_lines = [
                line_str.strip()
                for line_str in notes_file.read_text(encoding="utf-8").splitlines()
                if line_str.strip()
            ]
        else:
            legacy_notes = self.repo_path / ".git" / "refs" / "notes" / "verifyci"
            if legacy_notes.exists():
                try:
                    notes_lines = [
                        line_str.strip()
                        for line_str in legacy_notes.read_text(
                            encoding="utf-8"
                        ).splitlines()
                        if line_str.strip()
                    ]
                except Exception:
                    pass

        for line in notes_lines:
            data = json.loads(line)
            target_sha = data["target_commit_sha"]
            raw_env = data["envelope"]
            sigs = tuple(DSSESignature(**s) for s in raw_env.get("signatures", ()))
            self._git_notes_by_commit[target_sha] = DSSEEnvelope(
                payloadType=raw_env["payloadType"],
                payload=raw_env["payload"],
                signatures=sigs,
            )

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
        parent_id = self._rsl_chain[-1].entry_id if self._rsl_chain else None
        env_digest = canonical_digest(dsse_envelope, domain="verifyci.v2.dsse.envelope")
        ts = timestamp_epoch if timestamp_epoch is not None else int(time.time())

        payload_to_hash = {
            "parent_entry_id": parent_id,
            "ref_name": ref_name,
            "target_commit_sha": target_commit_sha,
            "ussa_merkle_root": ussa_merkle_root,
            "dsse_envelope_digest": env_digest,
            "timestamp_epoch": ts,
        }
        entry_id = canonical_digest(payload_to_hash, domain="verifyci.v2.gittuf.rsl")
        entry = RSLReferenceEntry(
            entry_id=entry_id,
            parent_entry_id=parent_id,
            ref_name=ref_name,
            target_commit_sha=target_commit_sha,
            ussa_merkle_root=ussa_merkle_root,
            dsse_envelope_digest=env_digest,
            timestamp_epoch=ts,
        )
        self._rsl_chain.append(entry)
        self._git_notes_by_commit[target_commit_sha] = dsse_envelope

        if self.repo_path:
            rsl_file, notes_file = self._get_storage_paths()
            with open(rsl_file, "a", encoding="utf-8") as f:
                f.write(canonical_jcs_str(msgspec.to_builtins(entry)) + "\n")

            note_record = {
                "target_commit_sha": target_commit_sha,
                "envelope": msgspec.to_builtins(dsse_envelope),
            }
            with open(notes_file, "a", encoding="utf-8") as f:
                f.write(canonical_jcs_str(note_record) + "\n")

            # Execute genuine gittuf RSL commit-chain plumbing inside a Git repository
            git_dir = self.repo_path / ".git"
            if git_dir.exists():
                import os
                import shutil

                try:
                    gittuf_bin = shutil.which("gittuf")
                    if gittuf_bin:
                        subprocess.run(
                            [gittuf_bin, "rsl", "record", ref_name],
                            cwd=str(self.repo_path),
                            capture_output=True,
                            check=False,
                        )

                    all_rsl_bytes = rsl_file.read_bytes()
                    blob_proc = subprocess.run(
                        ["git", "hash-object", "-w", "--stdin"],
                        input=all_rsl_bytes,
                        cwd=str(self.repo_path),
                        capture_output=True,
                        check=False,
                    )
                    if blob_proc.returncode == 0:
                        blob_sha = blob_proc.stdout.decode("ascii").strip()

                        # Build a Git tree object containing `reference-state-log.jsonl`
                        mktree_input = (
                            f"100644 blob {blob_sha}\treference-state-log.jsonl\n".encode("ascii")
                        )
                        tree_proc = subprocess.run(
                            ["git", "mktree"],
                            input=mktree_input,
                            cwd=str(self.repo_path),
                            capture_output=True,
                            check=False,
                        )
                        if tree_proc.returncode != 0:
                            raise RuntimeError(
                                f"Failed to create Git tree for RSL: {tree_proc.stderr.decode('utf-8')}"
                            )
                        tree_sha = tree_proc.stdout.decode("ascii").strip()

                        # Resolve existing parent RSL commit if refs/gittuf/reference-state-log exists
                        parent_rsl_commit: str | None = None
                        rev_proc = subprocess.run(
                            [
                                "git",
                                "rev-parse",
                                "--verify",
                                "--quiet",
                                "refs/gittuf/reference-state-log^{commit}",
                            ],
                            cwd=str(self.repo_path),
                            capture_output=True,
                            check=False,
                        )
                        if rev_proc.returncode == 0 and rev_proc.stdout.strip():
                            parent_rsl_commit = rev_proc.stdout.decode("ascii").strip()

                        rsl_commit_msg = (
                            f"RSL Reference Entry\n\n"
                            f"refName: {ref_name}\n"
                            f"targetID: {target_commit_sha}\n"
                            f"ussaMerkleRoot: {ussa_merkle_root}\n"
                            f"dsseEnvelopeDigest: {env_digest}\n"
                            f"entryID: {entry_id}\n"
                        ).encode("utf-8")
                        commit_cmd = ["git", "commit-tree", tree_sha]
                        if parent_rsl_commit:
                            commit_cmd.extend(["-p", parent_rsl_commit])

                        git_env = {
                            **os.environ,
                            "GIT_AUTHOR_NAME": "VerifyCI v2 RSL",
                            "GIT_AUTHOR_EMAIL": "rsl@verifyci.local",
                            "GIT_COMMITTER_NAME": "VerifyCI v2 RSL",
                            "GIT_COMMITTER_EMAIL": "rsl@verifyci.local",
                        }
                        commit_proc = subprocess.run(
                            commit_cmd,
                            input=rsl_commit_msg,
                            cwd=str(self.repo_path),
                            env=git_env,
                            capture_output=True,
                            check=False,
                        )
                        if commit_proc.returncode != 0:
                            raise RuntimeError(
                                f"Failed to create RSL commit-tree: {commit_proc.stderr.decode('utf-8')}"
                            )
                        rsl_commit_sha = commit_proc.stdout.decode("ascii").strip()

                        update_cmd = [
                            "git",
                            "update-ref",
                            "refs/gittuf/reference-state-log",
                            rsl_commit_sha,
                        ]
                        if parent_rsl_commit:
                            update_cmd.append(parent_rsl_commit)
                        update_proc = subprocess.run(
                            update_cmd,
                            cwd=str(self.repo_path),
                            capture_output=True,
                            check=False,
                        )
                        if update_proc.returncode != 0:
                            raise RuntimeError(
                                f"Failed to update Git ref refs/gittuf/reference-state-log: {update_proc.stderr.decode('utf-8')}"
                            )

                        # Check if target_commit_sha exists in git object database
                        if not target_commit_sha.startswith("-"):
                            cat_proc = subprocess.run(
                                [
                                    "git",
                                    "cat-file",
                                    "-e",
                                    f"{target_commit_sha}^{{commit}}",
                                ],
                                cwd=str(self.repo_path),
                                capture_output=True,
                                check=False,
                            )
                            if cat_proc.returncode == 0:
                                env_json = canonical_jcs_str(msgspec.to_builtins(dsse_envelope))
                                note_proc = subprocess.run(
                                    [
                                        "git",
                                        "notes",
                                        "--ref",
                                        "refs/notes/verifyci",
                                        "add",
                                        "-f",
                                        "-F",
                                        "-",
                                        "--",
                                        target_commit_sha,
                                    ],
                                    input=env_json.encode("utf-8"),
                                    cwd=str(self.repo_path),
                                    capture_output=True,
                                    check=False,
                                )
                                if note_proc.returncode != 0:
                                    raise RuntimeError(
                                        f"Failed to record Git note for {target_commit_sha}: {note_proc.stderr.decode('utf-8')}"
                                    )
                except RuntimeError:
                    raise
                except Exception:
                    pass

        return entry

    def verify_rsl_lineage(self, expected_head_commit: str | None = None) -> bool:
        """
        Cryptographically verifies every link in the Reference State Log from genesis to head
        and checks that the current branch tip matches the latest RSL entry.
        """
        prev_id: str | None = None
        for entry in self._rsl_chain:
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
