from __future__ import annotations

import time

from verifyci_v2.contracts.attestation import DSSEEnvelope, RSLReferenceEntry
from verifyci_v2.contracts.canonical import canonical_digest


class RSLTamperDetectedError(RuntimeError):
    """Raised when the gittuf Reference State Log hash chain or parent pointer is broken."""


class GittufRSLLedger:
    """
    Layer 7 Forge-Independent Provenance Ledger (`verifyci_v2/provenance/gittuf_rsl.py`).
    Maintains a hash-chained Reference State Log (`refs/gittuf/reference-state-log`) and
    `refs/notes/verifyci` map to defend against silent branch/tag rollbacks, force-pushes,
    and replay attacks across stateless CI runners.
    """

    def __init__(self) -> None:
        self._rsl_chain: list[RSLReferenceEntry] = []
        self._git_notes_by_commit: dict[str, DSSEEnvelope] = {}

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
                raise RSLTamperDetectedError(f"RSL entry digest tampered: {entry.entry_id}")
            prev_id = entry.entry_id

        if expected_head_commit is not None and self._rsl_chain:
            if self._rsl_chain[-1].target_commit_sha != expected_head_commit:
                raise RSLTamperDetectedError(
                    f"Rollback/force-push attack detected: RSL head is "
                    f"{self._rsl_chain[-1].target_commit_sha}, but ref points to {expected_head_commit}"
                )
        return True

    def get_note_for_commit(self, commit_sha: str) -> DSSEEnvelope | None:
        return self._git_notes_by_commit.get(commit_sha)