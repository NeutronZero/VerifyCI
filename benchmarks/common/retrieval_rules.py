"""Pure retrieval abstention rules shared between evaluation harnesses and adjudicators."""
from __future__ import annotations

import re


def evaluate_retrieval_abstention(query_text: str, ranked_doc_ids: list[str], doc_map: dict[str, str]) -> tuple[bool, str]:
    """Evaluates explicit entity-grounded abstention rule for retrieval.

    If query explicitly targets a named symbol or identifier (e.g. quantum_teleportation_...
    or _zk_nonce_...), system must verify that the requested symbol exists in candidate
    evidence before declaring an answer. If missing from all top-5 candidates, system abstains.
    """
    tokens = re.findall(r"[a-zA-Z0-9_]{10,}", query_text)
    symbols = [t for t in tokens if "_" in t and not re.match(r"^(?:dev|held_out)_repo_\d+$", t)]
    if symbols:
        for did in ranked_doc_ids[:5]:
            dtext = doc_map.get(did, "")
            if any(s in dtext for s in symbols):
                return False, "symbol_grounded"
        return True, "ungrounded_symbol_abstention"
    return False, "no_specific_symbol_claimed"
