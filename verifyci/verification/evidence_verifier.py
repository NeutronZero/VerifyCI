from verifyci.contracts.evidence import EvidencePack


def verify_evidence_coverage(evidence_pack: EvidencePack) -> bool:
    if not evidence_pack.entities and not evidence_pack.source_chunks:
        return False
    for chunk in evidence_pack.source_chunks:
        if not chunk.source_hash:
            return False
    return True
