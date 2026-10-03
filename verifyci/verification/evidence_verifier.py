from verifyci.contracts.evidence import EvidencePack


def verify_evidence_coverage(evidence_pack: EvidencePack) -> bool:
    chunks = evidence_pack.source_chunks or []
    if not chunks:
        return False
    for chunk in chunks:
        if not chunk.source_hash:
            return False
    entities = evidence_pack.entities or []
    if entities:
        pairs = {(getattr(e, 'file_path', None), getattr(e, 'source_hash', None)) for e in entities}
        for chunk in chunks:
            if (chunk.file_path, chunk.source_hash) not in pairs:
                return False
    return True
