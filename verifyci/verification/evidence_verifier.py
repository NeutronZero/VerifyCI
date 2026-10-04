from verifyci.contracts.evidence import EvidencePack
from verifyci.verification.diffmap import normalize_path


def verify_evidence_coverage(evidence_pack: EvidencePack) -> bool:
    chunks = evidence_pack.source_chunks or []
    if not chunks:
        return False
    for chunk in chunks:
        if not chunk.source_hash:
            return False
    entities = evidence_pack.entities or []
    if entities:
        pairs = {
            (normalize_path(getattr(e, 'file_path', '') or ''), getattr(e, 'source_hash', None))
            for e in entities
        }
        for chunk in chunks:
            chunk_path = normalize_path(chunk.file_path or '')
            if (chunk_path, chunk.source_hash) not in pairs:
                return False
    return True
