import time

from verifyci.contracts.evidence import EvidencePack, SourceChunk, ProvenanceEntry
from verifyci.contracts.verification_ir import BlastRadiusResult


def build_evidence_pack(
    query: str,
    entities: list,
    relationships: list,
    source_chunks: list[SourceChunk],
    scores: dict[str, float],
    retrieval_methods: list[str],
    graph_revision: str,
    blast_radius: BlastRadiusResult = None,
) -> EvidencePack:
    provenance = []
    for chunk in source_chunks:
        provenance.append(ProvenanceEntry(
            entry_id=f"prov_{chunk.chunk_id}",
            entity_id=None,
            file_path=chunk.file_path,
            line_start=chunk.line_start,
            line_end=chunk.line_end,
            source_hash=chunk.source_hash,
            revision_id=graph_revision,
        ))

    return EvidencePack(
        query=query,
        entities=entities,
        relationships=relationships,
        source_chunks=source_chunks,
        provenance=provenance,
        scores=scores,
        retrieval_methods=retrieval_methods,
        retrieval_timestamp=time.time(),
        graph_revision=graph_revision,
        blast_radius=blast_radius,
    )
