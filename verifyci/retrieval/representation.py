"""Indexed document text for code entities (H1 retrieval campaign).

Frozen format is `name file_path` — identical to the production indexing
in `interface/commands/query.py` and the frozen BEIR corpus. Enrichment
appends the entity's own signature and/or docstring (H1-B/C/D), each as
verbatim entity-intrinsic text: never qrels, queries, labels, or
benchmark metadata. Degenerate input falls back to the frozen format,
never to empty text (empty documents are validator-rejected).
"""


def build_doc_text(name: str, file_path: str, signature: str = "",
                   docstring: str = "") -> str:
    """Document text for one entity: frozen identity prefix plus
    verbatim enrichment. Whitespace-normalized to single-line text so
    multi-line docstrings index as one document."""
    base = " ".join(p for p in (name, file_path) if p and p.strip())
    extra = " ".join(t for t in (
        " ".join(str(signature).split()),
        " ".join(str(docstring).split()),
    ) if t)
    text = f"{base} | {extra}" if extra else base
    return text if text else "unnamed"
