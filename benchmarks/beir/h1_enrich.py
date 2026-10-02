"""H1-B/C/D enrichment: signature + docstring texts from the frozen tree.

Reads ONLY `corpus.jsonl` (ids + frozen `name path` texts) and git
objects at the frozen-reference tag. NEVER reads qrels, queries,
grades, config judgments, or benchmark metadata — there is no code
path here that could leak them (this module has no import of qrels).

For each doc: look up `path` at FROZEN_TAG, parse with the production
tree-sitter parser, find the first function/class node whose bare name
matches, and take:
  signature: source lines from the definition start through the header
             terminator (`:`-ending line for Python `def`/`class`;
             declarator span for C/C++),
  docstring: the leading string literal of a Python body, else "".
Anything unresolvable (unknown file, parse failure, name absent,
non-Python docstring) yields "" for that field, and build_doc_text
degrades to the frozen format — deterministic, no guessing, no tuning.

Writes scratch corpora `corpus_h1_{b,c,d}.json` (id -> enriched text)
for auditability. Frozen corpus.jsonl/qrels.jsonl/config.json and
results.json are never written.
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from verifyci.ingestion.language import detect_language  # noqa: E402
from verifyci.ingestion.parser import TreeSitterParser  # noqa: E402
from verifyci.retrieval.representation import build_doc_text  # noqa: E402

FROZEN_TAG = "v1.0.2-correctness"
VARIANTS = ("b", "c", "d")  # b: docstring, c: signature, d: both


def frozen_source(path: str) -> bytes | None:
    try:
        out = subprocess.run(
            ["git", "show", f"{FROZEN_TAG}:{path}"],
            capture_output=True, check=True,
            cwd=str(HERE.parent.parent),
        )
    except subprocess.CalledProcessError:
        return None
    return out.stdout


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _node_text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _extract(name: str, path: str) -> tuple[str, str]:
    """(signature, docstring) for bare `name` in frozen `path`; ("","")
    when unresolvable. Deterministic: first match in tree order."""
    src = frozen_source(path)
    if not src:
        return "", ""
    try:
        language = detect_language(path)
    except Exception:  # noqa: BLE001
        return "", ""
    if language not in ("python", "c", "cpp"):
        return "", ""
    try:
        parsed = TreeSitterParser().parse(path, src, language)
    except Exception:  # noqa: BLE001
        return "", ""
    if parsed.tree is None:
        return "", ""
    lines = src.decode("utf-8", "replace").splitlines()
    kinds = {"function_definition", "class_definition"}
    if language in ("c", "cpp"):
        kinds = {"function_definition", "struct_specifier",
                 "class_specifier", "declaration"}
    for node in _walk(parsed.tree.root_node):
        if node.type not in kinds:
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None:
            for child in node.children:
                if child.type == "identifier":
                    name_node = child
                    break
        if name_node is None or _node_text(name_node, src) != name:
            continue
        return _signature(node, lines), _docstring(node, src, language)
    return "", ""


def _signature(node, lines: list[str]) -> str:
    start = node.start_point[0]
    out = []
    for i in range(start, min(start + 12, len(lines))):
        out.append(lines[i].strip())
        if lines[i].rstrip().endswith(":"):
            break
    else:
        return ""
    text = " ".join(out)
    return text if text.startswith(("def ", "class ", "async def ")) else ""


def _docstring(node, source: bytes, language: str) -> str:
    if language != "python":
        return ""
    body = node.child_by_field_name("body")
    if body is None:
        return ""
    named = [c for c in body.children if c.is_named]
    if not named or named[0].type != "expression_statement":
        return ""
    expr = named[0]
    inner = [c for c in expr.children if c.is_named]
    if not inner or inner[0].type != "string":
        return ""
    return _node_text(inner[0], source).strip()


def load_frozen_corpus() -> dict[str, str]:
    corpus = {}
    for line in (HERE / "corpus.jsonl").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and "_doc" not in line:
            d = json.loads(line)
            corpus[d["id"]] = d["text"]
    return corpus


def build_variant(corpus: dict[str, str], variant: str) -> dict[str, str]:
    out = {}
    for did, text in corpus.items():
        name, _, path = text.partition(" ")
        signature, docstring = _extract(name.strip(), path.strip())
        if variant == "b":
            out[did] = build_doc_text(name.strip(), path.strip(), docstring=docstring)
        elif variant == "c":
            out[did] = build_doc_text(name.strip(), path.strip(), signature=signature)
        elif variant == "d":
            out[did] = build_doc_text(name.strip(), path.strip(),
                                      signature=signature, docstring=docstring)
        else:
            raise ValueError(variant)
    return out


def main() -> None:
    corpus = load_frozen_corpus()
    for variant in VARIANTS:
        enriched = build_variant(corpus, variant)
        n_enriched = sum(1 for did in enriched if enriched[did] != corpus[did])
        dest = HERE / f"corpus_h1_{variant}.json"
        dest.write_text(json.dumps(enriched, indent=1, sort_keys=True),
                        encoding="utf-8")
        print(f"H1-{variant.upper()}: {n_enriched}/{len(enriched)} docs enriched -> {dest.name}")


if __name__ == "__main__":
    main()
