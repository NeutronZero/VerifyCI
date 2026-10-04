
from verifyci.contracts.entity import Entity, EntityType
from verifyci.ingestion.file_slice import slice_source
from verifyci.verification.removal import _snippet_record


def test_slice_source_basic():
    code = (
        b"def foo():\n"
        b"    print('hello')\n"
        b"    return 1\n"
    )
    slices = slice_source(code, 1, 3, max_chars=100)
    assert len(slices) == 1
    assert slices[0] == code.decode("utf-8")


def test_slice_source_oversized_newline_preservation():
    # Build 100 lines of code, ~30 chars each = ~3000 chars
    lines = [f"    line_{i} = {i} * 2\n" for i in range(100)]
    code_str = "def large_fn():\n" + "".join(lines)
    code_bytes = code_str.encode("utf-8")

    slices = slice_source(code_bytes, 1, 101, max_chars=500)
    assert len(slices) > 1

    # Invariant: trailing newline on every slice
    for s in slices[:-1]:
        assert s.endswith("\n")

    # Invariant: concatenated slices reproduce original span byte-for-byte
    reconstructed = "".join(slices)
    assert reconstructed == code_str


def test_snippet_record_slice_concatenation():
    # Verify removal provenance slice reconstruction
    lines = [f"    step_{i} = {i}\n" for i in range(100)]
    full_code = "def process():\n" + "".join(lines)
    slices = slice_source(full_code.encode("utf-8"), 1, 101, max_chars=600)
    assert len(slices) > 1

    ent = Entity(
        repository_id="repo",
        logical_entity_id="l" * 64,
        revision_entity_id="r" * 64,
        type=EntityType.FUNCTION,
        name="process",
        file_path="pkg/app.py",
        line_start=1,
        line_end=101,
        language="python",
        source_hash="h" * 64,
        revision_id="rev",
        metadata={
            "snippet": slices[0],
            "slices": slices[1:],
            "snippet_is_complete": True,
        },
    )

    rec = _snippet_record(ent)
    assert rec is not None
    assert rec.is_complete is True
    # rec.lines must contain all 101 lines!
    assert len(rec.lines) == 101
    assert rec.lines[0] == "def process():"
    assert rec.lines[100] == "    step_99 = 99"


def test_extract_entities_oversized_slices():
    from verifyci.ingestion.parser import TreeSitterParser
    from verifyci.ingestion.extractor import extract_entities

    lines = [f"    step_{i} = {i} * 100\n" for i in range(120)]
    code_str = "def big_function():\n" + "".join(lines)
    code_bytes = code_str.encode("utf-8")
    assert len(code_bytes) > 2000

    parsed = TreeSitterParser().parse("module.py", code_bytes, "python")
    ents = extract_entities(parsed, "repo", "rev")
    func_ents = [e for e in ents if e.name == "big_function"]
    assert len(func_ents) == 1
    func = func_ents[0]

    # Must have slices and be complete
    assert func.metadata.get("snippet_is_complete") is True
    slices = func.metadata.get("slices")
    assert slices is not None
    assert len(slices) >= 1

    # Reconstruction via _snippet_record reproduces all 121 lines
    rec = _snippet_record(func)
    assert rec is not None
    assert rec.is_complete is True
    assert len(rec.lines) == 121
    assert rec.lines[0] == "def big_function():"
    assert rec.lines[120] == "    step_119 = 119 * 100"

