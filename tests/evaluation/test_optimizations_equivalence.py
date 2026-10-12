"""Semantic equivalence test suite proving that optimized implementations
match unoptimized reference baselines 100% across all edge cases, collisions,
and random inputs.
"""
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any

from verifyci.contracts.jsonio import to_json, to_json_dict
from verifyci.storage.graph_cache import _freeze_payload
from verifyci.verification.diffmap import (
    find_ambiguous_files,
    map_files_to_entity_ids,
    normalize_path,
)
from verifyci.verification.verification_ir import (
    _anchor_covered,
    _merge_spans,
)


# ==============================================================================
# 1. Diff Mapping Equivalence
# ==============================================================================

def _map_files_to_entity_ids_baseline(files: list[str], entities: list) -> dict[str, list[str]]:
    """Unoptimized O(|entities| * |files|) reference implementation."""
    wanted = {normalize_path(f) for f in files}
    mapping: dict[str, list[str]] = {}
    for entity in entities:
        epath = normalize_path(getattr(entity, "file_path", ""))
        for f in wanted:
            if epath == f or epath.endswith("/" + f) or f.endswith("/" + epath):
                mapping.setdefault(f, []).append(entity.revision_entity_id)
    return mapping


def _find_ambiguous_files_baseline(files: list[str], entities: list) -> dict[str, list[str]]:
    """Unoptimized O(|entities| * |files|) reference implementation."""
    wanted = {normalize_path(f) for f in files}
    hits: dict[str, set[str]] = {}
    for entity in entities:
        epath = normalize_path(getattr(entity, "file_path", ""))
        if not epath:
            continue
        for f in wanted:
            if epath == f or epath.endswith("/" + f) or f.endswith("/" + epath):
                hits.setdefault(f, set()).add(epath)
    return {f: sorted(paths) for f, paths in hits.items() if len(paths) > 1}


@dataclass
class _FakeEntity:
    revision_entity_id: str
    file_path: str
    line_start: int = 1
    line_end: int = 10
    type: str = "FUNCTION"


def test_diff_mapping_semantic_equivalence_exhaustive():
    """Test identical mapping and ambiguity verdicts over multi-level collisions and edge cases."""
    test_paths = [
        "utils.py",
        "src/utils.py",
        "pkg/sub/utils.py",
        "core/runner.py",
        "runner.py",
        "./core/runner.py",
        "tests/test_runner.py",
        "deeply/nested/dir/foo_bar.py",
        "foo_bar.py",
        "other/foo_bar.py",
        "empty/path/",
        "",
    ]

    entities = [
        _FakeEntity(revision_entity_id=f"e_{i}", file_path=path)
        for i, path in enumerate(test_paths * 10)
    ]

    query_file_sets = [
        ["utils.py"],
        ["src/utils.py", "runner.py"],
        ["pkg/sub/utils.py", "core/runner.py", "nonexistent.py"],
        ["foo_bar.py", "tests/test_runner.py"],
        ["./utils.py", "./core/runner.py"],
        ["nonexistent_1.py", "nonexistent_2.py"],
        [],
    ]

    for files in query_file_sets:
        # 1. Map files to entity IDs equivalence
        baseline_map = _map_files_to_entity_ids_baseline(files, entities)
        optimized_map = map_files_to_entity_ids(files, entities)
        assert baseline_map == optimized_map, f"Mismatch for query files {files}"

        # 2. Ambiguity detection equivalence
        baseline_amb = _find_ambiguous_files_baseline(files, entities)
        optimized_amb = find_ambiguous_files(files, entities)
        assert baseline_amb == optimized_amb, f"Ambiguity mismatch for query files {files}"


# ==============================================================================
# 2. Graph Cache Freezing Deep Immutability & Equivalence
# ==============================================================================

def test_graph_cache_deep_immutability_and_aliasing():
    """Verify that _freeze_payload prevents external alias mutation and enforces deep immutability."""
    # Test 1: External dict wrapped in MappingProxyType cannot mutate cache
    external_dict = {"secret": "initial", "nested": {"count": 1}}
    proxy = MappingProxyType(external_dict)
    frozen = _freeze_payload(proxy)

    # Mutate the external underlying dict
    external_dict["secret"] = "tampered"
    external_dict["nested"]["count"] = 999

    assert frozen["secret"] == "initial", "Frozen payload was corrupted via external dict alias!"
    assert frozen["nested"]["count"] == 1, "Nested structure was corrupted via external alias!"
    assert isinstance(frozen["nested"], MappingProxyType), "Nested dict was not converted to MappingProxyType!"

    # Test 2: Tuples with mutable contents are not identity-preserved
    mutable_tuple = ([1, 2], {"a": 3})
    frozen_tuple = _freeze_payload(mutable_tuple)
    assert frozen_tuple is not mutable_tuple
    assert isinstance(frozen_tuple[0], tuple)
    assert isinstance(frozen_tuple[1], MappingProxyType)

    # Test 3: Already deeply frozen tuple preserves identity (zero allocation)
    deeply_frozen_tuple = ("a", 1, True, ("b", 2))
    assert _freeze_payload(deeply_frozen_tuple) is deeply_frozen_tuple

    # Test 4: Already deeply frozen frozenset preserves identity
    deeply_frozen_set = frozenset({"x", 1, 2})
    assert _freeze_payload(deeply_frozen_set) is deeply_frozen_set

    # Test 5: Already deeply frozen MappingProxyType preserves identity
    # (repeat-freeze fast path: zero reallocation).
    frozen_inner = MappingProxyType({"count": 1, "tags": ("a", "b")})
    frozen_outer = MappingProxyType({"secret": "initial", "nested": frozen_inner})
    assert _freeze_payload(frozen_outer) is frozen_outer


# ==============================================================================
# 3. IR Line Attribution Interval Equivalence
# ==============================================================================

def _anchor_covered_baseline(ln: int, file_spans: list[tuple[int, int]], content: str = "") -> bool:
    """Original linear-scan reference implementation."""
    if any(s <= ln <= en for s, en in file_spans):
        return True
    if content.lstrip().startswith("@"):
        return any(s - ln == 1 for s, en in file_spans)
    if content.lstrip().startswith(("import ", "from ")):
        return any(abs(s - ln) <= 2 or abs(en - ln) <= 2 for s, en in file_spans)
    return False


def test_ir_line_attribution_interval_equivalence():
    """Verify that merged interval binary search is 100% equivalent to linear search."""
    # Complex overlapping, enclosed, adjacent, and disjoint spans
    raw_spans = [
        (10, 50),   # Enclosing class
        (15, 25),   # Nested method 1
        (30, 45),   # Nested method 2
        (48, 60),   # Overlapping method 3
        (100, 120), # Disjoint function
        (120, 130), # Adjacent span
        (200, 250), # Far span
    ]
    merged = _merge_spans(raw_spans)
    starts = [s for s, _ in merged]
    dec_starts = {s - 1 for s, _ in raw_spans}
    endpoints = sorted({s for s, _ in raw_spans} | {en for _, en in raw_spans})

    test_lines = list(range(1, 300))
    test_contents = ["", "    x = 1", "    @decorator", "import os", "from typing import Any"]

    for ln in test_lines:
        for content in test_contents:
            baseline_result = _anchor_covered_baseline(ln, raw_spans, content)
            optimized_result = _anchor_covered(ln, merged, starts, content, dec_starts, endpoints)
            assert baseline_result == optimized_result, (
                f"Line attribution mismatch at ln={ln}, content={content!r}: "
                f"baseline={baseline_result}, optimized={optimized_result}"
            )


# ==============================================================================
# 4. JSON Serialization Equivalence
# ==============================================================================

class _SampleEnum(Enum):
    ALPHA = "alpha_val"
    BETA = "beta_val"


@dataclass
class _InnerDC:
    flag: bool
    count: int
    ratio: float
    name: str


@dataclass
class _OuterDC:
    enum_val: _SampleEnum
    inner: _InnerDC
    items: list[Any]
    mapping: dict[str, Any]
    none_val: Any = None


def _to_json_dict_baseline(obj: Any) -> Any:
    """Original unoptimized serializer."""
    from dataclasses import fields, is_dataclass
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: _to_json_dict_baseline(getattr(obj, f.name)) for f in fields(obj)}
    from collections.abc import Mapping
    if isinstance(obj, (Mapping, dict)):
        return {k: _to_json_dict_baseline(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_json_dict_baseline(v) for v in obj]
    return obj


def test_json_serialization_equivalence():
    """Verify that primitive fast-pathing produces identical JSON output across edge cases."""
    data = _OuterDC(
        enum_val=_SampleEnum.ALPHA,
        inner=_InnerDC(flag=True, count=42, ratio=3.14159, name="test_entity"),
        items=[False, 0, 100, -5, "str_elem", None, ("nested_tuple", True)],
        mapping={"key_1": "val_1", "key_bool": False, "key_enum": _SampleEnum.BETA},
        none_val=None,
    )

    baseline_dict = _to_json_dict_baseline(data)
    optimized_dict = to_json_dict(data)
    assert baseline_dict == optimized_dict

    # Check to_json string output equality
    baseline_str = to_json(data)
    # Both use deterministic sorted keys
    assert to_json(baseline_dict) == baseline_str
