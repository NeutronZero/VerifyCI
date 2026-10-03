"""Contract 5: Execution Witness extraction and association rules.

Associates test functions in TEST_SUITE diffs with changed production entities
or files in CODE_CORE:
1. Probe metadata (explicit annotations)
2. Direct AST reference / imports
3. Fallback naming convention (module-level correspondence)
4. Ambiguous / unlinked tests become General Regression Witnesses
"""
import re
import uuid

from verifyci.contracts.verification_ir import ExecutionWitness
from verifyci.verification.diffmap import normalize_path, parse_unified_diff

_DEF_TEST_RE = re.compile(r"^[+ ]\s*def\s+(test_[a-zA-Z0-9_]+)\s*\(")
_PROBE_META_RE = re.compile(r"test_probe\s*[:=]\s*[\"']?([a-zA-Z0-9_./]+)[\"']?")


def _module_stem(path: str) -> str:
    norm = normalize_path(path)
    for prefix in ("verifyci/", "src/", "tests/", "lib/"):
        if norm.startswith(prefix):
            norm = norm[len(prefix):]
            break
    # strip test_ prefix from filename
    parts = norm.split("/")
    if parts[-1].startswith("test_"):
        parts[-1] = parts[-1][5:]
    elif parts[-1].endswith("_test.py"):
        parts[-1] = parts[-1][:-8] + ".py"
    return "/".join(parts)


def extract_execution_witnesses(
    diff: str | None,
    code_files: list[str],
    test_files: list[str],
    entities: list | None = None,
) -> list[ExecutionWitness]:
    """Extract and associate execution witnesses from TEST_SUITE changes."""
    if not diff or not test_files:
        return []

    parsed = parse_unified_diff(diff)
    diff_by_file = {normalize_path(f.path): f for f in parsed}

    code_stems = {normalize_path(cf): _module_stem(cf) for cf in code_files}

    witnesses: list[ExecutionWitness] = []

    for tf in test_files:
        norm_tf = normalize_path(tf)
        fd = diff_by_file.get(norm_tf)
        test_funcs: list[str] = []
        raw_lines: list[str] = []
        probe_target: str | None = None

        if fd:
            for h in fd.hunks:
                for line in h.lines:
                    raw_lines.append(line)
                    m_fn = _DEF_TEST_RE.match(line)
                    if m_fn:
                        fn_name = m_fn.group(1)
                        if fn_name not in test_funcs:
                            test_funcs.append(fn_name)
                    m_probe = _PROBE_META_RE.search(line)
                    if m_probe:
                        probe_target = m_probe.group(1)

        # Association resolution
        target_file: str | None = None
        association_method = "general_regression"
        is_general = True

        # 1. Probe metadata
        if probe_target:
            for cf in code_files:
                if probe_target in cf or cf in probe_target:
                    target_file = cf
                    association_method = "probe_metadata"
                    is_general = False
                    break

        # 2. Direct AST reference / imports
        if is_general and code_files:
            matches = set()
            for line in raw_lines:
                for cf in code_files:
                    stem = code_stems[cf].replace(".py", "")
                    bare = stem.split("/")[-1]
                    if not bare:
                        continue
                    if (
                        re.search(rf"\b(import\s+[\w.]*{re.escape(bare)}|from\s+[\w.]*{re.escape(bare)}\s+import)\b", line)
                        or re.search(rf"\b{re.escape(bare)}\s*\(", line)
                        or re.search(rf"\b{re.escape(bare)}\.\w+", line)
                    ):
                        matches.add(cf)
            if len(matches) == 1:
                target_file = next(iter(matches))
                association_method = "direct_ast"
                is_general = False

        # 3. Fallback naming convention
        if is_general and code_files:
            tf_stem = _module_stem(norm_tf)
            matches = [cf for cf, cs in code_stems.items() if cs == tf_stem or cs.endswith("/" + tf_stem) or tf_stem.endswith("/" + cs)]
            if len(matches) == 1:
                target_file = matches[0]
                association_method = "naming_convention"
                is_general = False

        # If no specific test function, emit single witness for file
        funcs_to_emit = test_funcs if test_funcs else [None]
        for fn in funcs_to_emit:
            witness_id = f"wit_{uuid.uuid4().hex[:8]}"
            target_eid = None
            if target_file and entities and fn:
                norm_tgt = normalize_path(target_file)
                fn_stem = fn[5:] if fn.startswith("test_") else fn
                for e in entities:
                    e_path = normalize_path(getattr(e, "file_path", "") or "")
                    if e_path == norm_tgt or norm_tgt.endswith("/" + e_path) or e_path.endswith("/" + norm_tgt):
                        if getattr(e, "name", "") == fn_stem:
                            target_eid = getattr(e, "revision_entity_id", None)
                            break
            witnesses.append(ExecutionWitness(
                witness_id=witness_id,
                test_file=tf,
                test_function=fn,
                target_file=target_file,
                target_entity_id=target_eid,
                is_general_regression=is_general,
                association_method=association_method,
            ))

    return witnesses
