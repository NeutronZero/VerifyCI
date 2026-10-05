"""Contract 4: Deletion Verification (C4).

Implements the frozen three-class deletion verification taxonomy:
- Class 1: Dead code / unreferenced entity removal
- Class 2: Refactoring / intra-entity replacement
- Class 3: Behavioral / guard deletion (fail closed unless formal signed waiver)

Requirements:
- 100% deletion provenance verification (preserves C3 semantics)
- CPG entity grounding and zero surviving callers (Class 1)
- Enclosing entity continuity, signature compatibility, and Execution Witness (Class 2)
- Security / guard deletion detection with signed waiver bypass (Class 3)
"""
import ast
from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any

from verifyci.contracts.verification_ir import ExecutionWitness, SignedIntentWaiver
from verifyci.verification.diffmap import (
    normalize_path,
    parse_unified_diff,
)
from verifyci.verification.removal import _classify_removed, _is_code


class DeletionClass(str, Enum):
    CLASS_1_DEAD_CODE = "class_1_dead_code"
    CLASS_2_REFACTORING = "class_2_refactoring"
    CLASS_3_GUARD_REMOVAL = "class_3_guard_removal"


@dataclass(frozen=True)
class DeletionHunkVerdict:
    file_path: str
    old_start: int
    deletion_class: DeletionClass
    passed: bool
    status: str  # "PASS", "INCONCLUSIVE", "FAIL"
    reasoning: str
    details: dict[str, Any] = field(default_factory=dict)


_ASSERT_RE = re.compile(r"^\s*assert\b")
_GUARD_KEYWORD_RE = re.compile(
    r"\b(raise\s+(PermissionError|PermissionDenied|AuthenticationError|NotAuthenticated|SecurityError|Unauthorized|Forbidden)|"
    r"check_permission|verify_token|validate_credentials|"
    r"require_auth|login_required|permission_required|"
    r"denied|unauthori\w*|unauthen\w*|forbidden|PermissionDenied|NotAuthenticated|"
    r"abort\s*\(\s*40[13]|status\s*\(\s*40[13]|return\s+40[13]|"
    r"throw)\b|"
    r"@(?:require_auth|login_required|permission_required|guard)\b|"
    r"!\s*auth\w*",
    re.IGNORECASE,
)


def _is_guard_line(line: str) -> bool:
    stripped = line.strip()
    if _ASSERT_RE.match(stripped):
        return True
    if _GUARD_KEYWORD_RE.search(stripped):
        return True
    return False


def _guard_identity(line: str) -> str | None:
    """Normalized guard predicate for one line (C-1 same-guard comparison).

    `raise PermissionError` -> `raise:permissionerror`, `abort(403)` ->
    `abort:403`, `@require_auth` -> `deco:require_auth`, `assert x` ->
    `assert`, `check_permission(u)` -> `kw:check_permission`. Two lines
    share a predicate only when the callee/exception/status code matches:
    swapping one guard for another (`PermissionError` -> `ValueError`)
    is a NEW guard, not preservation. None for non-guard lines.
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    m = re.search(r"\braise\s+([\w.]+)", s)
    if m:
        return "raise:" + m.group(1).split(".")[-1].lower()
    m = re.search(r"\babort\s*\(\s*(\d+)", s, re.IGNORECASE)
    if m:
        return "abort:" + m.group(1)
    m = re.search(r"\bstatus\s*\(\s*(\d+)", s, re.IGNORECASE)
    if m:
        return "status:" + m.group(1)
    m = re.search(r"\breturn\b[^#]*\b(40[13])\b", s)
    if m:
        return "return:" + m.group(1)
    m = re.search(r"\bthrow\s+([\w.]+)", s, re.IGNORECASE)
    if m:
        return "throw:" + m.group(1).split(".")[-1].lower()
    if re.search(r"\bthrow\b", s, re.IGNORECASE):
        return "throw"
    m = re.search(r"@([\w.]+)", s)
    if m and _is_guard_line(line):
        return "deco:" + m.group(1).split(".")[-1].lower()
    if re.match(r"assert\b", s):
        return "assert"
    m = _GUARD_KEYWORD_RE.search(s)
    if m:
        return "kw:" + m.group(0).strip().lower()
    if re.search(r"\bassert\b", s):
        return "assert"
    return None


def _is_guard_preserved_in_additions(
    added_lines: list[str],
    removed_guard_lines: list[str] | None = None,
) -> bool:
    """True when the additions preserve the removed guard predicate.

    With `removed_guard_lines` (the Class-3 call site): the SAME guard
    must reappear — normalized callee/exception/code equality via
    `_guard_identity`. Any-`raise` no longer counts: replacing
    `raise PermissionError` with `raise ValueError` fails closed.
    Without it (legacy single-arg callers): any guard or any
    raise/assert counts, preserving the previously pinned behavior.
    """
    if removed_guard_lines is None:
        for line in added_lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _is_guard_line(line):
                return True
            if re.search(r"\b(raise\s+\w+|assert\b)", stripped):
                return True
        return False
    removed_keys = {
        _guard_identity(gl) or ("raw:" + gl.strip().lower())
        for gl in removed_guard_lines
    }
    if not removed_keys:
        return False
    for line in added_lines:
        if line.strip().startswith("#"):
            continue
        key = _guard_identity(line) or ("raw:" + line.strip().lower())
        if key in removed_keys:
            return True
    return False


def _def_line_matches(line: str, name: str) -> bool:
    """Declaration-line match beyond Python (TS/JS/C/C++ Contract 4).

    Python `def/class` only caught renames; TS `function f(`, `const f = (`,
    and C/C++ declarators `int f(` fell through to `no_code_deletion_hunks`
    PASS. Liberal by design: callers gate on the entity name, so a
    looser match only routes to scrutiny, never to a pass.
    """
    if re.search(rf"\b(def|class|function|fn)\s+{re.escape(name)}\s*(\(|:|\{{)", line):
        return True
    if re.search(rf"\b(const|let|var)\s+{re.escape(name)}\s*=", line):
        return True
    if re.search(rf"(?<![\w:]){re.escape(name)}\s*\([^;{{}}]*\)\s*(?:const\s*)?[\{{;]", line):
        return True
    return False


def _looks_like_def(line: str) -> bool:
    t = line.strip()
    if t.startswith(("def ", "async def ", "class ")):
        return True
    if re.match(r"(?:export\s+)?(?:async\s+)?(?:function\s+\w|class\s+\w|(?:const|let|var)\s+\w+\s*=)", t):
        return True
    return bool(re.search(r"(?<![\w:])[\w:~]+\s*\([^;{}]*\)\s*(?:const\s*)?[{;]\s*$", t))


def _matches_waiver(
    removed_guard_lines: list[str],
    file_path: str,
    waivers: tuple[SignedIntentWaiver, ...] | list[SignedIntentWaiver],
) -> SignedIntentWaiver | None:
    norm_file = normalize_path(file_path)
    for w in waivers:
        if not w.valid or not getattr(w, "verify_signature", lambda: bool(w.signature))():
            continue
        t = w.target.strip()
        if not t:
            continue  # empty target must not match everything
        # Class-3 waiver contract: a bare file target (`src/foo.py`)
        # would waive EVERY guard removed file-wide, so it never matches
        # here (fail closed). Waive with a `file:symbol` target (below)
        # or a symbol / exact-guard-line target (after).
        if ":" not in t:
            norm_t = normalize_path(t)
            if norm_file == norm_t or norm_file.endswith("/" + norm_t.lstrip("/")):
                continue  # file-only target waives nothing file-wide
        # V-11: Match qualified file:symbol target
        if ":" in t:
            f_part, s_part = t.split(":", 1)
            norm_f = normalize_path(f_part.strip())
            s_clean = s_part.strip()
            if norm_file == norm_f or norm_file.endswith("/" + norm_f.lstrip("/")):
                pat = re.compile(r"(?<![\w.])" + re.escape(s_clean) + r"(?![\w])")
                for gl in removed_guard_lines:
                    if pat.search(gl) or gl.strip() == s_clean:
                        return w
            continue

        # V-11: Exact symbol token match (prevent loose substring false matches like "auth" in "require_auth")
        # Why token form: catches guard shapes like `from auth import ...` without matching `authenticate`.
        pat = re.compile(r"(?<![\w.])" + re.escape(t) + r"(?![\w])")
        for gl in removed_guard_lines:
            if pat.search(gl) or gl.strip() == t:
                return w
    return None


def _parse_params_from_def(def_line: str) -> list[tuple[str, bool]] | None:
    """Return list of (arg_name, has_default)."""
    try:
        stmt = def_line.strip()
        if not stmt.endswith(":"):
            stmt += ":"
        mod = ast.parse(stmt + "\n    pass\n")
        # NOTE (defensive): `not mod.body` is unreachable — stmt is never
        # empty here (":" at minimum, which raises above), and any valid
        # parse has a body. Kept so a future parser change fails safe.
        if not mod.body:
            return None
        fn = mod.body[0]
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            pos_args = [a.arg for a in getattr(fn.args, "posonlyargs", [])] + [a.arg for a in fn.args.args]
            num_defaults = len(fn.args.defaults)
            num_req = len(pos_args) - num_defaults
            defaults_flags = [False] * num_req + [True] * num_defaults
            params = list(zip(pos_args, defaults_flags, strict=False))
            # Also capture keyword-only arguments
            for arg, default in zip(fn.args.kwonlyargs, fn.args.kw_defaults, strict=False):
                params.append((arg.arg, default is not None))
            return params
    except Exception:
        pass
    return None


def _check_signature_compatibility(old_def_line: str, new_def_line: str) -> tuple[bool, str]:
    old_params = _parse_params_from_def(old_def_line)
    new_params = _parse_params_from_def(new_def_line)
    if old_params is None or new_params is None:
        if old_def_line.strip() == new_def_line.strip():
            return True, ""
        return False, "unparseable_signature_change"

    old_req = [name for name, has_def in old_params if not has_def]
    new_req = [name for name, has_def in new_params if not has_def]

    if len(new_req) > len(old_req):
        return False, f"new_signature_requires_more_args:{len(new_req)}>{len(old_req)}"

    for i, (old_name, _) in enumerate(old_params):
        if i < len(new_params):
            new_name, new_has_def = new_params[i]
            if not new_has_def and old_name != new_name:
                return False, f"param_position_mismatch:{old_name}->{new_name}"

    new_all_names = {name for name, _ in new_params}
    for old_name, has_def in old_params:
        if old_name not in new_all_names:
            if not has_def:
                return False, f"required_param_removed:{old_name}"
            return False, f"optional_param_removed:{old_name}"

    return True, ""


def _find_surviving_callers(
    target_entity: Any,
    graph: Any,
    node_map: dict | None,
    entities: list,
    diff_files: set[str],
) -> list[str]:
    """Find callers/references in the base CPG that survive unedited in the diff."""
    if graph is None or not node_map:
        return []
    target_id = getattr(target_entity, "revision_entity_id", None)
    if not target_id:
        return []
    idx = node_map.get(target_id)
    if idx is None:
        return []

    preds_fn = getattr(graph, "predecessors", None)
    if not callable(preds_fn):
        return []

    from verifyci.graph.traverse import as_index
    try:
        raw_preds = list(preds_fn(idx))
    except Exception:
        return []

    surviving: list[str] = []
    by_idx: dict[int, Any] = {}
    for e in entities:
        eid = getattr(e, "revision_entity_id", None)
        if eid and eid in node_map:
            by_idx[node_map[eid]] = e

    for p in raw_preds:
        pidx = as_index(p, node_map) if not isinstance(p, int) else p
        if pidx is None:
            continue
        caller_entity = by_idx.get(pidx)
        if caller_entity is None:
            caller_entity = p
        caller_file = getattr(caller_entity, "file_path", None)
        caller_name = getattr(caller_entity, "name", str(pidx))
        if caller_file:
            norm_cf = normalize_path(caller_file)
            if norm_cf not in diff_files and caller_file not in diff_files:
                surviving.append(f"{caller_name} ({caller_file})")
        else:
            surviving.append(str(caller_name))

    return surviving


def _has_associated_witness(
    file_path: str,
    entity: Any,
    witnesses: tuple[ExecutionWitness, ...] | list[ExecutionWitness],
) -> bool:
    """Check if any witness corroborates changes to entity or file_path.

    Scoping semantics:
    - If a witness specifically targets an entity (w.target_entity_id is not None),
      it matches ONLY when w.target_entity_id == entity.revision_entity_id. It does
      NOT fall back to a file-level match, preserving entity-level scoping in
      multi-entity files.
    - If a witness targets a file generally (w.target_entity_id is None, w.target_file set),
      it corroborates any entity in that file.
    - General regression witnesses (w.is_general_regression is True) cannot corroborate
      Class 2 refactorings (Contract 5).
    """
    norm_file = normalize_path(file_path)
    eid = getattr(entity, "revision_entity_id", None)
    for w in witnesses:
        if w.is_general_regression:
            continue
        if w.target_entity_id:
            if eid and w.target_entity_id == eid:
                return True
            continue
        if w.target_file:
            norm_target = normalize_path(w.target_file)
            if norm_target == norm_file or norm_file.endswith("/" + norm_target) or norm_target.endswith("/" + norm_file):
                return True
    return False


def _check_hunk_provenance(
    file_path: str, hunk: Any, covering: list
) -> tuple[bool, bool]:
    old_ln = hunk.old_start
    hunk_fabricated = False
    hunk_unverified = False
    for line in hunk.lines:
        if line.startswith("+") or line.startswith("\\"):
            continue
        if not line.startswith("-"):
            old_ln += 1
            continue
        content = line[1:]
        c_status = _classify_removed(file_path, old_ln, content, covering)
        if c_status == "fabricated":
            hunk_fabricated = True
            break
        elif c_status != "verified":
            hunk_unverified = True
        old_ln += 1
    return hunk_fabricated, hunk_unverified


def _verify_class_3_guard_hunk(
    file_path: str,
    hunk: Any,
    guard_lines: list[str],
    plus_lines: list[str],
    waivers: tuple[SignedIntentWaiver, ...] | list[SignedIntentWaiver],
) -> DeletionHunkVerdict | None:
    if not guard_lines or _is_guard_preserved_in_additions(plus_lines, guard_lines):
        return None
    matched_waiver = _matches_waiver(guard_lines, file_path, waivers)
    if matched_waiver:
        from verifyci.env import get_env as _get_env
        _posture = ("keyed" if (_get_env("WAIVER_KEYS") or _get_env("WAIVER_PUBLIC_KEYS"))
                    else "bearer-opt-in")
        return DeletionHunkVerdict(
            file_path=file_path,
            old_start=hunk.old_start,
            deletion_class=DeletionClass.CLASS_3_GUARD_REMOVAL,
            passed=True,
            status="PASS",
            reasoning=(f"class_3_guard_removal_waived:"
                       f"{matched_waiver.waiver_id}:{_posture}"),
        )
    return DeletionHunkVerdict(
        file_path=file_path,
        old_start=hunk.old_start,
        deletion_class=DeletionClass.CLASS_3_GUARD_REMOVAL,
        passed=False,
        status="FAIL",
        reasoning=f"class_3_guard_removal_without_waiver:{file_path}:{hunk.old_start}",
    )


def _verify_class_1_dead_code_hunk(
    file_path: str,
    hunk: Any,
    deleted_entity: Any,
    graph: Any,
    node_map: dict | None,
    code_entities: list,
    diff_files: set[str],
) -> DeletionHunkVerdict:
    surviving = _find_surviving_callers(deleted_entity, graph, node_map, code_entities, diff_files)
    if surviving:
        return DeletionHunkVerdict(
            file_path=file_path,
            old_start=hunk.old_start,
            deletion_class=DeletionClass.CLASS_1_DEAD_CODE,
            passed=False,
            status="INCONCLUSIVE",
            reasoning=f"surviving_callers_detected:{','.join(surviving[:3])}",
        )
    return DeletionHunkVerdict(
        file_path=file_path,
        old_start=hunk.old_start,
        deletion_class=DeletionClass.CLASS_1_DEAD_CODE,
        passed=True,
        status="PASS",
        reasoning=f"class_1_dead_code_verified:{deleted_entity.name}",
    )


def _verify_class_2_refactoring_hunk(
    file_path: str,
    hunk: Any,
    enclosing: Any,
    minus_lines: list[str],
    plus_lines: list[str],
    witnesses: tuple[ExecutionWitness, ...] | list[ExecutionWitness],
) -> DeletionHunkVerdict:
    old_defs = [ml for ml in minus_lines if _looks_like_def(ml)]
    new_defs = [pl for pl in plus_lines if _looks_like_def(pl)]

    if old_defs and not new_defs:
        return DeletionHunkVerdict(
            file_path=file_path,
            old_start=hunk.old_start,
            deletion_class=DeletionClass.CLASS_2_REFACTORING,
            passed=False,
            status="INCONCLUSIVE",
            reasoning=f"entity_continuity_broken:{enclosing.name}",
        )

    if old_defs and new_defs:
        compat, sig_err = _check_signature_compatibility(old_defs[0], new_defs[0])
        if not compat:
            return DeletionHunkVerdict(
                file_path=file_path,
                old_start=hunk.old_start,
                deletion_class=DeletionClass.CLASS_2_REFACTORING,
                passed=False,
                status="INCONCLUSIVE",
                reasoning=f"signature_incompatible:{sig_err}",
            )

    if not _has_associated_witness(file_path, enclosing, witnesses):
        return DeletionHunkVerdict(
            file_path=file_path,
            old_start=hunk.old_start,
            deletion_class=DeletionClass.CLASS_2_REFACTORING,
            passed=False,
            status="INCONCLUSIVE",
            reasoning=f"missing_execution_witness:{enclosing.name}",
        )

    return DeletionHunkVerdict(
        file_path=file_path,
        old_start=hunk.old_start,
        deletion_class=DeletionClass.CLASS_2_REFACTORING,
        passed=True,
        status="PASS",
        reasoning=f"class_2_refactoring_verified:{enclosing.name}",
    )


def verify_deletion_hunks(
    diff: str | None,
    code_files: list[str],
    entities: list | None,
    graph: Any = None,
    node_map: dict | None = None,
    witnesses: tuple[ExecutionWitness, ...] | list[ExecutionWitness] = (),
    waivers: tuple[SignedIntentWaiver, ...] | list[SignedIntentWaiver] = (),
) -> list[DeletionHunkVerdict]:
    """Verify each deletion hunk in CODE_CORE against the three frozen classes."""
    if not diff:
        return []

    parsed = parse_unified_diff(diff)
    norm_code = {normalize_path(f) for f in code_files}
    diff_files = {normalize_path(f.path) for f in parsed}

    code_entities = [e for e in (entities or []) if _is_code(e)]
    verdicts: list[DeletionHunkVerdict] = []

    for f in parsed:
        norm_path = normalize_path(f.path)
        if norm_path not in norm_code and f.path not in code_files:
            continue

        covering = [
            e for e in code_entities
            if normalize_path(getattr(e, "file_path", "") or "") == norm_path
            or norm_path.endswith("/" + normalize_path(getattr(e, "file_path", "") or ""))
            or normalize_path(getattr(e, "file_path", "") or "").endswith("/" + norm_path)
        ]

        for hunk in f.hunks:
            minus_lines = [b[1:] for b in hunk.lines if b.startswith("-")]
            plus_lines = [b[1:] for b in hunk.lines if b.startswith("+")]

            if not minus_lines:
                continue
            is_net_deletion = (len(minus_lines) > len(plus_lines)) or (hunk.old_count > hunk.new_count)
            guard_lines = [ml for ml in minus_lines if _is_guard_line(ml)]
            old_defs = [ml for ml in minus_lines if _looks_like_def(ml)]

            if not is_net_deletion and not guard_lines and not old_defs:
                continue

            hunk_fabricated, hunk_unverified = _check_hunk_provenance(f.path, hunk, covering)
            if hunk_fabricated:
                verdicts.append(DeletionHunkVerdict(
                    file_path=f.path,
                    old_start=hunk.old_start,
                    deletion_class=DeletionClass.CLASS_2_REFACTORING if not is_net_deletion else DeletionClass.CLASS_1_DEAD_CODE,
                    passed=False,
                    status="FAIL",
                    reasoning=f"fabricated_deletion_provenance:{f.path}:{hunk.old_start}",
                ))
                continue

            if hunk_unverified:
                verdicts.append(DeletionHunkVerdict(
                    file_path=f.path,
                    old_start=hunk.old_start,
                    deletion_class=DeletionClass.CLASS_2_REFACTORING if not is_net_deletion else DeletionClass.CLASS_1_DEAD_CODE,
                    passed=False,
                    status="INCONCLUSIVE",
                    reasoning=f"unverified_deletion_provenance:{f.path}:{hunk.old_start}",
                ))
                continue

            # Provenance verified: check Class 3 guard removal
            c3_verdict = _verify_class_3_guard_hunk(f.path, hunk, guard_lines, plus_lines, waivers)
            if c3_verdict is not None:
                verdicts.append(c3_verdict)
                continue

            # Overlapping entities
            h_end = hunk.old_start + max(1, hunk.old_count) - 1
            overlapping_entities = [
                e for e in covering
                if not (getattr(e, "line_end", 1) < hunk.old_start or getattr(e, "line_start", 1) > h_end)
            ]

            if not overlapping_entities:
                verdicts.append(DeletionHunkVerdict(
                    file_path=f.path,
                    old_start=hunk.old_start,
                    deletion_class=DeletionClass.CLASS_1_DEAD_CODE,
                    passed=False,
                    status="INCONCLUSIVE",
                    reasoning=f"deletion_outside_entity_spans:{f.path}:{hunk.old_start}",
                ))
                continue

            deleted_entity = None
            for e in overlapping_entities:
                e_name = getattr(e, "name", "")
                if not e_name:
                    continue
                def_removed = any(_def_line_matches(ml, e_name) for ml in minus_lines)
                def_added = any(_def_line_matches(pl, e_name) for pl in plus_lines)
                if def_removed and not def_added:
                    deleted_entity = e
                    break

            if deleted_entity is not None:
                verdicts.append(_verify_class_1_dead_code_hunk(
                    f.path, hunk, deleted_entity, graph, node_map, code_entities, diff_files
                ))
            else:
                verdicts.append(_verify_class_2_refactoring_hunk(
                    f.path, hunk, overlapping_entities[0], minus_lines, plus_lines, witnesses
                ))

    return verdicts


def evaluate_deletions(
    diff: str | None,
    code_files: list[str],
    entities: list | None,
    graph: Any = None,
    node_map: dict | None = None,
    witnesses: tuple[ExecutionWitness, ...] | list[ExecutionWitness] = (),
    waivers: tuple[SignedIntentWaiver, ...] | list[SignedIntentWaiver] = (),
) -> tuple[bool, str, str, list[DeletionHunkVerdict]]:
    """Return (passed, status, reasoning, verdicts) for CODE_CORE deletions."""
    verdicts = verify_deletion_hunks(
        diff=diff,
        code_files=code_files,
        entities=entities,
        graph=graph,
        node_map=node_map,
        witnesses=witnesses,
        waivers=waivers,
    )

    if not verdicts:
        return True, "PASS", "no_code_deletion_hunks", []

    # Check for hard FAIL
    fails = [v for v in verdicts if v.status == "FAIL"]
    if fails:
        first = fails[0]
        return False, "FAIL", first.reasoning, verdicts

    # Check for INCONCLUSIVE
    inconclusives = [v for v in verdicts if v.status == "INCONCLUSIVE"]
    if inconclusives:
        first = inconclusives[0]
        return False, "INCONCLUSIVE", first.reasoning, verdicts

    # All PASS
    return True, "PASS", "all_deletion_hunks_verified", verdicts
