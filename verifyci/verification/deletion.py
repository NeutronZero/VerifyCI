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
    r"\b(raise\s+(PermissionError|AuthenticationError|SecurityError|Unauthorized|Forbidden)|"
    r"check_permission|verify_token|validate_credentials|"
    r"require_auth|login_required|permission_required)\b|"
    r"@(?:require_auth|login_required|permission_required|guard)\b"
)


def _is_guard_line(line: str) -> bool:
    stripped = line.strip()
    if _ASSERT_RE.match(stripped):
        return True
    if _GUARD_KEYWORD_RE.search(stripped):
        return True
    return False


def _is_guard_preserved_in_additions(added_lines: list[str]) -> bool:
    for line in added_lines:
        if _is_guard_line(line):
            return True
        if re.search(r"\b(raise\s+\w+|assert\b)", line):
            return True
    return False


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
        # No wildcard, no bidirectional matching: `t in gl` only (target
        # names the file or the guard text, one direction). `gl in t`
        # let a long target swallow arbitrary guard lines, and `*`
        # waived everything — both fail open for a deny bypass.
        if t in norm_file or norm_file.endswith(t):
            return w
        for gl in removed_guard_lines:
            if t in gl:
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
            pos_args = [a.arg for a in fn.args.args]
            num_defaults = len(fn.args.defaults)
            num_req = len(pos_args) - num_defaults
            defaults_flags = [False] * num_req + [True] * num_defaults
            return list(zip(pos_args, defaults_flags, strict=False))
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

    if len(new_req) > len(old_params):
        return False, f"new_signature_requires_more_args:{len(new_req)}>{len(old_params)}"

    for i, (old_name, _) in enumerate(old_params):
        if i < len(new_params):
            new_name, new_has_def = new_params[i]
            if not new_has_def and old_name != new_name:
                return False, f"param_position_mismatch:{old_name}->{new_name}"

    new_all_names = {name for name, _ in new_params}
    for old_name in old_req:
        if old_name not in new_all_names:
            return False, f"required_param_removed:{old_name}"

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
            old_defs = [ml for ml in minus_lines if ml.strip().startswith("def ") or ml.strip().startswith("class ")]

            if not is_net_deletion and not guard_lines and not old_defs:
                continue

            # Check provenance of removed lines first
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
                c_status = _classify_removed(f.path, old_ln, content, covering)
                if c_status == "fabricated":
                    hunk_fabricated = True
                    break
                elif c_status != "verified":
                    hunk_unverified = True
                old_ln += 1

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

            # Provenance is 100% verified! Now evaluate deletion semantics.
            # 1. Class 3 check: Guard / assertion removal without waiver
            if guard_lines and not _is_guard_preserved_in_additions(plus_lines):
                matched_waiver = _matches_waiver(guard_lines, f.path, waivers)
                if matched_waiver:
                    # Record WHICH trust posture waived this: keys configured
                    # (cryptographic) vs bearer opt-in (sticky process-wide
                    # env the moment it is set — it never un-sets itself).
                    # Readers of this verdict must see the posture, not
                    # just the waiver id; backfilling it later is expensive.
                    import os as _os
                    _posture = ("keyed" if (_os.getenv("VERIFYCI_WAIVER_KEYS")
                                            or _os.getenv("VERIFYCI_WAIVER_PUBLIC_KEYS"))
                                else "bearer-opt-in")
                    verdicts.append(DeletionHunkVerdict(
                        file_path=f.path,
                        old_start=hunk.old_start,
                        deletion_class=DeletionClass.CLASS_3_GUARD_REMOVAL,
                        passed=True,
                        status="PASS",
                        reasoning=(f"class_3_guard_removal_waived:"
                                   f"{matched_waiver.waiver_id}:{_posture}"),
                    ))
                else:
                    verdicts.append(DeletionHunkVerdict(
                        file_path=f.path,
                        old_start=hunk.old_start,
                        deletion_class=DeletionClass.CLASS_3_GUARD_REMOVAL,
                        passed=False,
                        status="FAIL",
                        reasoning=f"class_3_guard_removal_without_waiver:{f.path}:{hunk.old_start}",
                    ))
                continue

            # Find entities overlapping this hunk
            h_end = hunk.old_start + max(1, hunk.old_count) - 1
            overlapping_entities = [
                e for e in covering
                if not (getattr(e, "line_end", 1) < hunk.old_start or getattr(e, "line_start", 1) > h_end)
            ]

            # NOTE (defensive): the no-overlap verdict below is unreachable
            # in practice — provenance-verified implies an entity contains
            # the removed line, which intersects the hunk window by
            # construction (pure insertions skip earlier for lack of `-`
            # lines). Kept so unattributable deletions decline rather
            # than pass if the geometry ever changes.
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

            # Determine whether any entity is being deleted (Class 1) or refactored (Class 2)
            # An entity is deleted if its declaration line is removed and not re-declared
            deleted_entity = None
            for e in overlapping_entities:
                e_name = getattr(e, "name", "")
                if not e_name:
                    continue
                def_removed = any(
                    bool(re.search(rf"\b(def|class)\s+{re.escape(e_name)}\s*(\(|:)", ml))
                    for ml in minus_lines
                )
                def_added = any(
                    bool(re.search(rf"\b(def|class)\s+{re.escape(e_name)}\s*(\(|:)", pl))
                    for pl in plus_lines
                )
                if def_removed and not def_added:
                    deleted_entity = e
                    break

            if deleted_entity is not None:
                # Class 1: Dead code / unreferenced entity removal
                surviving = _find_surviving_callers(deleted_entity, graph, node_map, code_entities, diff_files)
                if surviving:
                    verdicts.append(DeletionHunkVerdict(
                        file_path=f.path,
                        old_start=hunk.old_start,
                        deletion_class=DeletionClass.CLASS_1_DEAD_CODE,
                        passed=False,
                        status="INCONCLUSIVE",
                        reasoning=f"surviving_callers_detected:{','.join(surviving[:3])}",
                    ))
                else:
                    verdicts.append(DeletionHunkVerdict(
                        file_path=f.path,
                        old_start=hunk.old_start,
                        deletion_class=DeletionClass.CLASS_1_DEAD_CODE,
                        passed=True,
                        status="PASS",
                        reasoning=f"class_1_dead_code_verified:{deleted_entity.name}",
                    ))
            else:
                # Class 2: Refactoring / intra-entity replacement
                enclosing = overlapping_entities[0]
                # Enclosing entity continuity check
                # Check if declaration line was replaced by non-def or unrelated code
                old_defs = [ml for ml in minus_lines if ml.strip().startswith("def ") or ml.strip().startswith("class ")]
                new_defs = [pl for pl in plus_lines if pl.strip().startswith("def ") or pl.strip().startswith("class ")]

                if old_defs and not new_defs:
                    verdicts.append(DeletionHunkVerdict(
                        file_path=f.path,
                        old_start=hunk.old_start,
                        deletion_class=DeletionClass.CLASS_2_REFACTORING,
                        passed=False,
                        status="INCONCLUSIVE",
                        reasoning=f"entity_continuity_broken:{enclosing.name}",
                    ))
                    continue

                # Signature compatibility check
                if old_defs and new_defs:
                    compat, sig_err = _check_signature_compatibility(old_defs[0], new_defs[0])
                    if not compat:
                        verdicts.append(DeletionHunkVerdict(
                            file_path=f.path,
                            old_start=hunk.old_start,
                            deletion_class=DeletionClass.CLASS_2_REFACTORING,
                            passed=False,
                            status="INCONCLUSIVE",
                            reasoning=f"signature_incompatible:{sig_err}",
                        ))
                        continue

                # Execution witness corroboration
                if not _has_associated_witness(f.path, enclosing, witnesses):
                    verdicts.append(DeletionHunkVerdict(
                        file_path=f.path,
                        old_start=hunk.old_start,
                        deletion_class=DeletionClass.CLASS_2_REFACTORING,
                        passed=False,
                        status="INCONCLUSIVE",
                        reasoning=f"missing_execution_witness:{enclosing.name}",
                    ))
                    continue

                verdicts.append(DeletionHunkVerdict(
                    file_path=f.path,
                    old_start=hunk.old_start,
                    deletion_class=DeletionClass.CLASS_2_REFACTORING,
                    passed=True,
                    status="PASS",
                    reasoning=f"class_2_refactoring_verified:{enclosing.name}",
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
