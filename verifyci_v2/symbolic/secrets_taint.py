from __future__ import annotations

import ast
import base64
import binascii
import re
import textwrap
import urllib.parse

from verifyci_v2.contracts.ai_protocol import (
    ConformalProfile,
    DiscriminativeJudgeProtocol,
)
from verifyci_v2.contracts.attestation import VerificationFinding
from verifyci_v2.contracts.canonical import content_digest_hex
from verifyci_v2.contracts.redaction import (
    _has_long_sequential_run,
    shannon_entropy,
)
from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
from verifyci_v2.contracts.conformal import evaluate_with_conformal_gate

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    (
        "GITHUB_PAT",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{82})\b"
        ),
    ),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,120}\b")),
    (
        "SLACK_WEBHOOK",
        re.compile(
            r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,14}/B[0-9A-Za-z_]{8,14}/[0-9A-Za-z_]{20,36}"
        ),
    ),
    ("STRIPE_LIVE_KEY", re.compile(r"\b[rs]k_live_[0-9a-zA-Z]{16,99}\b")),
    (
        "GOOGLE_API_KEY",
        re.compile(r"\bAIza[0-9A-Za-z_-]{30,50}\b"),
    ),
    ("OPENAI_API_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,120}\b")),
    (
        "PRIVATE_KEY_HEADER",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    # Connection strings carrying an inline credential. The scheme allowlist keeps
    # ordinary `https://host:port/path` URIs out of the results, and the password
    # segment may itself contain `@`, `:` and `/`.
    (
        "CONNECTION_STRING_CREDENTIAL",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb\+srv|mongodb|redis|rediss|"
            r"amqps?|mssql|sqlserver|ftps?|ssh|ldap|jdbc):\/\/"
            r"[^\s:/@\"'()\[\]{}]{1,64}:[^\s\"'()\[\]]{4,128}@[^\s\"'()\[\]]{3,}"
        ),
    ),
    # JSON Web Tokens: base64url header (always starts "eyJ" for `{"`) + payload + signature.
    (
        "JWT",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
        ),
    ),
)

# Credential-bearing identifiers. Used by the explicit-credential rules below.
_CREDENTIAL_NAME_RE = re.compile(
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|credential|passphrase|client[_-]?secret|auth)",
    re.IGNORECASE,
)
_HARDCODED_COMPARE_OPS = frozenset({"Eq", "NotEq", "Is", "IsNot", "In", "NotIn"})

# Minimum literal length for a generic credential-named assignment.
_CREDENTIAL_MIN_LEN = 6

# Placeholder markers. A placeholder is not a credential regardless of which
# partition the file lives in, so this applies outside the test-file gate too.
_PLACEHOLDER_TOKENS = (
    "mock",
    "dummy",
    "fake",
    "example",
    "placeholder",
    "change_me",
    "changeme",
    "todo",
    "fixme",
    "enter_",
    "your_",
    "notreal",
    "replace_me",
    "sample",
)


def _looks_like_placeholder(var_name: str, value: str) -> bool:
    haystack = f"{var_name.lower()}\n{value.lower()}"
    if any(token in haystack for token in _PLACEHOLDER_TOKENS):
        return True
    # Sequential key runs such as "abcdefghijklmnopqrstuvwxyz" are alphabet
    # filler, not generated credentials.
    return _has_long_sequential_run(value.lower())


_BASE64_CANDIDATE_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
_HEX_CANDIDATE_RE = re.compile(r"^[0-9a-fA-F]{32,}$")


def multi_pass_decode(raw_value: str, max_passes: int = 3) -> tuple[str, ...]:
    """
    Recursively decodes obfuscated strings (URL-encoded, Base64, Hex) up to `max_passes`
    to expose hidden secrets (`cap011`).
    """
    discovered: list[str] = [raw_value]
    curr = raw_value.strip()

    for _ in range(max_passes):
        next_val: str | None = None
        if "%" in curr:
            unquoted = urllib.parse.unquote(curr)
            if unquoted != curr:
                next_val = unquoted

        if next_val is None and _HEX_CANDIDATE_RE.match(curr) and len(curr) % 2 == 0:
            try:
                decoded_bytes = binascii.unhexlify(curr)
                decoded_str = decoded_bytes.decode("utf-8")
                if decoded_str.isprintable() or all(
                    c.isprintable() or c in "\r\n\t" for c in decoded_str
                ):
                    next_val = decoded_str
            except (binascii.Error, UnicodeDecodeError):
                pass

        if next_val is None and _BASE64_CANDIDATE_RE.match(curr) and len(curr) % 4 == 0:
            try:
                decoded_bytes = base64.b64decode(curr, validate=True)
                decoded_str = decoded_bytes.decode("utf-8")
                if decoded_str.isprintable() or all(
                    c.isprintable() or c in "\r\n\t" for c in decoded_str
                ):
                    next_val = decoded_str
            except (binascii.Error, ValueError, UnicodeDecodeError):
                pass

        if next_val is None or next_val in discovered:
            break
        discovered.append(next_val)
        curr = next_val

    return tuple(discovered)


def is_test_or_fixture_partition(file_path: str) -> bool:
    """Classifies whether a file belongs to a unit test, mock, or fixture partition (`cap002b`)."""
    norm = file_path.replace("\\", "/").lower()
    parts = norm.split("/")
    if any(p in ("tests", "test", "fixtures", "mocks", "__mocks__") for p in parts):
        return True
    fname = parts[-1]
    return fname.startswith("test_") or fname.endswith("_test.py") or "fixture" in fname


def _resolve_constant_string(node: ast.AST | None) -> str | None:
    """Folds constant string concatenation, e.g. `"a:" + "secret" + "@host"`.

    Fragmented literals defeat per-literal pattern matching; folding them
    restores the full value before the rules run.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_constant_string(node.left)
        right = _resolve_constant_string(node.right)
        if left is not None and right is not None:
            return left + right
    return None


# Broad "sensitive identifier" notion, used for the entropy bar.
_SENSITIVE_NAME_TOKENS = ("secret", "token", "key", "password", "credential", "auth")


def _walk_string_literals(node: ast.AST):
    """Yields (assign_target_name, folded_string) for constant string assignments."""
    for child in ast.walk(node):
        if not isinstance(child, ast.Assign):
            continue
        folded = _resolve_constant_string(child.value)
        if folded is None:
            continue
        for target in child.targets:
            if isinstance(target, ast.Name):
                yield target.id, folded


_ENV_ASSIGN_RE = re.compile(
    r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*[=:]\s*(.+?)\s*$"
)


class TaintTrackedSecretEngine:
    """
    Layer 5 Stage 3 Secret & Taint Engine (`verifyci_v2/symbolic/secrets_taint.py`).
    Combines multi-pass decoding + Shannon entropy with U-SSA DFG source-to-sink
    taint reachability and Split Conformal mock/fixture triage (`cap002b` and `cap011`).
    """

    _SINK_PREFIXES: tuple[str, ...] = (
        "print",
        "logger.",
        "logging.",
        "requests.",
        "httpx.",
        "os.system",
        "subprocess.",
    )

    @classmethod
    def _trace_ussa_dfg_to_sink(
        cls,
        ussa_funcs: tuple,
        var_name: str,
        assign_line: int,
        *,
        tree: ast.Module | None = None,
        ussa_by_qname: Mapping[str, Any] | None = None,
    ) -> bool:
        """Trace local DFG and summary-based interprocedural taint to an I/O sink."""
        for fn in ussa_funcs:
            if not (fn.start_line <= assign_line <= fn.end_line):
                continue

            # 1. Identify initial tainted SSA variable(s) defined on assign_line or matching var_name
            tainted_ssa: set[str] = set()
            for blk in fn.basic_blocks:
                for inst in blk.instructions:
                    if inst.target_var and (
                        inst.source_line == assign_line
                        or inst.target_var.rsplit("_", 1)[0] == var_name
                    ):
                        tainted_ssa.add(inst.target_var)

            if not tainted_ssa:
                continue

            # 2. Propagate taint forward along intraprocedural U-SSA DFG edges
            dfg_adj: dict[str, set[str]] = {}
            for edge in fn.dfg_edges:
                if edge.edge_kind == "DFG":
                    dfg_adj.setdefault(edge.src_node_uid, set()).add(edge.dst_node_uid)

            frontier = list(tainted_ssa)
            while frontier:
                curr = frontier.pop()
                for nxt in dfg_adj.get(curr, ()):
                    if nxt not in tainted_ssa:
                        tainted_ssa.add(nxt)
                        frontier.append(nxt)

            # 3. Check if any tainted SSA variable is consumed by a sink CALL instruction
            for blk in fn.basic_blocks:
                for inst in blk.instructions:
                    if not inst.operands:
                        continue
                    expr_head = inst.operands[0]
                    used_operands = set(inst.operands[1:])
                    if any(s in expr_head for s in cls._SINK_PREFIXES):
                        if (used_operands & tainted_ssa) or any(
                            ssa_v in expr_head for ssa_v in tainted_ssa
                        ):
                            return True
            if tree is not None and ussa_by_qname:
                if cls._interprocedural_ast_flow(tree, fn, var_name, ussa_by_qname):
                    return True
        return False

    @staticmethod
    def _walk_function_scope(root: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AST]:
        """Walk one function's executable scope without entering nested definitions."""
        out: list[ast.AST] = []
        stack: list[ast.AST] = [root]
        nested_types = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        while stack:
            node = stack.pop()
            out.append(node)
            children = list(ast.iter_child_nodes(node))
            for child in reversed(children):
                if child is not root and isinstance(child, nested_types):
                    continue
                stack.append(child)
        return out

    @classmethod
    def _interprocedural_ast_flow(
        cls,
        tree: ast.Module,
        source_fn: Any,
        source_name: str,
        ussa_by_qname: Mapping[str, Any],
    ) -> bool:
        """Conservatively bind source-level call arguments to callee taint summaries.

        This is supplementary to the U-SSA DFG. Unknown star expansion is treated
        as tainting every bindable callee parameter; no name-based short match is
        accepted if it is ambiguous.
        """
        fn_nodes = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and getattr(n, "lineno", 0) <= source_fn.start_line <= getattr(n, "end_lineno", 0)]
        if not fn_nodes:
            return False
        active_fn = min(fn_nodes, key=lambda n: getattr(n, "end_lineno", n.lineno) - n.lineno)
        tainted_names = {source_name}
        # Include SSA version names by their root identifier.
        scoped_nodes = cls._walk_function_scope(active_fn)
        changed = True
        while changed:
            changed = False
            for node in scoped_nodes:
                if isinstance(node, ast.Assign):
                    call = node.value if isinstance(node.value, ast.Call) else None
                    if call is None:
                        # Ordinary aliases and container projections conservatively
                        # inherit taint when their value expression references a tainted name.
                        value_names = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
                        if value_names & tainted_names:
                            for target in node.targets:
                                for child in ast.walk(target):
                                    if isinstance(child, ast.Name) and child.id not in tainted_names:
                                        tainted_names.add(child.id)
                                        changed = True
                        continue
                    callee = cls._resolve_callee_summary(call, ussa_by_qname)
                    if callee is None:
                        # An unresolved helper receiving tainted input may return
                        # that input (directly or indirectly). Preserve taint on the
                        # assignment target instead of assuming an unknown call
                        # sanitizes its result.
                        call_names = {
                            n.id for arg in (*call.args, *(kw.value for kw in call.keywords))
                            for n in ast.walk(arg) if isinstance(n, ast.Name)
                        }
                        if call_names & tainted_names:
                            for target in node.targets:
                                for child in ast.walk(target):
                                    if isinstance(child, ast.Name) and child.id not in tainted_names:
                                        tainted_names.add(child.id)
                                        changed = True
                        continue
                    bound, uncertain = cls._bind_call_tainted_params(call, callee, tainted_names)
                    returned = set(callee.taint_summary.param_to_return)
                    if bound & returned or (uncertain and returned):
                        for target in node.targets:
                            for child in ast.walk(target):
                                if isinstance(child, ast.Name) and child.id not in tainted_names:
                                    tainted_names.add(child.id)
                                    changed = True
            # bound summary sink and direct sinks
            for node in scoped_nodes:
                if not isinstance(node, ast.Call):
                    continue
                callee_text = ast.unparse(node.func)
                actual_vars = {sub.id for arg in (*node.args, *(kw.value for kw in node.keywords))
                               for sub in ast.walk(arg) if isinstance(sub, ast.Name)}
                direct_sink = any(
                    actual_vars.intersection(tainted_names)
                    and (callee_text == prefix or callee_text.startswith(prefix))
                    for prefix in cls._SINK_PREFIXES
                )
                if direct_sink:
                    return True
                callee = cls._resolve_callee_summary(node, ussa_by_qname)
                if callee is None:
                    continue
                bound, uncertain = cls._bind_call_tainted_params(node, callee, tainted_names)
                sink_params = {p for p, _sink in callee.taint_summary.param_to_sinks}
                if bound & sink_params or (uncertain and bool(sink_params)):
                    return True
        return False

    @staticmethod
    def _resolve_callee_summary(call: ast.Call, ussa_by_qname: Mapping[str, Any]) -> Any | None:
        raw = ast.unparse(call.func)
        if raw in ussa_by_qname:
            return ussa_by_qname[raw]
        short = raw.split(".")[-1]
        candidates = [fn for qname, fn in ussa_by_qname.items() if qname.split(".")[-1] == short]
        return candidates[0] if len(candidates) == 1 else None

    @staticmethod
    def _bind_call_tainted_params(call: ast.Call, callee: Any, tainted_names: set[str]) -> tuple[set[str], bool]:
        """Bind possibly-tainted actual arguments to formal names conservatively.

        Dynamic ``*args`` can shift every later positional binding, so affected
        formals are conservatively marked rather than guessed by raw AST index.
        A tainted ``**kwargs`` spread can target any keyword-bindable parameter.
        """
        specs = list(getattr(callee, "param_specs", ()) or ())
        if specs:
            params = [(spec.name, spec.kind) for spec in specs]
        else:
            params = [(name, "POS_OR_KW") for name in callee.parameters]
        if isinstance(call.func, ast.Attribute) and params and params[0][0] in ("self", "cls"):
            params = params[1:]

        positionals = [p for p, kind in params if kind in ("POSONLY", "POS_OR_KW")]
        var_pos = next((p for p, kind in params if kind == "VAR_POSITIONAL"), None)
        var_kw = next((p for p, kind in params if kind == "VAR_KEYWORD"), None)
        tainted: set[str] = set()
        uncertain = False

        def is_tainted(expr: ast.AST) -> bool:
            return any(n.id in tainted_names for n in ast.walk(expr) if isinstance(n, ast.Name))

        positional_offset = 0
        uncertain_positional_alignment = False
        for arg in call.args:
            if isinstance(arg, ast.Starred):
                # A non-literal expansion may bind zero or many slots. If tainted,
                # it may taint every positional-capable formal; even an untainted
                # spread makes following positional indices ambiguous.
                if is_tainted(arg.value):
                    uncertain = True
                    tainted.update(positionals)
                    if var_pos:
                        tainted.add(var_pos)
                uncertain_positional_alignment = True
                continue

            if is_tainted(arg):
                if uncertain_positional_alignment:
                    uncertain = True
                    tainted.update(positionals[min(positional_offset, len(positionals)):])
                    if var_pos:
                        tainted.add(var_pos)
                elif positional_offset < len(positionals):
                    tainted.add(positionals[positional_offset])
                elif var_pos:
                    tainted.add(var_pos)
                else:
                    # Invalid/unknown binding cannot be narrowed safely.
                    uncertain = True
                    tainted.update(positionals)
            positional_offset += 1

        by_name = {name: kind for name, kind in params}
        keyword_bindable = {
            name for name, kind in params if kind in ("POS_OR_KW", "KWONLY")
        }
        for kw in call.keywords:
            if kw.arg is None:
                if is_tainted(kw.value):
                    uncertain = True
                    tainted.update(keyword_bindable)
                    if var_kw:
                        tainted.add(var_kw)
                continue
            if not is_tainted(kw.value):
                continue
            if by_name.get(kw.arg) in ("POS_OR_KW", "KWONLY"):
                tainted.add(kw.arg)
            elif var_kw:
                tainted.add(var_kw)
            else:
                uncertain = True
                tainted.update(keyword_bindable)
        return tainted, uncertain

    def scan_config_lines(
        self,
        file_path: str,
        lines: list[str],
    ) -> tuple[VerificationFinding, ...]:
        """Scans non-Python config text (`.env`, ini, yaml, toml) line by line.

        These files have no AST, so credential detection is lexical: a named
        rule match, or a credential-named key holding a high-entropy value.
        """
        findings: list[VerificationFinding] = []
        for index, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            for rule_name, pattern in _SECRET_PATTERNS:
                if pattern.search(line):
                    fid = content_digest_hex(
                        f"CFG_RULE:{file_path}:{index}:{rule_name}",
                        domain="verifyci.v2.finding",
                    )[:16]
                    findings.append(
                        VerificationFinding(
                            finding_id=fid,
                            rule_id="VC2-SECRET-RULE-MATCH",
                            severity="CRITICAL",
                            verdict="FAIL",
                            file_path=file_path,
                            start_line=index,
                            end_line=index,
                            message=(
                                f"{rule_name} pattern detected in '{file_path}' "
                                f"on line {index}."
                            ),
                        )
                    )
                    break

            match = _ENV_ASSIGN_RE.match(line)
            if not match:
                continue
            key, value = match.group(1), match.group(2).strip().strip("\"'")
            if not _CREDENTIAL_NAME_RE.search(key):
                continue
            if len(value) < _CREDENTIAL_MIN_LEN:
                continue
            if _looks_like_placeholder(key, value):
                continue
            if shannon_entropy(value) < 3.0:
                continue
            fid = content_digest_hex(
                f"CFG_CRED:{file_path}:{index}:{key}", domain="verifyci.v2.finding"
            )[:16]
            findings.append(
                VerificationFinding(
                    finding_id=fid,
                    rule_id="VC2-SECRET-CONFIG-CREDENTIAL",
                    severity="HIGH",
                    verdict="FAIL",
                    file_path=file_path,
                    start_line=index,
                    end_line=index,
                    message=(
                        f"Hardcoded credential in config key '{key}' "
                        f"({file_path}:{index})."
                    ),
                )
            )
        return tuple(findings)

    def scan_python_source(
        self,
        file_path: str,
        source: str,
        *,
        judge: DiscriminativeJudgeProtocol | None = None,
        conformal_profile: ConformalProfile | None = None,
        preparsed_tree: ast.Module | None = None,
        prelowered_funcs: tuple | None = None,
        ussa_by_qname: Mapping[str, Any] | None = None,
    ) -> tuple[VerificationFinding, ...]:
        is_test_file = is_test_or_fixture_partition(file_path)

        # The pipeline supplies its retained parse/lowering artifacts. In that
        # path the scanner never reparses or relowers the revision.
        parsed_source = source
        if preparsed_tree is not None:
            tree = preparsed_tree
        else:
            try:
                tree = ast.parse(source, filename=file_path)
            except (SyntaxError, ValueError, IndentationError):
                # Compatibility wrapper only: standalone callers may scan an
                # isolated fragment. The pipeline never uses this repair path.
                try:
                    dedented = textwrap.dedent(source)
                    if dedented == source:
                        return ()
                    tree = ast.parse(dedented, filename=file_path)
                    parsed_source = dedented
                except (SyntaxError, ValueError, IndentationError):
                    return ()
        ussa_funcs = prelowered_funcs
        if ussa_funcs is None:
            ussa_funcs = lower_file_to_ussa(file_path, parsed_source, language="python")

        findings: list[VerificationFinding] = []

        # Rule 0: named-rule match on any string constant in the tree. Secrets
        # are routinely nested in dicts, calls and f-strings where there is no
        # assignment to inspect, so this runs before the assignment loop and
        # claims those literals.
        claimed: set[tuple[str, str]] = set()
        direct_assign_values: set[int] = set()
        const_nodes: list[ast.Constant] = []
        compare_nodes: list[ast.Compare] = []
        assign_nodes: list[ast.Assign] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                assign_nodes.append(node)
                direct_assign_values.add(id(node.value))
            elif isinstance(node, ast.Compare):
                compare_nodes.append(node)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                const_nodes.append(node)

        for const_node in const_nodes:
            if id(const_node) in direct_assign_values:
                continue
            literal = const_node.value
            if len(literal) < 12:
                continue
            matched_rule = None
            for variant in multi_pass_decode(literal):
                for rule_name, pattern in _SECRET_PATTERNS:
                    if pattern.search(variant):
                        matched_rule = rule_name
                        break
                if matched_rule:
                    break
            if matched_rule is None:
                continue
            claimed.add((matched_rule, literal))
            fid = content_digest_hex(
                f"RULE:{file_path}:{const_node.lineno}:{matched_rule}:{literal}",
                domain="verifyci.v2.finding",
            )[:16]
            findings.append(
                VerificationFinding(
                    finding_id=fid,
                    rule_id="VC2-SECRET-RULE-MATCH",
                    severity="CRITICAL",
                    verdict="FAIL",
                    file_path=file_path,
                    start_line=const_node.lineno,
                    end_line=const_node.lineno,
                    message=(
                        f"{matched_rule} pattern detected on line "
                        f"{const_node.lineno}."
                    ),
                )
            )

        # Rule 1: hardcoded credential comparison, e.g. `if password == "secret":`.
        # This is a Compare, not an Assign, so the assignment loop below cannot
        # see it.
        for node in compare_nodes:
            if not any(op.__class__.__name__ in _HARDCODED_COMPARE_OPS for op in node.ops):
                continue
            names = [
                operand.id
                for operand in (node.left, *node.comparators)
                if isinstance(operand, ast.Name)
            ] + [
                operand.attr
                for operand in (node.left, *node.comparators)
                if isinstance(operand, ast.Attribute)
            ]
            literals = [
                operand.value
                for operand in (node.left, *node.comparators)
                if isinstance(operand, ast.Constant)
                and isinstance(operand.value, str)
                and operand.value.strip()
            ]
            if not names or not literals:
                continue
            credential_name = next(
                (nm for nm in names if _CREDENTIAL_NAME_RE.search(nm)), None
            )
            if credential_name is None:
                continue
            line_no = node.lineno
            fid = content_digest_hex(
                f"AUTH_CMP:{file_path}:{line_no}:{credential_name}",
                domain="verifyci.v2.finding",
            )[:16]
            findings.append(
                VerificationFinding(
                    finding_id=fid,
                    rule_id="VC2-SECRET-HARDCODED-AUTH-COMPARE",
                    severity="CRITICAL",
                    verdict="FAIL",
                    file_path=file_path,
                    start_line=line_no,
                    end_line=line_no,
                    message=(
                        f"Hardcoded credential literal compared against "
                        f"'{credential_name}' on line {line_no}."
                    ),
                )
            )

        for node in assign_nodes:
            if not isinstance(
                node.value, (ast.Constant, ast.BinOp)
            ):
                continue
            raw_literal = _resolve_constant_string(node.value)
            if raw_literal is None:
                continue

            var_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            var_name = var_names[0] if var_names else "literal"
            is_credential_var = bool(_CREDENTIAL_NAME_RE.search(var_name))

            # A short literal assigned to a credential-named variable is still a
            # hardcoded credential, so credential names get a lower length floor.
            min_len = _CREDENTIAL_MIN_LEN if is_credential_var else 12
            if len(raw_literal) < min_len:
                continue

            if is_test_file and any(
                tok in raw_literal.lower() or tok in var_name.lower()
                for tok in (
                    "mock",
                    "dummy",
                    "fake",
                    "example",
                    "test_key",
                    "placeholder",
                )
            ):
                continue

            decoded_variants = multi_pass_decode(raw_literal)
            matched_rule: str | None = None
            max_entropy = 0.0

            for variant in decoded_variants:
                max_entropy = max(max_entropy, shannon_entropy(variant))
                for rule_name, pattern in _SECRET_PATTERNS:
                    if pattern.search(variant):
                        matched_rule = rule_name
                        break
                if matched_rule:
                    break

            if matched_rule is None and _looks_like_placeholder(var_name, raw_literal):
                continue

            if matched_rule is not None and (matched_rule, raw_literal) in claimed:
                # Already reported by the tree-wide rule pass above.
                continue

            sensitive_var = any(
                k in var_name.lower() for k in _SENSITIVE_NAME_TOKENS
            )
            # Compute sink reachability before the acceptance gate so that any
            # credential/sensitive variable flowing into an active I/O sink is
            # always caught regardless of entropy.
            flows_to_sink = any(
                self._trace_ussa_dfg_to_sink(
                    ussa_funcs, vn, node.lineno, tree=tree, ussa_by_qname=ussa_by_qname
                )
                for vn in var_names
            )
            # Acceptance: a named rule matched, or the value is high-entropy
            # under a credential-ish identifier, or it is an explicit
            # production credential assignment.
            if (
                matched_rule is None
                and not (sensitive_var and max_entropy >= 3.85)
                and not (is_credential_var and not is_test_file)
                and not (sensitive_var and flows_to_sink)
            ):
                continue

            if is_test_file and judge is not None and conformal_profile is not None:
                choice = judge.judge_choice(
                    state={
                        "file_path": file_path,
                        "var_name": var_name,
                        "entropy": round(max_entropy, 3),
                    },
                    question="Classify this credential candidate:",
                    options=("test_fixture_or_mock", "live_production_credential"),
                )
                decision = evaluate_with_conformal_gate(
                    choice.distribution,
                    conformal_profile,
                    safe_label="test_fixture_or_mock",
                )
                if (
                    not decision.escalate_to_smt
                    and decision.top_choice == "test_fixture_or_mock"
                ):
                    continue

            # Trace transitive DFG taint flow (with module-scope fallback)
            flows_to_sink = self._trace_ussa_dfg_to_sink(
                ussa_funcs, var_name, node.lineno, tree=tree, ussa_by_qname=ussa_by_qname
            ) or bool(
                re.search(
                    rf"(?:print|logger\.\w+|logging\.\w+|requests\.\w+|httpx\.\w+)\([^)]*\b{re.escape(var_name)}\b",
                    source,
                )
            )
            severity = (
                "CRITICAL" if (flows_to_sink or matched_rule is not None) else "HIGH"
            )
            rule_tag = matched_rule or "HIGH_ENTROPY_TAINTED_SECRET"
            obfuscated_note = (
                " (decoded via multi-pass decoder)" if len(decoded_variants) > 1 else ""
            )
            sink_note = " and flows into active I/O sink" if flows_to_sink else ""

            fid = content_digest_hex(
                f"SECRET:{file_path}:{node.lineno}:{var_name}:{rule_tag}",
                domain="verifyci.v2.finding",
            )[:16]
            findings.append(
                VerificationFinding(
                    finding_id=fid,
                    rule_id=f"VC2-SECRET-{rule_tag}",
                    severity=severity,
                    verdict="FAIL",
                    file_path=file_path,
                    start_line=node.lineno,
                    end_line=node.lineno,
                    message=(
                        f"Hardcoded secret detected in '{var_name}' [{rule_tag}, "
                        f"entropy={max_entropy:.2f} bits]{obfuscated_note}{sink_note}."
                    ),
                )
            )

        return tuple(findings)
