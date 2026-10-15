from __future__ import annotations

import ast
import base64
import binascii
import math
import re
import textwrap
import urllib.parse

from verifyci_v2.contracts.ai_protocol import (
    ConformalProfile,
    DiscriminativeJudgeProtocol,
)
from verifyci_v2.contracts.attestation import VerificationFinding
from verifyci_v2.contracts.canonical import blake3_hex
from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
from verifyci_v2.neural.conformal import evaluate_with_conformal_gate

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    (
        "GITHUB_PAT",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{82})\b"
        ),
    ),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,120}\b")),
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


def _has_long_sequential_run(value: str, run_length: int = 12) -> bool:
    for start in range(len(value) - run_length + 1):
        window = value[start : start + run_length]
        ascending = all(
            ord(window[i + 1]) - ord(window[i]) == 1 for i in range(run_length - 1)
        )
        descending = all(
            ord(window[i]) - ord(window[i + 1]) == 1 for i in range(run_length - 1)
        )
        if ascending or descending:
            return True
    return False

_BASE64_CANDIDATE_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
_HEX_CANDIDATE_RE = re.compile(r"^[0-9a-fA-F]{32,}$")


def shannon_entropy(text: str) -> float:
    """Computes the Shannon entropy H(X) in bits per character."""
    if not text:
        return 0.0
    length = len(text)
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


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


def redact_secrets(text: str) -> str:
    """
    Scrubs matched credential patterns and high-entropy token assignments before any payload
    is sent to an external BYO-AI endpoint.
    """
    redacted = text
    counter = 0
    for _rule_name, pattern in _SECRET_PATTERNS:
        for match in list(pattern.finditer(redacted)):
            counter += 1
            redacted = redacted.replace(match.group(0), f"<REDACTED_SECRET_{counter}>")

    # Also scrub high-entropy string literals assigned to secret/token/key/password variables
    assign_re = re.compile(
        r"(?i)\b(api_key|secret|token|password|passwd|client_secret)\s*=\s*['\"]([^'\"]{16,})['\"]"
    )
    for match in list(assign_re.finditer(redacted)):
        candidate = match.group(2)
        if shannon_entropy(candidate) >= 3.7 and not candidate.startswith("<REDACTED_"):
            counter += 1
            redacted = redacted.replace(candidate, f"<REDACTED_SECRET_{counter}>")
    return redacted


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
    ) -> bool:
        """Traces transitive DFG reachability from `var_name` at `assign_line` to any I/O sink."""
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
        return False

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
                    fid = blake3_hex(
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
            fid = blake3_hex(
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
    ) -> tuple[VerificationFinding, ...]:
        is_test_file = is_test_or_fixture_partition(file_path)

        # Unparseable input is not an engine fault. A partial diff hunk may not
        # be valid Python on its own; the caller's syntax gate owns that case.
        # Returning empty here keeps a raised SyntaxError from being misread as
        # a checker failure.
        parsed_source = source
        try:
            tree = ast.parse(source, filename=file_path)
        except (SyntaxError, ValueError, IndentationError):
            # A function-level hunk is a uniformly indented fragment. Dedenting
            # it recovers a parseable module for pattern scanning; scanning a
            # fragment is strictly better than scanning nothing.
            try:
                dedented = textwrap.dedent(source)
            except (ValueError, IndexError):
                return ()
            if dedented == source:
                return ()
            try:
                tree = ast.parse(dedented, filename=file_path)
            except (SyntaxError, ValueError, IndentationError):
                return ()
            parsed_source = dedented
        ussa_funcs = lower_file_to_ussa(file_path, parsed_source, language="python")

        findings: list[VerificationFinding] = []

        # Rule 0: named-rule match on any string constant in the tree. Secrets
        # are routinely nested in dicts, calls and f-strings where there is no
        # assignment to inspect, so this runs before the assignment loop and
        # claims those literals.
        claimed: set[tuple[str, str]] = set()
        # Literals bound directly by an assignment are handled by the loop
        # below, which reports the matched rule and sink reachability. This pass
        # exists only to reach literals nested in calls, dicts and f-strings.
        direct_assign_values = {
            id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Assign)
        }
        for const_node in ast.walk(tree):
            if not (
                isinstance(const_node, ast.Constant)
                and isinstance(const_node.value, str)
            ):
                continue
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
            fid = blake3_hex(
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
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
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
            fid = blake3_hex(
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

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or not isinstance(
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
            # Acceptance: a named rule matched, or the value is high-entropy
            # under a credential-ish identifier, or it is an explicit
            # production credential assignment.
            if (
                matched_rule is None
                and not (sensitive_var and max_entropy >= 3.85)
                and not (is_credential_var and not is_test_file)
                and not (
                    is_credential_var
                    and not is_test_file
                    and not _looks_like_placeholder(var_name, raw_literal)
                )
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
                ussa_funcs, var_name, node.lineno
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

            fid = blake3_hex(
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
