"""Main Clean-Room Secret Detection Engine for VerifyCI (CAP-002B)."""
from __future__ import annotations

import re
from typing import Any

from verifyci.secrets.composite import CompositeSignalEngine
from verifyci.secrets.contracts import (
    DetectionSignal,
    DetectorContext,
    ResourceLimitExceeded,
    SecretFinding,
    SecretRule,
    SignalCategory,
    SuppressionDecision,
)
from verifyci.secrets.decoder import BoundedDecoder
from verifyci.secrets.entropy import (
    is_dotted_attribute_wiring,
    is_env_or_config_lookup,
    is_git_or_hex_hash,
    is_uuid,
    is_well_known_placeholder,
    shannon_entropy,
)
from verifyci.secrets.hashing import (
    compute_finding_fingerprint,
    compute_rule_config_hash,
    compute_source_hash,
)
from verifyci.secrets.prefilter import PrefilterIndex
from verifyci.secrets.redaction import redact_context_snippet, redact_secret_value
from verifyci.secrets.rules import RuleRegistry, get_default_rules
from verifyci.verification.diffmap import iter_added_lines_with_lineno


#: Cap on a single scanned line/buffer: matches BoundedDecoder's 2048
#: posture so per-line regex evaluation stays linear-time.
_MAX_LINE_SCAN_BYTES = 2048
#: Caps on the multiline continuation buffer (count and total bytes).
_MAX_MULTILINE_LINES = 200
_MAX_MULTILINE_BYTES = 32_768


def _spans_intersect(
    a: tuple[int | None, int | None],
    b: tuple[int | None, int | None],
) -> bool:
    """True when two [start, end) column spans overlap.

    A missing (None) bound is treated as intersecting (fail-closed):
    without coordinates we cannot prove disjointness.
    """
    if a[0] is None or a[1] is None or b[0] is None or b[1] is None:
        return True
    return max(a[0], b[0]) < min(a[1], b[1])


class SecretDetector:
    """Provenance-aware, multi-signal secret detector."""

    def __init__(
        self,
        registry: RuleRegistry | None = None,
        max_diff_bytes: int = 2_000_000,
        max_candidates: int = 1000,
        max_decode_depth: int = 2,
        timeout_seconds: float = 10.0,
    ):
        self.registry = registry or RuleRegistry(get_default_rules())
        self.prefilter = PrefilterIndex(self.registry.rules)
        self.decoder = BoundedDecoder(max_depth=max_decode_depth)
        self.composite_engine = CompositeSignalEngine()
        self.max_diff_bytes = max_diff_bytes
        self.max_candidates = max_candidates
        self.max_decode_depth = max_decode_depth
        self.timeout_seconds = timeout_seconds
        self.rule_config_hash = compute_rule_config_hash(self.registry.rules)

    def scan_diff(
        self,
        diff: str,
        context: DetectorContext | None = None,
    ) -> list[SecretFinding]:
        """Scan a unified diff and return all findings (active and suppressed)."""
        if not diff:
            return []
        if len(diff) > self.max_diff_bytes:
            raise ResourceLimitExceeded(
                f"Diff size {len(diff)} exceeds limit {self.max_diff_bytes}",
                limit_type="diff_size",
            )

        ctx = context or DetectorContext(
            timeout_seconds=self.timeout_seconds,
            max_candidates=self.max_candidates,
            max_decode_depth=self.max_decode_depth,
        )
        # Honor caller-supplied limits: decoder depth and composite fan-out
        # follow the active context, not just constructor defaults.
        self.decoder.max_depth = ctx.max_decode_depth
        self.composite_engine.max_combinations = ctx.max_component_combinations
        raw_candidates: list[SecretFinding] = []

        # 1. Parse added lines grouped by file
        lines_by_file: dict[str, list[tuple[int | None, str]]] = {}
        for fname, lineno, content in iter_added_lines_with_lineno(diff):
            fkey = fname if fname is not None else "unscoped"
            lines_by_file.setdefault(fkey, []).append((lineno, content))

        # 2. Process each file
        for file_path, lines in lines_by_file.items():
            if ctx.is_timeout():
                raise ResourceLimitExceeded("Scan timed out", limit_type="timeout")

            # Extract context signals for composite correlation
            context_signals_map = self.composite_engine.extract_context_signals(lines)

            # Multiline continuation state
            # state: (opener_quote, paren_balance, backslash_flag, buffer_lines, start_lineno)
            tdq, tsq = '"""', "'''"
            st: list[Any] = [None, 0, False, [], None]

            for lineno, content in lines:
                if ctx.is_timeout():
                    raise ResourceLimitExceeded("Scan timed out", limit_type="timeout")
                if len(raw_candidates) > ctx.max_candidates:
                    raise ResourceLimitExceeded(
                        f"Candidate count exceeded limit {ctx.max_candidates}",
                        limit_type="candidate_count",
                    )

                src_hash = compute_source_hash(content)

                # Single-line scan
                line_findings = self._scan_line(
                    content=content,
                    file_path=file_path,
                    lineno=lineno,
                    src_hash=src_hash,
                    ctx=ctx,
                    context_signals_map=context_signals_map,
                )
                raw_candidates.extend(line_findings)

                # Multiline tracking
                in_multiline = st[0] is not None or st[1] > 0 or st[2]
                if in_multiline:
                    if len(st[3]) >= _MAX_MULTILINE_LINES or (
                        sum(len(x) for x in st[3]) + len(content) > _MAX_MULTILINE_BYTES
                    ):
                        raise ResourceLimitExceeded(
                            "Multiline buffer exceeded "
                            f"({_MAX_MULTILINE_LINES} lines / {_MAX_MULTILINE_BYTES} bytes)",
                            limit_type="multiline_buffer",
                        )
                    st[3].append(content)
                    joined = " ".join(st[3])
                    clean_joined = re.sub(r"\\\s*", "", joined)
                    clean_joined = re.sub(r'"""|\'\'\'', '"', clean_joined)
                    joined_hash = compute_source_hash(clean_joined)
                    multiline_findings = self._scan_line(
                        content=clean_joined,
                        file_path=file_path,
                        lineno=st[4] if st[4] is not None else lineno,
                        src_hash=joined_hash,
                        ctx=ctx,
                        context_signals_map=context_signals_map,
                    )
                    raw_candidates.extend(multiline_findings)

                    # Also check triple-quote body lines
                    if st[0] is not None and len(content.replace(st[0], "").strip()) >= 3:
                        opener = st[3][0] if st[3] else ""
                        if any(kw in opener.lower() for kw in ("password", "passwd", "secret", "api", "auth", "token", "private", "key")):
                            bare_val = content.replace(st[0], "").strip()
                            synth = f'{opener.split("=")[0]} = "{bare_val}"'
                            synth_findings = self._scan_line(
                                content=synth,
                                file_path=file_path,
                                lineno=st[4] if st[4] is not None else lineno,
                                src_hash=compute_source_hash(synth),
                                ctx=ctx,
                                context_signals_map=context_signals_map,
                            )
                            raw_candidates.extend(synth_findings)

                    # Check closing
                    if st[0] is not None:
                        if st[0] in content:
                            st[0] = None
                            st[3] = []
                            st[4] = None
                    elif st[1] > 0:
                        st[1] += content.count("(") - content.count(")")
                        if st[1] <= 0:
                            st[1] = 0
                            st[3] = []
                            st[4] = None
                    else:
                        st[2] = False
                        st[3] = []
                        st[4] = None
                    continue

                # Openers check
                if content.count(tdq) % 2 == 1:
                    st[0] = tdq
                    st[3] = [content]
                    st[4] = lineno
                    continue
                if content.count(tsq) % 2 == 1:
                    st[0] = tsq
                    st[3] = [content]
                    st[4] = lineno
                    continue
                if content.rstrip().endswith("\\"):
                    st[2] = True
                    st[3] = [content]
                    st[4] = lineno
                    continue
                stripped = content.rstrip()
                if stripped.endswith("(") and stripped.count("(") > stripped.count(")"):
                    st[1] = stripped.count("(") - stripped.count(")")
                    st[3] = [content]
                    st[4] = lineno
                    continue

        # 3. Specificity and overlap resolution
        resolved_findings = self._resolve_overlaps(raw_candidates)
        return resolved_findings

    def _scan_line(
        self,
        content: str,
        file_path: str,
        lineno: int | None,
        src_hash: str,
        ctx: DetectorContext,
        context_signals_map: dict[int, list[DetectionSignal]],
    ) -> list[SecretFinding]:
        """Scan a single content line or joined multiline buffer."""
        if len(content) > _MAX_LINE_SCAN_BYTES:
            raise ResourceLimitExceeded(
                f"Line length {len(content)} exceeds limit {_MAX_LINE_SCAN_BYTES}",
                limit_type="line_length",
            )
        findings: list[SecretFinding] = []
        eligible_rules = self.prefilter.eligible_rules_for_line(content)

        # First evaluate direct rules
        for rule in eligible_rules:
            findings.extend(
                self._evaluate_rule_on_content(
                    rule=rule,
                    content=content,
                    file_path=file_path,
                    lineno=lineno,
                    src_hash=src_hash,
                    ctx=ctx,
                    context_signals_map=context_signals_map,
                    transform_trace=None,
                )
            )

        # Next evaluate bounded decoded candidates
        for decoded_text, orig_span, trace in self.decoder.decode_candidates(content, src_hash):
            for rule in self.registry.rules:
                decoded_findings = self._evaluate_rule_on_content(
                    rule=rule,
                    content=decoded_text,
                    file_path=file_path,
                    lineno=lineno,
                    src_hash=src_hash,
                    ctx=ctx,
                    context_signals_map=context_signals_map,
                    transform_trace=trace,
                    override_span=orig_span,
                    original_line_content=content,
                )
                findings.extend(decoded_findings)

        return findings

    def _evaluate_rule_on_content(
        self,
        rule: SecretRule,
        content: str,
        file_path: str,
        lineno: int | None,
        src_hash: str,
        ctx: DetectorContext,
        context_signals_map: dict[int, list[DetectionSignal]],
        transform_trace: Any | None = None,
        override_span: tuple[int, int] | None = None,
        original_line_content: str | None = None,
    ) -> list[SecretFinding]:
        """Evaluate a specific rule against content string."""
        results: list[SecretFinding] = []
        pat = rule.pattern_strategy
        if not isinstance(pat, re.Pattern):
            return results

        display_line = original_line_content if original_line_content is not None else content

        for match in pat.finditer(content):
            # Extract raw secret value
            if match.groups():
                raw_val = match.group(1)
                span = match.span(1)
            else:
                raw_val = match.group(0)
                span = match.span(0)

            actual_span = override_span or span

            if len(raw_val) < rule.min_length or len(raw_val) > rule.max_length:
                continue

            # Multi-signal collection
            signals = [
                DetectionSignal(
                    signal_id=f"rule_{rule.rule_id}",
                    category=SignalCategory.PATTERN,
                    span=actual_span,
                    confidence=rule.confidence,
                    description=rule.description,
                )
            ]

            # Entropy calculation
            ent = shannon_entropy(raw_val)
            signals.append(
                DetectionSignal(
                    signal_id="entropy_score",
                    category=SignalCategory.ENTROPY,
                    span=actual_span,
                    confidence=min(1.0, ent / 4.5),
                    description=f"Shannon entropy: {ent:.2f}",
                )
            )

            # Check suppression criteria
            suppression: SuppressionDecision | None = None

            # 1. Path exclusions
            if rule.excluded_path_patterns:
                for excl in rule.excluded_path_patterns:
                    if excl in file_path:
                        suppression = SuppressionDecision(
                            suppressed=True,
                            reason="excluded_path_pattern",
                            rule_id=rule.rule_id,
                            scope="path",
                        )
                        break

            # 2. General test allowlist patterns
            if not suppression and ctx.test_allowlist_patterns:
                for allow in ctx.test_allowlist_patterns:
                    if allow in file_path or allow in display_line:
                        suppression = SuppressionDecision(
                            suppressed=True,
                            reason="test_allowlist_matched",
                            rule_id=rule.rule_id,
                            scope="allowlist",
                        )
                        break

            # 3. Environment or config lookup guard (only for keyword rules)
            if not suppression and rule.detector_family == "keyword_assignment":
                if is_env_or_config_lookup(display_line):
                    suppression = SuppressionDecision(
                        suppressed=True,
                        reason="env_or_config_lookup",
                        rule_id=rule.rule_id,
                    )
                elif is_dotted_attribute_wiring(display_line):
                    suppression = SuppressionDecision(
                        suppressed=True,
                        reason="dotted_attribute_wiring",
                        rule_id=rule.rule_id,
                    )

            # 4. Non-secret structural false positives (UUID, pure hex hashes, placeholders)
            if not suppression:
                if is_uuid(raw_val):
                    suppression = SuppressionDecision(
                        suppressed=True,
                        reason="uuid_format_non_secret",
                        rule_id=rule.rule_id,
                    )
                elif is_git_or_hex_hash(raw_val) and rule.detector_family not in ("private_key",):
                    suppression = SuppressionDecision(
                        suppressed=True,
                        reason="hex_hash_non_secret",
                        rule_id=rule.rule_id,
                    )
                elif is_well_known_placeholder(raw_val):
                    suppression = SuppressionDecision(
                        suppressed=True,
                        reason="template_placeholder",
                        rule_id=rule.rule_id,
                    )

            # 5. Entropy threshold check if rule demands it
            if not suppression and rule.entropy_threshold is not None:
                if ent < rule.entropy_threshold:
                    suppression = SuppressionDecision(
                        suppressed=True,
                        reason="below_entropy_threshold",
                        rule_id=rule.rule_id,
                    )

            # 6. Supporting context check if required
            if not suppression and rule.requires_supporting_context:
                supporting_signals = self.composite_engine.find_supporting_signals(
                    lineno=lineno, context_signals=context_signals_map
                )
                if not supporting_signals:
                    suppression = SuppressionDecision(
                        suppressed=True,
                        reason="missing_supporting_context",
                        rule_id=rule.rule_id,
                    )
                else:
                    signals.extend(supporting_signals)

            # Redaction hard boundary: compute finding fields WITHOUT plain secret
            redacted_val = redact_secret_value(raw_val)
            redacted_ctx = redact_context_snippet(display_line, actual_span)
            fingerprint = compute_finding_fingerprint(rule.rule_id, raw_val)

            finding = SecretFinding(
                rule_id=rule.rule_id,
                detector_family=rule.detector_family,
                file_path=file_path,
                line_start=lineno,
                line_end=lineno,
                col_start=actual_span[0],
                col_end=actual_span[1],
                finding_fingerprint=fingerprint,
                source_hash=src_hash,
                redacted_value=redacted_val,
                redacted_context=redacted_ctx,
                signals=tuple(signals),
                transforms=(transform_trace,) if transform_trace else (),
                suppression=suppression,
                rule_config_hash=self.rule_config_hash,
                confidence=rule.confidence,
            )
            results.append(finding)

        return results

    def _resolve_overlaps(self, candidates: list[SecretFinding]) -> list[SecretFinding]:
        """Resolve competing overlapping findings by specificity while retaining all in evidence.

        Only findings whose column spans actually intersect are superseded;
        non-overlapping findings on the same line stay active.
        """
        if not candidates:
            return []

        # Group by (file_path, line_start)
        by_line: dict[tuple[str, int], list[SecretFinding]] = {}
        for c in candidates:
            by_line.setdefault((c.file_path, c.line_start), []).append(c)

        final_findings: list[SecretFinding] = []

        for _key, line_candidates in by_line.items():
            active = [c for c in line_candidates if c.is_active]
            suppressed = [c for c in line_candidates if not c.is_active]

            if len(active) <= 1:
                final_findings.extend(line_candidates)
                continue

            # Sort active by rule specificity descending
            def _spec(finding: SecretFinding) -> int:
                r = self.registry.get_rule(finding.rule_id)
                return r.specificity if r else 0

            active.sort(key=_spec, reverse=True)
            kept: list[SecretFinding] = []
            demoted: list[tuple[SecretFinding, SecretFinding]] = []
            for cand in active:
                cand_span = (cand.col_start, cand.col_end)
                blocker = next(
                    (k for k in kept if _spans_intersect((k.col_start, k.col_end), cand_span)),
                    None,
                )
                if blocker is None:
                    kept.append(cand)
                else:
                    demoted.append((cand, blocker))
            final_findings.extend(kept)

            # Mark only genuinely intersecting active candidates as superseded
            for loser, winner in demoted:
                new_suppression = SuppressionDecision(
                    suppressed=True,
                    reason="superseded_by_specific_rule",
                    rule_id=loser.rule_id,
                    superseded_by_rule_id=winner.rule_id,
                )
                updated_loser = SecretFinding(
                    rule_id=loser.rule_id,
                    detector_family=loser.detector_family,
                    file_path=loser.file_path,
                    line_start=loser.line_start,
                    line_end=loser.line_end,
                    col_start=loser.col_start,
                    col_end=loser.col_end,
                    finding_fingerprint=loser.finding_fingerprint,
                    source_hash=loser.source_hash,
                    redacted_value=loser.redacted_value,
                    redacted_context=loser.redacted_context,
                    signals=loser.signals,
                    transforms=loser.transforms,
                    suppression=new_suppression,
                    rule_config_hash=loser.rule_config_hash,
                    confidence=loser.confidence,
                )
                final_findings.append(updated_loser)

            final_findings.extend(suppressed)

        return final_findings
