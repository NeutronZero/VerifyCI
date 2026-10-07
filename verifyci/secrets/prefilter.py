"""Candidate prefilter index for efficient rule evaluation (CAP-002B)."""
from __future__ import annotations

import re
from typing import Sequence

from verifyci.secrets.contracts import SecretRule


class PrefilterIndex:
    """Pre-filters rules against input lines using keyword indexing while guaranteeing
    that keywordless (value-first) rules remain unconditionally eligible.
    """

    def __init__(self, rules: Sequence[SecretRule]):
        self._universal_rules: list[SecretRule] = []
        self._keyword_map: dict[str, list[SecretRule]] = {}
        all_keywords = set()

        for rule in rules:
            if not rule.keywords:
                # Universal / value-first rules: always eligible on every line
                self._universal_rules.append(rule)
            else:
                for kw in rule.keywords:
                    low = kw.lower()
                    self._keyword_map.setdefault(low, []).append(rule)
                    all_keywords.add(low)

        if all_keywords:
            escaped = [re.escape(k) for k in sorted(all_keywords, key=len, reverse=True)]
            # Alphanumeric-adjacent boundaries (not strict \b): affixed
            # keywords such as db_password / api_key stay eligible while
            # pure-substring hosts such as "monkey" (for "key") do not.
            # Strict \b would break affixed keywords ("_" is a word char)
            # and cause false negatives on yaml/unquoted rules.
            self._keyword_re: re.Pattern | None = re.compile(
                r"(?i)(?<![A-Za-z0-9])(?:" + "|".join(escaped) + r")(?![A-Za-z0-9])"
            )
        else:
            self._keyword_re = None

    @property
    def universal_rules(self) -> tuple[SecretRule, ...]:
        return tuple(self._universal_rules)

    def eligible_rules_for_line(self, line: str) -> list[SecretRule]:
        """Return the subset of rules eligible to evaluate on the given line."""
        # Value-first / universal rules are unconditionally included
        eligible = list(self._universal_rules)

        if not self._keyword_re or not line:
            return eligible

        seen_rule_ids = {r.rule_id for r in eligible}
        for match in self._keyword_re.finditer(line):
            kw = match.group(0).lower()
            matching_rules = self._keyword_map.get(kw, ())
            for rule in matching_rules:
                if rule.rule_id not in seen_rule_ids:
                    eligible.append(rule)
                    seen_rule_ids.add(rule.rule_id)

        # Maintain specificity ordering
        eligible.sort(key=lambda x: (-x.specificity, x.rule_id))
        return eligible
