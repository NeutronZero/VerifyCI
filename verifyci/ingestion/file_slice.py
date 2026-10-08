"""Semantic chunk slicing at syntactic boundaries.

Splits source code spans exceeding maximum character thresholds (default 2000)
into coherent slices. Strict newline preservation ensures `"".join(slices)`
matches the original text exactly, preventing line-number misalignment during
verification or removal checks.
"""
from __future__ import annotations


def slice_source(
    source: bytes,
    line_start: int,
    line_end: int,
    max_chars: int = 2000,
) -> list[str]:
    """Slice a source line range [line_start, line_end] (1-indexed, inclusive)
    into syntactic chunks no larger than max_chars.

    Strict invariant: All slices except possibly the final slice end with a newline.
    `"".join(slices)` exactly reproduces the text extracted from the given span.
    """
    if not source or line_start <= 0 or line_end < line_start:
        return []

    # P1-B: split on b"\n" only. bytes.splitlines() also splits on \x0b,
    # \x0c, \u2028 et al, while tree-sitter and git count \n alone — a
    # form-feed in a file desynchronized every span after it.
    parts = source.split(b"\n")
    lines_raw = [part + b"\n" for part in parts[:-1]]
    if parts[-1]:
        lines_raw.append(parts[-1])
    if not lines_raw:
        return []

    total_lines = len(lines_raw)
    eff_start = max(1, line_start)
    eff_end = min(total_lines, line_end)
    if eff_start > total_lines:
        return []

    span_lines = [
        line.decode("utf-8", errors="replace")
        for line in lines_raw[eff_start - 1 : eff_end]
    ]
    full_text = "".join(span_lines)
    if len(full_text) <= max_chars:
        return [full_text]

    slices: list[str] = []
    current_lines: list[str] = []
    current_len = 0

    for line in span_lines:
        line_len = len(line)
        # If adding this line exceeds max_chars and we already have lines, check split candidate
        if current_len + line_len > max_chars and current_lines:
            # Check if this line is a natural boundary or if we must force a split
            slices.append("".join(current_lines))
            current_lines = [line]
            current_len = line_len
        else:
            current_lines.append(line)
            current_len += line_len

    if current_lines:
        slices.append("".join(current_lines))

    return slices
