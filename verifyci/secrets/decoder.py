"""Bounded, provenance-preserving transformations for encoded secret candidates (CAP-002B)."""
from __future__ import annotations

import base64
import binascii
import re
from typing import Generator

from verifyci.secrets.contracts import TransformTrace
from verifyci.secrets.hashing import compute_source_hash

# Candidate patterns inside quotes or identifiers
_B64_CANDIDATE_RE = re.compile(r"""['"]([A-Za-z0-9+/]{16,}={0,2})['"]""")
_HEX_CANDIDATE_RE = re.compile(r"""['"]([0-9a-fA-F]{16,})['"]""")


def _is_printable_ascii(b: bytes) -> bool:
    """True if bytes are predominantly printable ASCII characters."""
    if not b:
        return False
    printable_count = sum(1 for byte in b if 32 <= byte <= 126 or byte in (9, 10, 13))
    return (printable_count / len(b)) >= 0.95


class BoundedDecoder:
    """Bounded decoder that tracks complete provenance for transformed secret material."""

    def __init__(self, max_depth: int = 2, max_length: int = 2048):
        self.max_depth = max_depth
        self.max_length = max_length

    def decode_candidates(
        self,
        fragment: str,
        source_hash: str | None = None,
    ) -> Generator[tuple[str, tuple[int, int], TransformTrace], None, None]:
        """Yield (decoded_candidate, original_span, transform_trace) tuples.
        
        Preserves original span and source hash for all transformations up to max_depth.
        """
        if not fragment or len(fragment) > self.max_length:
            return

        src_hash = source_hash or compute_source_hash(fragment)

        # 1. Base64 candidates
        for match in _B64_CANDIDATE_RE.finditer(fragment):
            candidate_str = match.group(1)
            span = match.span(1)
            yield from self._decode_b64_recursive(candidate_str, span, src_hash, depth=1)

        # 2. Hex candidates
        for match in _HEX_CANDIDATE_RE.finditer(fragment):
            candidate_str = match.group(1)
            span = match.span(1)
            if len(candidate_str) % 2 == 0:
                try:
                    decoded_bytes = bytes.fromhex(candidate_str)
                    if _is_printable_ascii(decoded_bytes):
                        decoded_text = decoded_bytes.decode("utf-8", errors="replace")
                        trace = TransformTrace(
                            transform_type="hex",
                            depth=1,
                            original_span=span,
                            source_hash=src_hash,
                            description=f"Hex decoded candidate at span {span}",
                        )
                        yield (decoded_text, span, trace)
                except (ValueError, binascii.Error):
                    pass

    def _decode_b64_recursive(
        self,
        encoded_str: str,
        original_span: tuple[int, int],
        source_hash: str,
        depth: int,
    ) -> Generator[tuple[str, tuple[int, int], TransformTrace], None, None]:
        if depth > self.max_depth or len(encoded_str) > self.max_length:
            return

        try:
            # Pad if necessary
            padding = len(encoded_str) % 4
            padded = encoded_str + ("=" * ((4 - padding) % 4))
            decoded_bytes = base64.b64decode(padded, validate=True)
            if _is_printable_ascii(decoded_bytes):
                decoded_text = decoded_bytes.decode("utf-8", errors="replace").strip()
                trace = TransformTrace(
                    transform_type="base64",
                    depth=depth,
                    original_span=original_span,
                    source_hash=source_hash,
                    description=f"Base64 decoded at depth {depth}",
                )
                yield (decoded_text, original_span, trace)

                # Check if decoded text itself is base64 encoded (nested depth)
                if depth + 1 <= self.max_depth:
                    # Look for inner base64 string
                    inner_match = re.match(r"^[A-Za-z0-9+/]{16,}={0,2}$", decoded_text)
                    if inner_match:
                        yield from self._decode_b64_recursive(
                            decoded_text, original_span, source_hash, depth=depth + 1
                        )
        except (binascii.Error, ValueError):
            pass
