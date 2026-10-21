"""RFC 8785 JSON Canonicalization Scheme (JCS) compliance tests."""

from __future__ import annotations

import json
import subprocess

from verifyci.evidence.canonical import canonical_json_bytes, payload_hash


def test_rfc8785_official_specification_vector() -> None:
    """Official example from RFC 8785 Section 3."""
    rfc_json_input = r'''{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\\\"\/",
  "literals": [null, true, false]
}'''
    official_data = json.loads(rfc_json_input)

    # RFC 8785 Section 3 canonical UTF-8 bytes:
    expected_hex_tokens = [
        "7b", "22", "6c", "69", "74", "65", "72", "61", "6c", "73", "22", "3a", "5b", "6e", "75", "6c", "6c", "2c", "74", "72", "75", "65", "2c", "66", "61", "6c", "73", "65", "5d", "2c",
        "22", "6e", "75", "6d", "62", "65", "72", "73", "22", "3a", "5b", "33", "33", "33", "33", "33", "33", "33", "33", "33", "2e", "33", "33", "33", "33", "33", "33", "33", "2c",
        "31", "65", "2b", "33", "30", "2c", "34", "2e", "35", "2c", "30", "2e", "30", "30", "32", "2c", "31", "65", "2d", "32", "37", "5d", "2c",
        "22", "73", "74", "72", "69", "6e", "67", "22", "3a", "22", "e2", "82", "ac", "24", "5c", "75", "30", "30", "30", "66", "5c", "6e", "41", "27", "42", "5c", "22", "5c", "5c", "5c", "5c", "5c", "5c", "5c", "22", "2f", "22", "7d"
    ]
    expected_bytes = bytes.fromhex("".join(expected_hex_tokens))

    actual = canonical_json_bytes(official_data)
    assert actual == expected_bytes
    assert payload_hash(official_data).startswith("sha256:")


def test_rfc8785_utf16_code_unit_sorting() -> None:
    """Keys must sort by UTF-16 code units (RFC 8785 Section 3.2.3)."""
    # Character U+10000 has UTF-16 code units D800 DC00
    # Character U+FFFF has UTF-16 code unit FFFF
    # In code point order: U+FFFF < U+10000
    # In UTF-16 code unit order: U+10000 (0xD800...) < U+FFFF (0xFFFF)
    data = {"\uffff": 1, "\U00010000": 2}
    result = canonical_json_bytes(data)
    # \U00010000 should come first in RFC 8785 JCS
    assert result.startswith(b'{"\xf0\x90\x80\x80":2,"\xef\xbf\xbf":1}')


def test_rfc8785_number_edge_cases() -> None:
    """Number edge cases: -0.0 -> 0, integer float 1.0 -> 1."""
    assert canonical_json_bytes(-0.0) == b"0"
    assert canonical_json_bytes(1.0) == b"1"
    assert canonical_json_bytes(0) == b"0"
    assert canonical_json_bytes(-42) == b"-42"
    assert canonical_json_bytes([1e21, 1e-6]) == b"[1e+21,0.000001]"


def test_rfc8785_parity_with_node() -> None:
    """Verify parity against Node.js JSON.stringify for numerical test cases."""
    cases = [
        0.0,
        -0.0,
        1.0,
        -1.0,
        1e-5,
        1e-6,
        1e-7,
        1e20,
        1e21,
        0.000001,
        0.0000001,
        333333333.3333333,
        {"a": [1, 2, None, True, False]},
    ]
    for case in cases:
        actual = canonical_json_bytes(case).decode("utf-8")
        node_script = f"process.stdout.write(JSON.stringify({actual if isinstance(case, (int, float)) else 'JSON.parse(' + repr(actual) + ')'}))"
        node_out = subprocess.check_output(["node", "-e", node_script], encoding="utf-8")
        assert actual == node_out
