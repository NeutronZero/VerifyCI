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


APPENDIX_B_TABLE_1: tuple[tuple[str, str], ...] = (
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
)


def test_rfc8785_appendix_b_table_1_vectors() -> None:
    """Full RFC 8785 Appendix B Table 1 IEEE 754 test vectors (all 24 finite vectors)."""
    import struct
    import pytest

    for h, expected in APPENDIX_B_TABLE_1:
        val = struct.unpack(">d", bytes.fromhex(h))[0]
        actual = canonical_json_bytes(val).decode("ascii")
        assert actual == expected, f"Vector {h} failed: expected {expected}, got {actual}"

    # Disallowed non-finite values per RFC 8785 Section 3.2.2.3
    with pytest.raises(ValueError, match="NaN and Infinity"):
        canonical_json_bytes(float("nan"))
    with pytest.raises(ValueError, match="NaN and Infinity"):
        canonical_json_bytes(float("inf"))
    with pytest.raises(ValueError, match="NaN and Infinity"):
        canonical_json_bytes(float("-inf"))


def test_rfc8785_integer_safe_range_policy() -> None:
    """Integers outside [-(2^53 - 1), 2^53 - 1] are rejected per RFC 8785 Section 3.2.2.3."""
    import pytest

    safe_max = 9007199254740991  # 2^53 - 1
    safe_min = -9007199254740991

    assert canonical_json_bytes(safe_max) == b"9007199254740991"
    assert canonical_json_bytes(safe_min) == b"-9007199254740991"
    assert canonical_json_bytes(0) == b"0"

    with pytest.raises(ValueError, match="exceeds RFC 8785 safe integer limit"):
        canonical_json_bytes(safe_max + 1)

    with pytest.raises(ValueError, match="exceeds RFC 8785 safe integer limit"):
        canonical_json_bytes(safe_min - 1)

    with pytest.raises(ValueError, match="exceeds RFC 8785 safe integer limit"):
        canonical_json_bytes(2**64)

    # High precision integers formatted as string are valid
    assert canonical_json_bytes(str(2**64)) == f'"{2**64}"'.encode("ascii")


def test_rfc8785_parity_with_node() -> None:
    """Verify parity against Node.js JSON.stringify for numerical test cases and Appendix B bit patterns."""
    import struct

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

    # Verify bit-pattern parity against Node.js for all 24 RFC 8785 Appendix B Table 1 vectors
    for h, _ in APPENDIX_B_TABLE_1:
        val = struct.unpack(">d", bytes.fromhex(h))[0]
        actual = canonical_json_bytes(val).decode("utf-8")
        node_script = f"process.stdout.write(JSON.stringify(Buffer.from('{h}', 'hex').readDoubleBE(0)))"
        node_out = subprocess.check_output(["node", "-e", node_script], encoding="utf-8")
        assert actual == node_out, f"{h}: Python produced {actual!r}, Node.js produced {node_out!r}"
