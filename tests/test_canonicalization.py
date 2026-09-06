from pigeon.crypto.canonicalization import CanonicalError, canonicalize
import pytest


def test_key_order_does_not_matter():
    a = canonicalize({"b": 1, "a": 2})
    b = canonicalize({"a": 2, "b": 1})
    assert a == b == b'{"a":2,"b":1}'


def test_no_whitespace():
    assert canonicalize({"x": [1, 2]}) == b'{"x":[1,2]}'


def test_null():
    assert canonicalize(None) == b"null"


def test_rejects_floats():
    with pytest.raises(CanonicalError):
        canonicalize(1.5)


def test_rejects_out_of_range_int():
    with pytest.raises(CanonicalError):
        canonicalize((1 << 53))


def test_string_escapes():
    assert canonicalize("a\"b\\c") == b'"a\\"b\\\\c"'
    assert canonicalize("line\n") == b'"line\\n"'
    assert canonicalize("\u0001") == b'"\\u0001"'


def test_utf8_unescaped():
    assert canonicalize("café") == '"café"'.encode("utf-8")


def test_zero_is_zero():
    assert canonicalize(0) == b"0"


def test_nested_sorted_keys():
    payload = {
        "issuer": {"public_key": "ab", "principal_id": "h", "principal_type": "human"},
        "id": "1",
    }
    assert canonicalize(payload) == (
        b'{"id":"1","issuer":{"principal_id":"h","principal_type":"human","public_key":"ab"}}'
    )


def test_bool_not_int():
    assert canonicalize(True) == b"true"
    assert canonicalize(False) == b"false"
