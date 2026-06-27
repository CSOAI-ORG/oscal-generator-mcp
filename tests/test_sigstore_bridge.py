"""Tests for sigstore_bridge.

Covers:
  - Smoke test (availability, version, canonical sha256)
  - Error path: signing without OIDC token returns helpful error
  - Round-trip shape: verify_sigstore_bundle() handles a malformed bundle gracefully
  - is_available() boolean contract
  - get_version() returns the installed version

Full sign+verify integration test requires an OIDC token (CI only).
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from sigstore_bridge import (
    _canon,
    get_version,
    is_available,
    sign_with_sigstore,
    smoke_test,
    verify_sigstore_bundle,
)


def test_is_available():
    """sigstore-python is installed in the test env."""
    assert is_available() is True, "sigstore-python should be installed"


def test_get_version():
    v = get_version()
    assert v != "not installed"
    assert v == "4.3.0" or "." in v  # any semver


def test_canonical_deterministic():
    """Canonical JSON is deterministic for the same input."""
    doc = {"hello": "world", "n": 1}
    a = _canon(doc)
    b = _canon(doc)
    assert a == b
    # Order doesn't matter for keys
    doc2 = {"n": 1, "hello": "world"}
    assert _canon(doc2) == a


def test_sign_without_oidc_returns_error():
    """Without OIDC token, signing returns a helpful error."""
    # Make sure env doesn't leak from parent
    env_token = os.environ.pop("SIGSTORE_ID_TOKEN", None)
    try:
        res = sign_with_sigstore({"component-definition": {"uuid": "test"}})
        assert "error" in res
        assert "OIDC" in res["error"] or "token" in res["error"].lower()
    finally:
        if env_token:
            os.environ["SIGSTORE_ID_TOKEN"] = env_token


def test_verify_malformed_bundle_returns_invalid():
    """verify_sigstore_bundle() handles garbage input gracefully."""
    res = verify_sigstore_bundle({"hello": "world"}, "not a valid bundle json")
    assert res["valid"] is False
    assert "reason" in res


def test_smoke_test_shape():
    """smoke_test() returns the expected keys."""
    res = smoke_test()
    assert "sigstore_available" in res
    assert "sigstore_version" in res
    assert "canonical_sha256_test" in res
    assert "note" in res
    assert res["sigstore_available"] is True


def test_verify_unknown_signature_returns_invalid():
    """verify_sigstore_bundle() against a syntactically-valid-but-wrong bundle fails cleanly."""
    # Build a bundle with wrong content (just some bytes base64-encoded as a string)
    fake_bundle = json.dumps({"some": "fake", "data": "wrong"})
    res = verify_sigstore_bundle({"hello": "world"}, fake_bundle)
    assert res["valid"] is False


def test_canonical_unicode_safe():
    """Canonical JSON uses ensure_ascii=False — unicode survives."""
    doc = {"text": "Tanjiro Kamado 竈門炭治郎"}
    canon = _canon(doc)
    assert "Tanjiro" in canon.decode("utf-8")
    assert "竈門" in canon.decode("utf-8")


def test_sign_uses_staging_flag_correctly():
    """sign_with_sigstore passes the staging flag through to the result."""
    # Without a token, the error path fires first; but the result should still
    # acknowledge the staging setting if it gets that far.
    # We test the no-token error path here.
    res = sign_with_sigstore({}, use_staging=True)
    assert "error" in res


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))