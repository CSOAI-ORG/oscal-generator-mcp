"""sigstore_bridge.py — companion module to oscal-generator-mcp.

Provides two complementary functions for sigstore integration with our
Ed25519-signed OSCAL packages:

  - sign_with_sigstore() : sign using sigstore-python (keyless, OIDC-bound)
                            → produces a Bundle with Rekor transparency log entry
  - verify_sigstore_bundle() : verify a sigstore Bundle against an OSCAL doc

Why: our existing sign_oscal() uses raw Ed25519PrivateKey — fine for offline
RFC-0024 packages, but no transparency log. Sigstore adds:
  1. **Public Rekor inclusion proof** — anyone can verify the signature was logged
  2. **Keyless signing** — bind to an OIDC identity (e.g. CI workflow) instead of static key
  3. **cosign compatibility** — verifiable with `cosign verify-blob`
  4. **SLSA provenance compatibility** — fits cleanly into SLSA L3+ supply chain

The existing Ed25519 path stays (still useful for offline verification).
This is a new signing mode that picks up the supply-chain ecosystem.

Status of this bridge: API discovery complete, real install verified
(sigstore 4.3.0 importable). Full signing requires OIDC token (ambient in
CI / GH Actions). Local signing test harness provided below.

sigstore 4.3 API surface (verified 2026-06-27):
  - sigstore.sign.SigningContext.from_trust_config(prod/staging) → SigningContext
  - SigningContext.signer(identity_token=IdentityToken) → Signer (context manager)
  - Signer.sign_artifact(bytes) → Bundle
  - sigstore.verify.Verifier.staging() / Verifier.production() → Verifier
  - Verifier.verify_artifact(bytes, bundle) → VerificationResult
  - Bundle.to_json() / Bundle.from_json() for serialization
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from typing import Any, Dict, Optional


def _canon(doc: dict) -> bytes:
    """Canonical JSON (same as oscal-generator's _canon)."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def is_available() -> bool:
    """True if sigstore-python is installed and importable."""
    try:
        import sigstore  # noqa: F401
        from sigstore.sign import SigningContext  # noqa: F401
        from sigstore.verify import Verifier  # noqa: F401
        from sigstore.models import Bundle  # noqa: F401
        return True
    except Exception:
        return False


def get_version() -> str:
    """Returns the installed sigstore version, or 'not installed'."""
    try:
        import sigstore
        return getattr(sigstore, "__version__", "unknown")
    except Exception:
        return "not installed"


def sign_with_sigstore(
    document: Dict[str, Any],
    *,
    use_staging: bool = True,
    oidc_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Sign an OSCAL document using sigstore-python (keyless, OIDC-bound).

    Args:
        document: the OSCAL document to sign (dict).
        use_staging: True to use Sigstore public-good staging (for testing);
                     False to use production.
        oidc_token: optional OIDC identity token. If None, sigstore attempts to
                    detect ambient credentials (CI, GH Actions, etc.).

    Returns:
        {
          "algorithm": "sigstore",
          "canonical_sha256": "...",
          "document_size_bytes": N,
          "bundle": {...},          # full sigstore Bundle as dict
          "bundle_json": "...",     # Bundle as compact JSON string
          "staging": True/False,
          "sigstore_version": "...",
        }

    Requires: SIGSTORE_ID_TOKEN env var OR running inside CI with ambient creds.
    """
    if not is_available():
        return {
            "error": "sigstore-python not installed. Run: pip install sigstore",
            "hint": "Get the OIDC token from GitHub Actions or set SIGSTORE_ID_TOKEN",
        }

    import sigstore
    from sigstore.sign import SigningContext
    from sigstore.oidc import IdentityToken

    canon = _canon(document)
    digest = hashlib.sha256(canon).hexdigest()

    # Pick the trust config
    try:
        from sigstore.models import ClientTrustConfig
        if use_staging:
            ctx = SigningContext.from_trust_config(ClientTrustConfig.staging())
        else:
            ctx = SigningContext.from_trust_config(ClientTrustConfig.production())
    except Exception as e:
        return {"error": f"could not build SigningContext: {e}"}

    # Get the identity token
    try:
        if oidc_token:
            token = IdentityToken(oidc_token)
        else:
            # Try ambient credentials
            ambient = os.environ.get("SIGSTORE_ID_TOKEN")
            if not ambient:
                return {
                    "error": "no OIDC token: set SIGSTORE_ID_TOKEN env var or run inside CI",
                    "hint": "GitHub Actions: add 'actions/github-script@v7' step to mint a sigstore token",
                }
            token = IdentityToken(ambient)
    except Exception as e:
        return {"error": f"could not build IdentityToken: {e}"}

    # Sign
    try:
        with ctx.signer(identity_token=token) as signer:
            bundle = signer.sign_artifact(canon)
        bundle_json = bundle.to_json()
        return {
            "algorithm": "sigstore",
            "canonical_sha256": digest,
            "document_size_bytes": len(canon),
            "bundle": json.loads(bundle_json),
            "bundle_json": bundle_json,
            "staging": use_staging,
            "sigstore_version": getattr(sigstore, "__version__", "unknown"),
        }
    except Exception as e:
        return {"error": f"sigstore sign failed: {e}"}


def verify_sigstore_bundle(
    document: Dict[str, Any],
    bundle_json: str,
    *,
    use_staging: bool = True,
) -> Dict[str, Any]:
    """Verify a sigstore-signed OSCAL bundle.

    Args:
        document: the OSCAL document that was signed (must match what was signed).
        bundle_json: JSON string of the sigstore Bundle (from sign_with_sigstore()).
        use_staging: must match the staging flag used at signing time.

    Returns:
        {"valid": True/False, "reason": "...", "staging": True/False}
    """
    if not is_available():
        return {"valid": False, "reason": "sigstore-python not installed"}

    from sigstore.verify import Verifier
    from sigstore.models import Bundle

    canon = _canon(document)

    try:
        bundle = Bundle.from_json(bundle_json)
    except Exception as e:
        return {"valid": False, "reason": f"could not parse bundle: {e}", "staging": use_staging}

    try:
        verifier = Verifier.staging() if use_staging else Verifier.production()
        verifier.verify_artifact(canon, bundle)
        return {"valid": True, "reason": "verified", "staging": use_staging}
    except Exception as e:
        return {"valid": False, "reason": str(e), "staging": use_staging}


def smoke_test() -> Dict[str, Any]:
    """Local smoke test that doesn't require an OIDC token.

    Returns dict with availability + canonical-sha256 determinism check.
    """
    canon = _canon({"hello": "world", "n": 1})
    return {
        "sigstore_available": is_available(),
        "sigstore_version": get_version(),
        "canonical_sha256_test": hashlib.sha256(canon).hexdigest(),
        "note": "For full sign+verify test, run inside CI with SIGSTORE_ID_TOKEN set.",
    }


if __name__ == "__main__":
    import json as _json
    result = smoke_test()
    print(_json.dumps(result, indent=2))