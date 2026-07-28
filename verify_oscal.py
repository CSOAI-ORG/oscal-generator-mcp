#!/usr/bin/env python3
"""verify_oscal.py — verify a CSOAI Ed25519-signed OSCAL package OFFLINE.

Standalone. No account, no network, no CSOAI code. Only dependency is `cryptography`:
    pip install cryptography
    python3 verify_oscal.py layer0_protocol.oscal.json layer0_protocol.oscal.sig.json

WHY THIS FILE EXISTS
--------------------
The product claim is "verify it yourself offline — don't trust our dashboard." That claim only
holds if a third party can actually verify with off-the-shelf tooling. Before this file, they
could not: the signature is taken over a canonical form using `ensure_ascii=False`, and an
auditor trying the obvious `json.dumps(doc, sort_keys=True, separators=(',',':'))` gets a
verification FAILURE on a perfectly genuine document. A proof that only the issuer can check
is the trust-us model the signature was supposed to replace.

THE CANONICAL FORM (must match the signer exactly — one flag difference breaks everything):
    json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                                                           ^^^^^^^^^^^^^^^^^^
Non-ASCII characters are emitted as raw UTF-8, NOT \\uXXXX escapes.

Exit codes: 0 = verified · 1 = verification FAILED · 2 = usage/IO error.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def canonical(doc) -> bytes:
    """The exact canonical form the signer used. Do not 'tidy' this function."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def parse_receipt(sig: dict) -> dict:
    """Normalise the two receipt schemas in the estate into one shape.

    A verifier that only reads one receipt format is a verifier that will one day declare a
    perfectly valid attestation "unverifiable" — which is exactly what happened on 2026-07-28.
    Both formats are genuine; they just come from different signers.

    SCHEMA A — flat (oscal-generator-mcp, resign_oscal.py):
        {signature, public_key, canonical_sha256}
        The signature is over canonical(document).

    SCHEMA B — enveloped (defoneos sign-core, e.g. the 2026-07-05 assurance-pack receipt):
        {defoneos_signed_contact: {message, signature_ed25519, public_key_ed25519, fingerprint}}
        The signature is over canonical(MESSAGE ENVELOPE), NOT over the document. The document
        is bound indirectly, via message.detail.doc_sha256 — which is itself a hash of the
        CANONICAL form of the document (not of the raw file bytes; confusing those two is how
        a valid receipt gets mistaken for an orphaned one).
    """
    if "defoneos_signed_contact" in sig:
        c = sig["defoneos_signed_contact"]
        detail = c.get("message", {}).get("detail")
        doc_hash = None
        if isinstance(detail, str):
            try:
                doc_hash = json.loads(detail).get("doc_sha256")
            except Exception:
                pass
        elif isinstance(detail, dict):
            doc_hash = detail.get("doc_sha256")
        return {
            "schema": "enveloped (defoneos_signed_contact)",
            "signature": c["signature_ed25519"],
            "public_key": c["public_key_ed25519"],
            "signed_over": canonical(c["message"]),
            "doc_sha256": doc_hash,
            "fingerprint": c.get("fingerprint"),
        }
    # SCHEMA C — short form (the SSP receipts): {alg, sig, pub, sha256}, hex-encoded.
    if "sig" in sig and "pub" in sig:
        return {
            "schema": "short (alg/sig/pub)",
            "signature": sig["sig"],
            "public_key": sig["pub"],
            "signed_over": None,
            "doc_sha256": sig.get("sha256"),
            "fingerprint": None,
        }

    # SCHEMA D — keyless (e.g. csoai-os/maps): {scheme, value, sha256, signed_at}.
    # There is NO public key in the receipt, so NOBODY can verify it — not us, not an auditor.
    # This is not a "failure" to be re-signed blindly; it is a receipt that never carried the
    # material needed to check it. Report it as UNVERIFIABLE and say why.
    if "value" in sig and "scheme" in sig and "pub" not in sig and "public_key" not in sig:
        return {
            "schema": "keyless",
            "signature": sig["value"],
            "public_key": None,
            "signed_over": None,
            "doc_sha256": sig.get("sha256"),
            "fingerprint": None,
        }

    return {
        "schema": "flat",
        "signature": sig["signature"],
        "public_key": sig["public_key"],
        "signed_over": None,          # filled in by caller: canonical(document)
        "doc_sha256": sig.get("canonical_sha256"),
        "fingerprint": sig.get("fingerprint"),
    }


def verify(doc_path: Path, sig_path: Path) -> int:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        print("ERROR: pip install cryptography", file=sys.stderr)
        return 2

    doc = json.loads(doc_path.read_text())
    sig = json.loads(sig_path.read_text())

    canon = canonical(doc)
    digest = hashlib.sha256(canon).hexdigest()

    try:
        r = parse_receipt(sig)
    except KeyError as e:
        print(f"  ❌ unrecognised receipt schema — missing {e}", file=sys.stderr)
        return 2

    signed_over = r["signed_over"] if r["signed_over"] is not None else canon

    print(f"  document       : {doc_path.name}")
    cd = doc.get("component-definition", doc)
    print(f"  components     : {len(cd.get('components', []))}")
    print(f"  receipt schema : {r['schema']}")

    # A receipt with no public key cannot be checked by anyone. Say so plainly rather than
    # emitting a pass/fail that implies a cryptographic result we did not obtain.
    if not r["public_key"]:
        print("\n  ⚠️  UNVERIFIABLE — this receipt carries NO public key.")
        print("     A signature without a key cannot be checked by us OR by a third party.")
        if r["doc_sha256"]:
            raw = hashlib.sha256(doc_path.read_bytes()).hexdigest()
            match = "raw-bytes" if raw == r["doc_sha256"] else (
                "canonical" if digest == r["doc_sha256"] else "NEITHER")
            print(f"     Recorded sha256 matches: {match}"
                  f" (integrity only — proves nothing about WHO signed it).")
        print("     FIX: re-issue with the public key embedded, or publish the key alongside.")
        return 3

    print(f"  public key     : {r['public_key']}")
    if r.get("fingerprint"):
        print(f"  fingerprint    : {r['fingerprint']}")

    # 1. integrity.
    # Signers in this estate hash EITHER the canonical form OR the raw file bytes as written.
    # Both are legitimate; assuming one is how a valid receipt gets called broken (twice, on
    # 2026-07-28). Try both and REPORT WHICH MATCHED rather than presuming.
    raw = doc_path.read_bytes()
    raw_digest = hashlib.sha256(raw).hexdigest()
    form = None
    if r["doc_sha256"]:
        if digest == r["doc_sha256"]:
            form = "canonical"
        elif raw_digest == r["doc_sha256"]:
            form = "raw-bytes"
        print(f"  recorded hash  : {r['doc_sha256']}")
        print(f"  hashed form    : {form or 'NO MATCH'}"
              f"   (canonical={digest[:16]}… raw={raw_digest[:16]}…)")
        if form is None:
            print("\n  ❌ FAIL — the document has CHANGED since it was signed.")
            print("     Neither the canonical form nor the raw bytes match the recorded hash.")
            return 1

    # 2. authenticity — try the same two forms (plus the envelope, if this is schema B).
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(r["public_key"]))
    sig_bytes = bytes.fromhex(r["signature"])
    candidates = [("envelope", signed_over)] if r["signed_over"] is not None else [
        ("canonical", canon), ("raw-bytes", raw)]
    verified_over = None
    for name, blob in candidates:
        try:
            pub.verify(sig_bytes, blob)
            verified_over = name
            break
        except Exception:
            continue
    if verified_over is None:
        print("\n  ❌ FAIL — signature does not verify over the canonical form, the raw bytes,")
        print("     or the message envelope. Either the key, the signature, or the document is wrong.")
        return 1
    print(f"  signed over    : {verified_over}")

    print("\n  ✅ VERIFIED — signature is authentic and the document is untampered.")
    print("     Note: this attests DECLARED POSTURE. It is not a certification,")
    print("     and it is not a competent-authority conformity assessment.")
    return 0


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    d, s = Path(sys.argv[1]), Path(sys.argv[2])
    if not d.exists() or not s.exists():
        print(f"ERROR: missing {d if not d.exists() else s}", file=sys.stderr)
        return 2
    return verify(d, s)


if __name__ == "__main__":
    raise SystemExit(main())
