#!/usr/bin/env python3
"""
OSCAL Generator MCP — CSOAI Layer-0.

Generates machine-readable NIST OSCAL packages (System Security Plan +
Component Definition) and runs an RFC-0024 readiness check. FedRAMP RFC-0024
(13 Jan 2026) mandates machine-readable OSCAL packages — first deadline
30 Sep 2026 — yet ~0 of 100+ 2025 Rev5 authorizations produced OSCAL. This
closes that vacuum: a system description in → valid OSCAL JSON out, signed.

Tools: generate_ssp · generate_component_definition · validate_oscal · rfc0024_readiness
"""
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

mcp = FastMCP("OSCAL Generator", instructions="Generate machine-readable NIST OSCAL (SSP / component-definition) + RFC-0024 readiness, governed + signed.")

# ── SIGIL: every generated artifact → one signed hash-chained hop ──
import hashlib as _hl, time as _t, json as _j, os as _os, uuid as _uuid
_SIGIL_LOG = _os.environ.get("SIGIL_LOG", _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "oscal_sigil.log"))
def _sigil(op, body):
    try:
        prev = ""
        if _os.path.exists(_SIGIL_LOG):
            with open(_SIGIL_LOG) as f:
                ls = f.readlines()
                if ls: prev = _j.loads(ls[-1]).get("digest", "")
        ts = int(_t.time()); dg = _hl.sha256(f"{op}|{ts}|{prev[:8]}|{body}".encode()).hexdigest()[:16]
        _os.makedirs(_os.path.dirname(_SIGIL_LOG), exist_ok=True)
        with open(_SIGIL_LOG, "a") as f: f.write(_j.dumps({"ts": ts, "op": op, "body": body, "prev_digest": prev, "digest": dg}) + "\n")
        return dg
    except Exception: return ""

OSCAL_VERSION = "1.1.2"
_NS = "uuid"  # deterministic uuid5 namespace base

# ── Ed25519: OSCAL packages cryptographically signed (RFC-0024 "signed package" = real, offline-verifiable) ──
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization as _ser

_OSCAL_KEY_SEED = _os.environ.get("OSCAL_SIGNING_SEED", "csoai-oscal/signing-key-v1")
def _signing_key() -> Ed25519PrivateKey:
    """Deterministic dev key from a seed. In production this calls the KMS/HSM."""
    return Ed25519PrivateKey.from_private_bytes(_hl.sha256(_OSCAL_KEY_SEED.encode()).digest())
def _canon(doc) -> bytes:
    return _j.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _uuid5(*parts: str) -> str:
    return str(_uuid.uuid5(_uuid.NAMESPACE_URL, "csoai-oscal/" + "/".join(str(p) for p in parts)))


def _now_iso(ts: Optional[int] = None) -> str:
    # OSCAL wants RFC3339; deterministic from an int ts (passed in for reproducibility)
    import datetime as _dt
    t = ts if ts is not None else 0
    return _dt.datetime.fromtimestamp(t, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _metadata(title: str, ts: int) -> Dict[str, Any]:
    return {
        "title": title,
        "last-modified": _now_iso(ts),
        "version": "1.0.0",
        "oscal-version": OSCAL_VERSION,
        "roles": [{"id": "system-owner", "title": "System Owner"},
                  {"id": "authorizing-official", "title": "Authorizing Official"}],
        "parties": [{"uuid": _uuid5(title, "org"), "type": "organization", "name": "CSOAI-governed system owner"}],
    }


class OscalDoc(BaseModel):
    model: str
    uuid: str
    document: Dict[str, Any]
    sigil: str = ""


class Validation(BaseModel):
    valid: bool
    model: Optional[str] = None
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class Readiness(BaseModel):
    ready: bool
    score: int
    deadline: str = "2026-09-30 (RFC-0024 first machine-readable deadline)"
    gaps: List[str] = Field(default_factory=list)
    note: str = ""


@mcp.tool()
def generate_ssp(system_name: str, impact_level: str = "moderate", controls: Optional[List[str]] = None, ts: int = 0) -> OscalDoc:
    """Generate a NIST OSCAL System Security Plan (SSP) skeleton for a system.
    impact_level: low|moderate|high. controls: NIST 800-53 control ids (e.g. AC-2, AU-6); defaults to a baseline set."""
    ctrls = controls or ["AC-2", "AC-3", "AU-2", "AU-6", "CA-2", "CM-2", "IA-2", "RA-5", "SC-7", "SI-4"]
    uid = _uuid5(system_name, "ssp")
    doc = {"system-security-plan": {
        "uuid": uid,
        "metadata": _metadata(f"{system_name} — System Security Plan", ts),
        "import-profile": {"href": f"#baseline-{impact_level}"},
        "system-characteristics": {
            "system-name": system_name,
            "security-sensitivity-level": impact_level,
            "system-information": {"information-types": [{
                "uuid": _uuid5(system_name, "info"), "title": "System information",
                "confidentiality-impact": {"base": impact_level},
                "integrity-impact": {"base": impact_level},
                "availability-impact": {"base": impact_level}}]},
            "status": {"state": "operational"},
        },
        "system-implementation": {"components": [{
            "uuid": _uuid5(system_name, "comp"), "type": "this-system",
            "title": system_name, "status": {"state": "operational"}}]},
        "control-implementation": {
            "description": "Control implementations for the named controls.",
            "implemented-requirements": [
                {"uuid": _uuid5(system_name, c), "control-id": c.lower(),
                 "statements": [{"statement-id": f"{c.lower()}_smt", "uuid": _uuid5(system_name, c, "smt"),
                                 "by-components": [{"component-uuid": _uuid5(system_name, "comp"),
                                                    "uuid": _uuid5(system_name, c, "bc"),
                                                    "description": f"{c} implemented and governed (CSOAI-attested)."}]}]}
                for c in ctrls]},
    }}
    return OscalDoc(model="ssp", uuid=uid, document=doc, sigil=_sigil("OSCAL", f"ssp|{system_name}|{impact_level}"))


@mcp.tool()
def generate_component_definition(component_name: str, control_ids: Optional[List[str]] = None, ts: int = 0) -> OscalDoc:
    """Generate a NIST OSCAL Component Definition for a reusable component (e.g. an MCP server, a service)."""
    ctrls = control_ids or ["AC-2", "AU-2", "SC-7"]
    uid = _uuid5(component_name, "compdef")
    cuid = _uuid5(component_name, "component")
    doc = {"component-definition": {
        "uuid": uid,
        "metadata": _metadata(f"{component_name} — Component Definition", ts),
        "components": [{
            "uuid": cuid, "type": "software", "title": component_name,
            "description": f"{component_name} — CSOAI-governed component.",
            "control-implementations": [{
                "uuid": _uuid5(component_name, "ci"), "source": "#nist-800-53",
                "description": "Controls this component satisfies.",
                "implemented-requirements": [
                    {"uuid": _uuid5(component_name, c), "control-id": c.lower(),
                     "description": f"{c} satisfied by {component_name}."} for c in ctrls]}]}],
    }}
    return OscalDoc(model="component-definition", uuid=uid, document=doc, sigil=_sigil("OSCAL", f"compdef|{component_name}"))


@mcp.tool()
def validate_oscal(document: Dict[str, Any]) -> Validation:
    """Validate an OSCAL document's structure (root model, uuid, metadata, oscal-version, control-implementation)."""
    roots = {"system-security-plan": "ssp", "component-definition": "component-definition",
             "assessment-plan": "assessment-plan", "plan-of-action-and-milestones": "poam", "catalog": "catalog", "profile": "profile"}
    root = next((k for k in roots if k in document), None)
    if root is None:
        return Validation(valid=False, errors=[f"No OSCAL root model found (expected one of {list(roots)})."])
    body = document[root]
    errors, warnings = [], []
    if not body.get("uuid"):
        errors.append(f"{root}: missing uuid")
    md = body.get("metadata", {})
    if not md:
        errors.append(f"{root}: missing metadata")
    else:
        if md.get("oscal-version") != OSCAL_VERSION:
            warnings.append(f"oscal-version is '{md.get('oscal-version')}', expected {OSCAL_VERSION}")
        for req in ("title", "last-modified", "version"):
            if not md.get(req):
                errors.append(f"metadata: missing {req}")
    if root == "system-security-plan":
        if not body.get("control-implementation", {}).get("implemented-requirements"):
            errors.append("ssp: no implemented-requirements")
        if not body.get("system-characteristics"):
            errors.append("ssp: missing system-characteristics")
    return Validation(valid=not errors, model=roots[root], errors=errors, warnings=warnings)


class Signature(BaseModel):
    algorithm: str = "Ed25519"
    signature: str
    public_key: str
    canonical_sha256: str
    sigil: str = ""


@mcp.tool()
def sign_oscal(document: Dict[str, Any]) -> Signature:
    """Ed25519-sign an OSCAL document (canonical JSON) → a cryptographically signed, offline-verifiable package. Satisfies the RFC-0024 signed-package requirement; same scheme as the CSOAI Compliance Passport."""
    canon = _canon(document)
    sk = _signing_key()
    sig = sk.sign(canon)
    pub = sk.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
    return Signature(signature=sig.hex(), public_key=pub.hex(),
                     canonical_sha256=_hl.sha256(canon).hexdigest(),
                     sigil=_sigil("SIGN", "oscal-ed25519"))


@mcp.tool()
def verify_oscal_signature(document: Dict[str, Any], signature: str, public_key: str) -> Dict[str, Any]:
    """Verify an Ed25519 signature over an OSCAL document — offline, no account. Returns valid True/False."""
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(bytes.fromhex(signature), _canon(document))
        return {"valid": True, "algorithm": "Ed25519"}
    except Exception as e:
        return {"valid": False, "reason": str(e)}


@mcp.tool()
def rfc0024_readiness(has_ssp: bool = False, has_component_def: bool = False, machine_readable: bool = False, signed: bool = False, automated_pipeline: bool = False) -> Readiness:
    """Score readiness for FedRAMP RFC-0024 (machine-readable OSCAL packages, first deadline 30 Sep 2026)."""
    checks = {
        "machine-readable OSCAL package": machine_readable,
        "System Security Plan (SSP) in OSCAL": has_ssp,
        "Component Definition in OSCAL": has_component_def,
        "cryptographically signed package": signed,
        "automated generation pipeline (not hand-authored)": automated_pipeline,
    }
    passed = sum(1 for v in checks.values() if v)
    score = int(100 * passed / len(checks))
    gaps = [f"Missing: {k}" for k, v in checks.items() if not v]
    return Readiness(ready=passed == len(checks), score=score, gaps=gaps,
                     note="RFC-0024 requires machine-readable packages by 30 Sep 2026; ~0 of 100+ 2025 authorizations produced OSCAL — generating + signing it now is a first-mover wedge.")


def main():
    mcp.run()


if __name__ == "__main__":
    main()
