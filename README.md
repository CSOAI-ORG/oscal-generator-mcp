# oscal-generator-mcp

Generate **machine-readable NIST OSCAL** packages (System Security Plan + Component Definition) and score **FedRAMP RFC-0024 readiness** — governed + SIGIL-signed. CSOAI Layer-0.

**Why:** RFC-0024 (13 Jan 2026) mandates machine-readable OSCAL packages, first deadline **30 Sep 2026** — yet ~0 of 100+ 2025 Rev5 authorizations actually produced OSCAL. System description in → valid OSCAL JSON out, signed.

## Verify it yourself

This repository ships a signed OSCAL artefact. **Check it without trusting us:**

```bash
pip install cryptography
python3 verify_oscal.py layer0_protocol.oscal.json layer0_protocol.oscal.sig.json
```

`verify_oscal.py` depends on nothing but `cryptography`. No account, no network, no code of ours
beyond that one file. It reads the four receipt schemas used across this estate, tries both the
canonical and raw-bytes forms, and **reports which one matched** rather than assuming.

A receipt carrying no public key is reported as **UNVERIFIABLE** (exit 3), not as a pass or a
failure — a signature nobody can check is not evidence, and saying so is the point.

**What this attests:** that the document is unaltered and attributable to the signing key.
**What it does not attest:** that the declared posture is accurate, or that any authority has
certified it. EU AI Act conformity requires a competent authority, and none is yet constituted.


## Tools
- `generate_ssp(system_name, impact_level, controls, ts)` → OSCAL System Security Plan
- `generate_component_definition(component_name, control_ids, ts)` → OSCAL Component Definition
- `validate_oscal(document)` → structural validation
- `rfc0024_readiness(...)` → 0–100 readiness score + gaps vs the 30 Sep 2026 deadline

Deterministic (uuid5 + explicit ts) → reproducible packages. Apache-2.0.
