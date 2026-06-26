# oscal-generator-mcp

Generate **machine-readable NIST OSCAL** packages (System Security Plan + Component Definition) and score **FedRAMP RFC-0024 readiness** — governed + SIGIL-signed. CSOAI Layer-0.

**Why:** RFC-0024 (13 Jan 2026) mandates machine-readable OSCAL packages, first deadline **30 Sep 2026** — yet ~0 of 100+ 2025 Rev5 authorizations actually produced OSCAL. System description in → valid OSCAL JSON out, signed.

## Tools
- `generate_ssp(system_name, impact_level, controls, ts)` → OSCAL System Security Plan
- `generate_component_definition(component_name, control_ids, ts)` → OSCAL Component Definition
- `validate_oscal(document)` → structural validation
- `rfc0024_readiness(...)` → 0–100 readiness score + gaps vs the 30 Sep 2026 deadline

Deterministic (uuid5 + explicit ts) → reproducible packages. Apache-2.0.
