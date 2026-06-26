#!/usr/bin/env python3
"""
Generate the signed OSCAL package for the ENTIRE CSOAI Layer-0 protocol.

Enumerates every Layer-0 component (the 19 governed bridges + scoreboard +
OSCAL generator + Compliance Passport + gateway) with its frameworks, builds
ONE OSCAL Component Definition, Ed25519-signs it, writes it, and verifies the
signature. Output = a machine-readable, signed description of the whole protocol.
"""
import json
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location("oscal_server", Path(__file__).resolve().parent / "server.py")
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)

# The Layer-0 fleet — component → frameworks it governs.
LAYER0 = [
    {"name": "cobol-bridge-mcp", "frameworks": ["SOX", "DORA", "PCI-DSS"]},
    {"name": "iso20022-bridge-mcp", "frameworks": ["ISO 20022", "DORA", "NIS2", "AML"]},
    {"name": "hl7-fhir-bridge-mcp", "frameworks": ["HIPAA", "EU MDR", "GDPR"]},
    {"name": "as400-bridge-mcp", "frameworks": ["SOX", "DORA"]},
    {"name": "sap-bridge-mcp", "frameworks": ["SOX", "GDPR"]},
    {"name": "oracle-bridge-mcp", "frameworks": ["SOX", "GDPR"]},
    {"name": "scada-bridge-mcp", "frameworks": ["IEC 62443", "NIS2"]},
    {"name": "edi-bridge-mcp", "frameworks": ["SOX"]},
    {"name": "fix-bridge-mcp", "frameworks": ["MiFID II"]},
    {"name": "cics-bridge-mcp", "frameworks": ["SOX", "PCI-DSS", "DORA"]},
    {"name": "mqtt-bridge-mcp", "frameworks": ["IEC 62443", "NIS2"]},
    {"name": "acord-bridge-mcp", "frameworks": ["Solvency II", "GDPR", "EU AI Act"]},
    {"name": "nacha-bridge-mcp", "frameworks": ["OFAC", "AML"]},
    {"name": "iso8583-bridge-mcp", "frameworks": ["PCI-DSS", "DORA"]},
    {"name": "sip-bridge-mcp", "frameworks": ["STIR/SHAKEN", "GDPR"]},
    {"name": "tax-bridge-mcp", "frameworks": ["SOX"]},
    {"name": "gs1-bridge-mcp", "frameworks": ["EU AI Act"]},
    {"name": "mismo-bridge-mcp", "frameworks": ["ECOA", "EU AI Act"]},
    {"name": "dlms-bridge-mcp", "frameworks": ["ISO 62056", "NIS2", "GDPR"]},
    {"name": "model-scoreboard-mcp", "frameworks": ["NIST", "ISO 42001"]},
    {"name": "oscal-generator-mcp", "frameworks": ["NIST", "EU AI Act"]},
    {"name": "meok-compliance-passport-mcp", "frameworks": ["EU AI Act", "GDPR"]},
    {"name": "meok-compliance-gateway", "frameworks": ["EU AI Act", "GDPR", "NIST", "ISO 42001"]},
    {"name": "nist-iso42001-crosswalk-mcp", "frameworks": ["NIST", "ISO 42001"]},
    {"name": "ll144-bias-audit-mcp", "frameworks": ["EU AI Act", "ECOA"]},
    # A2A agent-governance substrate (20)
    {"name": "agent-identity-trust-mcp", "frameworks": ["EU AI Act"]},
    {"name": "agent-policy-enforcement-mcp", "frameworks": ["EU AI Act"]},
    {"name": "agent-incident-relay-mcp", "frameworks": ["EU AI Act", "NIS2"]},
    {"name": "agent-incident-reporter-mcp", "frameworks": ["EU AI Act"]},
    {"name": "agent-prompt-injection-firewall-mcp", "frameworks": ["EU AI Act"]},
    {"name": "agent-x402-paywall-mcp", "frameworks": ["DORA"]},
    {"name": "agent-handoff-certified-mcp", "frameworks": ["EU AI Act"]},
    {"name": "agent-audit-logger-mcp", "frameworks": ["SOX", "GDPR"]},
    {"name": "agent-mcp-router-mcp", "frameworks": ["EU AI Act"]},
    {"name": "agent-rate-limiter-mcp", "frameworks": ["NIS2"]},
    {"name": "agent-data-residency-mcp", "frameworks": ["GDPR"]},
    {"name": "agent-cost-allocator-mcp", "frameworks": ["SOX"]},
    {"name": "agent-token-budget-mcp", "frameworks": ["SOX"]},
    {"name": "agent-orchestrator-mcp", "frameworks": ["EU AI Act"]},
    {"name": "agent-negotiation-mcp", "frameworks": ["EU AI Act"]},
    {"name": "agent-delegation-mcp", "frameworks": ["EU AI Act"]},
    {"name": "agent-replay-debugger-mcp", "frameworks": ["EU AI Act"]},
    {"name": "agent-commerce-protocol-mcp", "frameworks": ["DORA"]},
    {"name": "agent-commerce-payments-mcp", "frameworks": ["PCI-DSS", "DORA"]},
    {"name": "agent-content-watermark-mcp", "frameworks": ["EU AI Act"]},
    # article-level framework MCPs
    {"name": "eu-ai-act-compliance-mcp", "frameworks": ["EU AI Act"]},
    {"name": "dora-compliance-mcp", "frameworks": ["DORA"]},
    {"name": "nis2-compliance-mcp", "frameworks": ["NIS2"]},
    {"name": "hipaa-compliance-mcp", "frameworks": ["HIPAA"]},
    {"name": "pci-dss-mcp", "frameworks": ["PCI-DSS"]},
    {"name": "gdpr-compliance-ai-mcp", "frameworks": ["GDPR"]},
    {"name": "mifid-ii-ai-mcp", "frameworks": ["MiFID II"]},
    {"name": "aml-ai-mcp", "frameworks": ["AML"]},
    {"name": "basel-ai-overlay-mcp", "frameworks": ["NIST", "SOX"]},
    {"name": "soc2-compliance-ai-mcp", "frameworks": ["NIST", "ISO 42001"]},
]


def main():
    pkg = srv.generate_protocol_package("CSOAI Layer-0 Protocol", LAYER0, ts=0)
    out = Path(__file__).resolve().parent / "layer0_protocol.oscal.json"
    out.write_text(json.dumps(pkg.document, indent=2))
    # write a detached signature sidecar
    (out.with_suffix(".sig.json")).write_text(json.dumps({
        "algorithm": "Ed25519", "signature": pkg.signature, "public_key": pkg.public_key,
        "canonical_sha256": pkg.canonical_sha256, "sigil": pkg.sigil}, indent=2))
    # verify what we just wrote
    v = srv.verify_oscal_signature(pkg.document, pkg.signature, pkg.public_key)
    print(f"components: {pkg.component_count}")
    print(f"sha256(canonical): {pkg.canonical_sha256}")
    print(f"Ed25519 sig: {pkg.signature[:32]}...")
    print(f"signature verifies: {v['valid']}")
    print(f"written: {out.name} + {out.with_suffix('.sig.json').name}")
    return v["valid"]


if __name__ == "__main__":
    import sys
    sys.exit(0 if main() else 1)
