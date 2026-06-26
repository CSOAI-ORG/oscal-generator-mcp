"""Tests for the OSCAL Generator MCP — valid OSCAL out, validation, RFC-0024 readiness."""
import sys, importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location("oscal_server", Path(__file__).resolve().parents[1] / "server.py")
srv = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(srv)


def test_generate_ssp_is_valid_oscal():
    doc = srv.generate_ssp("Payments Core", impact_level="high", ts=0)
    assert doc.model == "ssp" and doc.uuid
    assert doc.sigil  # signed
    ssp = doc.document["system-security-plan"]
    assert ssp["system-characteristics"]["security-sensitivity-level"] == "high"
    assert len(ssp["control-implementation"]["implemented-requirements"]) >= 5
    # round-trips through the validator
    v = srv.validate_oscal(doc.document)
    assert v.valid is True and v.model == "ssp"


def test_generate_ssp_deterministic():
    a = srv.generate_ssp("Same System", ts=0)
    b = srv.generate_ssp("Same System", ts=0)
    assert a.document == b.document  # uuid5 + fixed ts → reproducible packages


def test_component_definition_valid():
    doc = srv.generate_component_definition("cobol-bridge-mcp", control_ids=["AC-2", "SC-7"], ts=0)
    assert doc.model == "component-definition"
    v = srv.validate_oscal(doc.document)
    assert v.valid is True


def test_validate_rejects_non_oscal():
    v = srv.validate_oscal({"not": "oscal"})
    assert v.valid is False and v.errors


def test_validate_flags_missing_metadata():
    v = srv.validate_oscal({"system-security-plan": {"uuid": "x"}})
    assert v.valid is False
    assert any("metadata" in e for e in v.errors)


def test_rfc0024_readiness_scoring():
    none = srv.rfc0024_readiness()
    assert none.ready is False and none.score == 0 and len(none.gaps) == 5
    full = srv.rfc0024_readiness(has_ssp=True, has_component_def=True, machine_readable=True, signed=True, automated_pipeline=True)
    assert full.ready is True and full.score == 100 and not full.gaps
    partial = srv.rfc0024_readiness(has_ssp=True, machine_readable=True)
    assert 0 < partial.score < 100
