"""Tests for govulncheck agent."""

import json
from pathlib import Path

import pytest

from agent.govulncheck_wrapper import GovulncheckWrapper


def test_convert_to_oxo_format():
    """Test conversion from govulncheck to OXO format."""
    wrapper = GovulncheckWrapper()
    
    # Load sample data
    fixture_path = Path(__file__).parent / "fixtures" / "sample_govulncheck.json"
    with open(fixture_path) as f:
        sample_data = json.load(f)
    
    # Convert
    result = {
        "vulnerabilities": sample_data["vulns"]
    }
    oxo_vulns = wrapper.convert_to_oxo_format(result)
    
    # Assertions
    assert len(oxo_vulns) == 1
    assert oxo_vulns[0]["vulnerability_id"] == "GO-2023-1234"
    assert oxo_vulns[0]["severity"] == "HIGH"
    assert oxo_vulns[0]["is_used"] is True  # Has callstacks
    assert oxo_vulns[0]["affected_package"] == "golang.org/x/net"
    assert oxo_vulns[0]["affected_version"] == "v0.10.0"
    assert oxo_vulns[0]["cvss_score"] == 7.5


def test_convert_to_oxo_format_no_callstacks():
    """Test conversion when vulnerability is not used."""
    wrapper = GovulncheckWrapper()
    
    # Sample data without callstacks
    sample_data = {
        "vulns": [
            {
                "osv": {
                    "id": "GO-2023-5678",
                    "summary": "Unused vulnerability",
                    "details": "This vulnerability exists but is not used",
                    "references": [],
                    "database_specific": {
                        "cvss_score": 5.0
                    }
                },
                "module": {
                    "path": "example.com/module",
                    "version": "v1.0.0"
                },
                "callstacks": []
            }
        ]
    }
    
    result = {
        "vulnerabilities": sample_data["vulns"]
    }
    oxo_vulns = wrapper.convert_to_oxo_format(result)
    
    assert len(oxo_vulns) == 1
    assert oxo_vulns[0]["is_used"] is False
    assert oxo_vulns[0]["severity"] == "MEDIUM"


def test_convert_to_oxo_format_empty():
    """Test conversion with empty results."""
    wrapper = GovulncheckWrapper()
    
    result = {
        "vulnerabilities": []
    }
    oxo_vulns = wrapper.convert_to_oxo_format(result)
    
    assert len(oxo_vulns) == 0


def test_convert_to_oxo_format_missing_fields():
    """Test conversion with missing optional fields."""
    wrapper = GovulncheckWrapper()
    
    sample_data = {
        "vulns": [
            {
                "osv": {
                    "id": "GO-2023-9999"
                },
                "module": {
                    "path": "example.com/module"
                },
                "callstacks": []
            }
        ]
    }
    
    result = {
        "vulnerabilities": sample_data["vulns"]
    }
    oxo_vulns = wrapper.convert_to_oxo_format(result)
    
    assert len(oxo_vulns) == 1
    assert oxo_vulns[0]["vulnerability_id"] == "GO-2023-9999"
    assert oxo_vulns[0]["severity"] == "UNKNOWN"
    assert "Vulnerability in example.com/module" in oxo_vulns[0]["title"]

