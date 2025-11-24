"""Tests for the Report Generator module"""

import pytest
import json
from datetime import datetime, timezone

from app.core.report_generator import ReportGenerator, Finding, Evidence


@pytest.fixture
def report_generator():
    """Create a ReportGenerator instance for testing"""
    return ReportGenerator()


@pytest.fixture
def sample_findings():
    """Create sample findings for testing"""
    findings = []
    
    # Critical finding
    finding1 = Finding(
        finding_id="find_001",
        workspace_id="ws_123",
        vulnerability_type="SQL Injection",
        severity="critical",
        title="SQL Injection in Login Form",
        description="The login form is vulnerable to SQL injection attacks.",
        affected_url="https://example.com/login",
        proof_of_concept="username: admin' OR '1'='1\npassword: anything",
        remediation="Use parameterized queries to prevent SQL injection.",
        discovered_at=datetime.now(timezone.utc),
        flags=["CTF{sql_injection_found}"],
        evidence=[
            Evidence(
                evidence_type="request",
                data="POST /login HTTP/1.1\nHost: example.com\n\nusername=admin' OR '1'='1",
                description="Malicious SQL injection request",
                timestamp=datetime.now(timezone.utc),
            ),
        ],
    )
    findings.append(finding1)
    
    # High finding
    finding2 = Finding(
        finding_id="find_002",
        workspace_id="ws_123",
        vulnerability_type="XSS",
        severity="high",
        title="Reflected XSS in Search Parameter",
        description="The search parameter reflects user input without sanitization.",
        affected_url="https://example.com/search?q=<script>alert(1)</script>",
        proof_of_concept="<script>alert(document.cookie)</script>",
        remediation="Sanitize and encode all user input before rendering.",
        discovered_at=datetime.now(timezone.utc),
        flags=[],
        evidence=[],
    )
    findings.append(finding2)
    
    return findings


def test_report_generator_initialization(report_generator):
    """Test report generator initialization"""
    assert report_generator is not None


def test_generate_markdown_report(report_generator, sample_findings):
    """Test generating Markdown report"""
    report = report_generator.generate_report(
        findings=sample_findings,
        format="markdown",
        workspace_name="Test Workspace",
        target_url="https://example.com",
    )
    
    assert report is not None
    assert isinstance(report, bytes)
    
    # Decode and check content
    content = report.decode("utf-8")
    assert "VulnChain Security Assessment Report" in content
    assert "Test Workspace" in content
    assert "https://example.com" in content
    assert "SQL Injection in Login Form" in content
    assert "Reflected XSS in Search Parameter" in content
    assert "CTF{sql_injection_found}" in content


def test_generate_html_report(report_generator, sample_findings):
    """Test generating HTML report"""
    report = report_generator.generate_report(
        findings=sample_findings,
        format="html",
        workspace_name="Test Workspace",
        target_url="https://example.com",
    )
    
    assert report is not None
    assert isinstance(report, bytes)
    
    # Decode and check content
    content = report.decode("utf-8")
    assert "<!DOCTYPE html>" in content
    assert "<html>" in content
    assert "VulnChain Security Assessment Report" in content
    assert "Test Workspace" in content
    assert "SQL Injection in Login Form" in content
    assert "severity-critical" in content
    assert "severity-high" in content


def test_generate_json_report(report_generator, sample_findings):
    """Test generating JSON report"""
    report = report_generator.generate_report(
        findings=sample_findings,
        format="json",
        workspace_name="Test Workspace",
        target_url="https://example.com",
    )
    
    assert report is not None
    assert isinstance(report, bytes)
    
    # Parse JSON
    data = json.loads(report.decode("utf-8"))
    
    assert data["report_type"] == "vulnchain_security_assessment"
    assert data["workspace_name"] == "Test Workspace"
    assert data["target_url"] == "https://example.com"
    assert data["summary"]["total_findings"] == 2
    assert data["summary"]["by_severity"]["critical"] == 1
    assert data["summary"]["by_severity"]["high"] == 1
    assert len(data["findings"]) == 2
    
    # Check first finding
    finding = data["findings"][0]
    assert finding["title"] == "SQL Injection in Login Form"
    assert finding["severity"] == "critical"
    assert finding["vulnerability_type"] == "SQL Injection"
    assert "CTF{sql_injection_found}" in finding["flags"]


def test_generate_pdf_report(report_generator, sample_findings):
    """Test generating PDF report (currently returns HTML)"""
    report = report_generator.generate_report(
        findings=sample_findings,
        format="pdf",
        workspace_name="Test Workspace",
        target_url="https://example.com",
    )
    
    assert report is not None
    assert isinstance(report, bytes)
    
    # Currently returns HTML, so check for HTML content
    content = report.decode("utf-8")
    assert "VulnChain Security Assessment Report" in content


def test_unsupported_format(report_generator, sample_findings):
    """Test that unsupported format raises ValueError"""
    with pytest.raises(ValueError, match="Unsupported format"):
        report_generator.generate_report(
            findings=sample_findings,
            format="xml",
        )


def test_markdown_report_severity_counts(report_generator, sample_findings):
    """Test that Markdown report includes severity counts"""
    report = report_generator.generate_report(
        findings=sample_findings,
        format="markdown",
    )
    
    content = report.decode("utf-8")
    assert "Critical: 1" in content
    assert "High: 1" in content
    assert "Medium: 0" in content


def test_html_report_styling(report_generator, sample_findings):
    """Test that HTML report includes CSS styling"""
    report = report_generator.generate_report(
        findings=sample_findings,
        format="html",
    )
    
    content = report.decode("utf-8")
    assert "<style>" in content
    assert "font-family" in content
    assert ".severity-critical" in content


def test_json_report_structure(report_generator, sample_findings):
    """Test JSON report structure"""
    report = report_generator.generate_report(
        findings=sample_findings,
        format="json",
    )
    
    data = json.loads(report.decode("utf-8"))
    
    # Check required fields
    assert "report_type" in data
    assert "generated_at" in data
    assert "summary" in data
    assert "findings" in data
    
    # Check summary structure
    assert "total_findings" in data["summary"]
    assert "by_severity" in data["summary"]
    
    # Check finding structure
    finding = data["findings"][0]
    assert "finding_id" in finding
    assert "vulnerability_type" in finding
    assert "severity" in finding
    assert "title" in finding
    assert "description" in finding
    assert "affected_url" in finding
    assert "proof_of_concept" in finding
    assert "remediation" in finding
    assert "discovered_at" in finding
    assert "flags" in finding
    assert "evidence" in finding


def test_report_with_no_findings(report_generator):
    """Test generating report with no findings"""
    report = report_generator.generate_report(
        findings=[],
        format="markdown",
    )
    
    content = report.decode("utf-8")
    assert "Total findings: 0" in content


def test_report_with_metadata(report_generator, sample_findings):
    """Test generating report with custom metadata"""
    metadata = {
        "scan_duration": "5 minutes",
        "tools_used": ["VulnChain", "SQLMap"],
    }
    
    report = report_generator.generate_report(
        findings=sample_findings,
        format="json",
        metadata=metadata,
    )
    
    data = json.loads(report.decode("utf-8"))
    assert data["metadata"]["scan_duration"] == "5 minutes"
    assert "VulnChain" in data["metadata"]["tools_used"]


def test_html_escape(report_generator):
    """Test HTML escaping in HTML reports"""
    finding = Finding(
        finding_id="find_001",
        workspace_id="ws_123",
        vulnerability_type="XSS",
        severity="high",
        title="XSS with <script> tag",
        description="Test with <script>alert('xss')</script>",
        affected_url="https://example.com",
        proof_of_concept="<script>alert(1)</script>",
        remediation="Sanitize input",
        discovered_at=datetime.now(timezone.utc),
    )
    
    report = report_generator.generate_report(
        findings=[finding],
        format="html",
    )
    
    content = report.decode("utf-8")
    # Check that HTML is escaped
    assert "&lt;script&gt;" in content
    assert "<script>alert" not in content  # Should be escaped


def test_markdown_code_blocks(report_generator, sample_findings):
    """Test that Markdown report includes code blocks for PoC"""
    report = report_generator.generate_report(
        findings=sample_findings,
        format="markdown",
    )
    
    content = report.decode("utf-8")
    assert "```" in content  # Code block markers
    assert "Proof of Concept:" in content


def test_evidence_in_reports(report_generator, sample_findings):
    """Test that evidence is included in reports"""
    # Markdown
    md_report = report_generator.generate_report(
        findings=sample_findings,
        format="markdown",
    )
    md_content = md_report.decode("utf-8")
    assert "Evidence:" in md_content
    assert "Malicious SQL injection request" in md_content
    
    # HTML
    html_report = report_generator.generate_report(
        findings=sample_findings,
        format="html",
    )
    html_content = html_report.decode("utf-8")
    assert "Evidence" in html_content
    
    # JSON
    json_report = report_generator.generate_report(
        findings=sample_findings,
        format="json",
    )
    json_data = json.loads(json_report.decode("utf-8"))
    assert len(json_data["findings"][0]["evidence"]) > 0


def test_flags_in_reports(report_generator, sample_findings):
    """Test that flags are included in reports"""
    # Markdown
    md_report = report_generator.generate_report(
        findings=sample_findings,
        format="markdown",
    )
    md_content = md_report.decode("utf-8")
    assert "Flags Captured:" in md_content
    assert "CTF{sql_injection_found}" in md_content
    
    # HTML
    html_report = report_generator.generate_report(
        findings=sample_findings,
        format="html",
    )
    html_content = html_report.decode("utf-8")
    assert "Flags Captured" in html_content
    
    # JSON
    json_report = report_generator.generate_report(
        findings=sample_findings,
        format="json",
    )
    json_data = json.loads(json_report.decode("utf-8"))
    assert "CTF{sql_injection_found}" in json_data["findings"][0]["flags"]


def test_multiple_severity_levels(report_generator):
    """Test report with findings of all severity levels"""
    findings = []
    for severity in ["critical", "high", "medium", "low", "info"]:
        finding = Finding(
            finding_id=f"find_{severity}",
            workspace_id="ws_123",
            vulnerability_type="Test",
            severity=severity,
            title=f"{severity.capitalize()} Finding",
            description=f"Test {severity} finding",
            affected_url="https://example.com",
            proof_of_concept="test",
            remediation="test",
            discovered_at=datetime.now(timezone.utc),
        )
        findings.append(finding)
    
    report = report_generator.generate_report(
        findings=findings,
        format="json",
    )
    
    data = json.loads(report.decode("utf-8"))
    assert data["summary"]["by_severity"]["critical"] == 1
    assert data["summary"]["by_severity"]["high"] == 1
    assert data["summary"]["by_severity"]["medium"] == 1
    assert data["summary"]["by_severity"]["low"] == 1
    assert data["summary"]["by_severity"]["info"] == 1
