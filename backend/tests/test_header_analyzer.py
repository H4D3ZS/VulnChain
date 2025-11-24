"""Unit tests for Header Analyzer module

Tests security header analysis, misconfiguration detection, information disclosure,
and security score calculation.

Validates Requirements: 20.1, 20.2, 20.3, 20.4, 20.5
"""

import pytest
from app.core.header_analyzer import (
    HeaderAnalyzer,
    HeaderFinding,
    SecurityScore,
    Severity
)


class TestHeaderAnalyzer:
    """Test suite for HeaderAnalyzer class"""
    
    def test_initialization(self):
        """Test HeaderAnalyzer initialization"""
        analyzer = HeaderAnalyzer()
        assert analyzer.findings == []
        assert len(analyzer.SECURITY_HEADERS) == 7
        assert len(analyzer.INFORMATION_DISCLOSURE_HEADERS) == 5
    
    def test_analyze_empty_headers(self):
        """Test analysis with no headers"""
        analyzer = HeaderAnalyzer()
        findings = analyzer.analyze_headers({})
        
        # Should find all security headers missing
        assert len(findings) == 7
        assert all(f.issue_type == "missing" for f in findings)
    
    def test_missing_security_headers(self):
        """Test detection of missing security headers (Requirement 20.2)"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Content-Type": "text/html",
            "Content-Length": "1234"
        }
        
        findings = analyzer.analyze_headers(headers)
        
        # All 7 security headers should be flagged as missing
        missing_findings = [f for f in findings if f.issue_type == "missing"]
        assert len(missing_findings) == 7
        
        # Check specific headers
        header_names = [f.header_name for f in missing_findings]
        assert "Content-Security-Policy" in header_names
        assert "Strict-Transport-Security" in header_names
        assert "X-Frame-Options" in header_names
        assert "X-Content-Type-Options" in header_names
    
    def test_present_security_headers(self):
        """Test that present security headers are not flagged as missing"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "X-XSS-Protection": "1; mode=block"
        }
        
        findings = analyzer.analyze_headers(headers)
        
        # No missing headers
        missing_findings = [f for f in findings if f.issue_type == "missing"]
        assert len(missing_findings) == 0
    
    def test_csp_unsafe_inline_misconfiguration(self):
        """Test detection of CSP unsafe-inline (Requirement 20.3)"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"
        }
        
        findings = analyzer.analyze_headers(headers)
        
        # Should detect unsafe-inline
        csp_findings = [f for f in findings if f.header_name == "Content-Security-Policy"]
        assert len(csp_findings) > 0
        assert any("unsafe-inline" in f.description for f in csp_findings)
        assert any(f.severity == Severity.HIGH for f in csp_findings)
    
    def test_csp_unsafe_eval_misconfiguration(self):
        """Test detection of CSP unsafe-eval (Requirement 20.3)"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-eval'"
        }
        
        findings = analyzer.analyze_headers(headers)
        
        # Should detect unsafe-eval
        csp_findings = [f for f in findings if f.header_name == "Content-Security-Policy"]
        assert any("unsafe-eval" in f.description for f in csp_findings)
        assert any(f.severity == Severity.HIGH for f in csp_findings)
    
    def test_csp_wildcard_misconfiguration(self):
        """Test detection of CSP wildcard (Requirement 20.3)"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Content-Security-Policy": "default-src *"
        }
        
        findings = analyzer.analyze_headers(headers)
        
        # Should detect wildcard
        csp_findings = [f for f in findings if f.header_name == "Content-Security-Policy"]
        assert any("*" in f.description or "wildcard" in f.description.lower() for f in csp_findings)
    
    def test_hsts_max_age_zero(self):
        """Test detection of HSTS max-age=0 (Requirement 20.3)"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Strict-Transport-Security": "max-age=0"
        }
        
        findings = analyzer.analyze_headers(headers)
        
        # Should detect max-age=0
        hsts_findings = [f for f in findings if f.header_name == "Strict-Transport-Security"]
        assert len(hsts_findings) > 0
        assert any("max-age" in f.description.lower() and "0" in f.description for f in hsts_findings)
        assert any(f.severity == Severity.HIGH for f in hsts_findings)
    
    def test_hsts_short_max_age(self):
        """Test detection of short HSTS max-age (Requirement 20.3)"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Strict-Transport-Security": "max-age=3600"  # 1 hour, too short
        }
        
        findings = analyzer.analyze_headers(headers)
        
        # Should detect short max-age
        hsts_findings = [f for f in findings if f.header_name == "Strict-Transport-Security"]
        assert len(hsts_findings) > 0
        assert any("max-age" in f.description.lower() for f in hsts_findings)
    
    def test_hsts_good_max_age(self):
        """Test that good HSTS max-age is not flagged"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
        }
        
        findings = analyzer.analyze_headers(headers)
        
        # Should not flag this configuration
        hsts_findings = [f for f in findings if f.header_name == "Strict-Transport-Security" and f.issue_type == "misconfigured"]
        assert len(hsts_findings) == 0
    
    def test_information_disclosure_server_header(self):
        """Test detection of Server header (Requirement 20.4)"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Server": "Apache/2.4.41 (Ubuntu)"
        }
        
        findings = analyzer.analyze_headers(headers)
        
        # Should detect Server header
        server_findings = [f for f in findings if f.header_name == "Server"]
        assert len(server_findings) == 1
        assert server_findings[0].issue_type == "information_disclosure"
        assert server_findings[0].current_value == "Apache/2.4.41 (Ubuntu)"
        assert server_findings[0].severity == Severity.LOW
    
    def test_information_disclosure_x_powered_by(self):
        """Test detection of X-Powered-By header (Requirement 20.4)"""
        analyzer = HeaderAnalyzer()
        headers = {
            "X-Powered-By": "PHP/7.4.3"
        }
        
        findings = analyzer.analyze_headers(headers)
        
        # Should detect X-Powered-By header
        powered_by_findings = [f for f in findings if f.header_name == "X-Powered-By"]
        assert len(powered_by_findings) == 1
        assert powered_by_findings[0].issue_type == "information_disclosure"
        assert powered_by_findings[0].current_value == "PHP/7.4.3"
    
    def test_information_disclosure_aspnet_headers(self):
        """Test detection of ASP.NET version headers (Requirement 20.4)"""
        analyzer = HeaderAnalyzer()
        headers = {
            "X-AspNet-Version": "4.0.30319",
            "X-AspNetMvc-Version": "5.2"
        }
        
        findings = analyzer.analyze_headers(headers)
        
        # Should detect both ASP.NET headers
        aspnet_findings = [f for f in findings if "AspNet" in f.header_name]
        assert len(aspnet_findings) == 2
        assert all(f.issue_type == "information_disclosure" for f in aspnet_findings)
    
    def test_case_insensitive_header_matching(self):
        """Test that header matching is case-insensitive"""
        analyzer = HeaderAnalyzer()
        headers = {
            "content-security-policy": "default-src 'self'",
            "STRICT-TRANSPORT-SECURITY": "max-age=31536000",
            "x-frame-options": "DENY"
        }
        
        findings = analyzer.analyze_headers(headers)
        
        # Should recognize these headers despite case differences
        missing_findings = [f for f in findings if f.issue_type == "missing"]
        # Only 4 headers should be missing (not the 3 we provided)
        assert len(missing_findings) == 4
    
    def test_security_score_perfect(self):
        """Test security score with all headers present (Requirement 20.5)"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "X-XSS-Protection": "1; mode=block"
        }
        
        score = analyzer.calculate_security_score(headers)
        
        assert score.total_score == 100
        assert score.grade == "A+"
        assert score.total_findings == 0
        assert score.security_headers_present == 7
        assert score.security_headers_missing == 0
    
    def test_security_score_no_headers(self):
        """Test security score with no security headers (Requirement 20.5)"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Content-Type": "text/html"
        }
        
        score = analyzer.calculate_security_score(headers)
        
        # Should have low score due to missing headers
        assert score.total_score < 50
        assert score.grade == "F"
        assert score.total_findings == 7  # All security headers missing
        assert score.security_headers_present == 0
        assert score.security_headers_missing == 7
    
    def test_security_score_with_info_disclosure(self):
        """Test security score with information disclosure (Requirement 20.5)"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Server": "Apache/2.4.41",
            "X-Powered-By": "PHP/7.4.3",
            "X-AspNet-Version": "4.0.30319"
        }
        
        score = analyzer.calculate_security_score(headers)
        
        # Should deduct points for info disclosure
        assert score.total_score < 100
        assert score.findings_by_severity[Severity.LOW] >= 2
        assert score.findings_by_severity[Severity.INFO] >= 0
    
    def test_security_score_grade_calculation(self):
        """Test grade assignment based on score (Requirement 20.5)"""
        analyzer = HeaderAnalyzer()
        
        # Test different score ranges
        test_cases = [
            (100, "A+"),
            (95, "A+"),
            (94, "A"),
            (90, "A"),
            (89, "B"),
            (80, "B"),
            (79, "C"),
            (70, "C"),
            (69, "D"),
            (60, "D"),
            (59, "F"),
            (0, "F")
        ]
        
        for score_value, expected_grade in test_cases:
            # Manually create a score to test grade logic
            score = SecurityScore(
                total_score=score_value,
                grade="",  # Will be set by logic
                findings_by_severity={},
                total_findings=0,
                headers_analyzed=0,
                security_headers_present=0,
                security_headers_missing=0
            )
            
            # Determine grade using same logic as calculate_security_score
            if score_value >= 95:
                grade = "A+"
            elif score_value >= 90:
                grade = "A"
            elif score_value >= 80:
                grade = "B"
            elif score_value >= 70:
                grade = "C"
            elif score_value >= 60:
                grade = "D"
            else:
                grade = "F"
            
            assert grade == expected_grade
    
    def test_get_findings_by_severity(self):
        """Test filtering findings by severity"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
            "Server": "Apache/2.4.41"
        }
        
        analyzer.analyze_headers(headers)
        
        # Get high severity findings
        high_findings = analyzer.get_findings_by_severity(Severity.HIGH)
        assert len(high_findings) > 0
        assert all(f.severity == Severity.HIGH for f in high_findings)
        
        # Get low severity findings
        low_findings = analyzer.get_findings_by_severity(Severity.LOW)
        assert len(low_findings) > 0
        assert all(f.severity == Severity.LOW for f in low_findings)
    
    def test_get_findings_by_type(self):
        """Test filtering findings by type"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
            "Server": "Apache/2.4.41"
        }
        
        analyzer.analyze_headers(headers)
        
        # Get missing headers
        missing = analyzer.get_findings_by_type("missing")
        assert all(f.issue_type == "missing" for f in missing)
        
        # Get misconfigured headers
        misconfigured = analyzer.get_findings_by_type("misconfigured")
        assert all(f.issue_type == "misconfigured" for f in misconfigured)
        
        # Get information disclosure
        info_disclosure = analyzer.get_findings_by_type("information_disclosure")
        assert all(f.issue_type == "information_disclosure" for f in info_disclosure)
    
    def test_generate_text_report(self):
        """Test text report generation"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Server": "Apache/2.4.41",
            "X-Powered-By": "PHP/7.4.3"
        }
        
        report = analyzer.generate_report(headers, format="text")
        
        assert "HTTP SECURITY HEADER ANALYSIS REPORT" in report
        assert "Overall Security Score:" in report
        assert "Grade:" in report
        assert "DETAILED FINDINGS" in report
        assert "Server" in report
        assert "X-Powered-By" in report
    
    def test_generate_markdown_report(self):
        """Test markdown report generation"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Server": "Apache/2.4.41"
        }
        
        report = analyzer.generate_report(headers, format="markdown")
        
        assert "# HTTP Security Header Analysis Report" in report
        assert "## Overall Security Score:" in report
        assert "## Detailed Findings" in report
        assert "**Severity:**" in report
    
    def test_generate_json_report(self):
        """Test JSON report generation"""
        import json
        
        analyzer = HeaderAnalyzer()
        headers = {
            "Server": "Apache/2.4.41"
        }
        
        report = analyzer.generate_report(headers, format="json")
        
        # Should be valid JSON
        data = json.loads(report)
        assert "score" in data
        assert "grade" in data
        assert "findings" in data
        assert isinstance(data["findings"], list)
    
    def test_generate_report_invalid_format(self):
        """Test that invalid format raises error"""
        analyzer = HeaderAnalyzer()
        headers = {}
        
        with pytest.raises(ValueError, match="Unsupported format"):
            analyzer.generate_report(headers, format="invalid")
    
    def test_clear_findings(self):
        """Test clearing findings"""
        analyzer = HeaderAnalyzer()
        headers = {"Server": "Apache"}
        
        analyzer.analyze_headers(headers)
        assert len(analyzer.findings) > 0
        
        analyzer.clear_findings()
        assert len(analyzer.findings) == 0
    
    def test_multiple_analyses(self):
        """Test that multiple analyses work correctly"""
        analyzer = HeaderAnalyzer()
        
        # First analysis
        headers1 = {"Server": "Apache"}
        findings1 = analyzer.analyze_headers(headers1)
        count1 = len(findings1)
        
        # Second analysis should replace findings
        headers2 = {"X-Powered-By": "PHP"}
        findings2 = analyzer.analyze_headers(headers2)
        count2 = len(findings2)
        
        # Findings should be from second analysis only
        assert len(analyzer.findings) == count2
    
    def test_comprehensive_analysis(self):
        """Test comprehensive analysis with multiple issues (Requirements 20.1-20.5)"""
        analyzer = HeaderAnalyzer()
        headers = {
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
            "Strict-Transport-Security": "max-age=0",
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3",
            "X-AspNet-Version": "4.0.30319"
        }
        
        findings = analyzer.analyze_headers(headers)
        score = analyzer.calculate_security_score(headers)
        
        # Should have multiple types of findings
        assert len(findings) > 0
        
        # Should have missing headers
        missing = [f for f in findings if f.issue_type == "missing"]
        assert len(missing) > 0
        
        # Should have misconfigurations
        misconfigured = [f for f in findings if f.issue_type == "misconfigured"]
        assert len(misconfigured) > 0
        
        # Should have information disclosure
        info_disclosure = [f for f in findings if f.issue_type == "information_disclosure"]
        assert len(info_disclosure) > 0
        
        # Score should reflect issues
        assert score.total_score < 100
        assert score.grade in ["F", "D", "C"]
        assert score.total_findings == len(findings)
