"""Header Analyzer Demo

Demonstrates the usage of the Header Analyzer module for security header analysis.

This example shows:
1. Basic header analysis
2. Security score calculation
3. Report generation in multiple formats
4. Filtering findings by severity and type
"""

import asyncio
from app.core.header_analyzer import HeaderAnalyzer, Severity


def demo_basic_analysis():
    """Demonstrate basic header analysis"""
    print("=" * 70)
    print("DEMO 1: Basic Header Analysis")
    print("=" * 70)
    
    analyzer = HeaderAnalyzer()
    
    # Example headers from a typical web application
    headers = {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Length": "1234",
        "Date": "Mon, 01 Jan 2024 00:00:00 GMT",
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3"
    }
    
    print("\nAnalyzing headers:")
    for key, value in headers.items():
        print(f"  {key}: {value}")
    
    findings = analyzer.analyze_headers(headers)
    
    print(f"\nFound {len(findings)} security issues:")
    for i, finding in enumerate(findings, 1):
        print(f"\n[{i}] {finding.header_name}")
        print(f"    Severity: {finding.severity.value.upper()}")
        print(f"    Type: {finding.issue_type}")
        print(f"    Description: {finding.description}")


def demo_security_score():
    """Demonstrate security score calculation"""
    print("\n\n" + "=" * 70)
    print("DEMO 2: Security Score Calculation")
    print("=" * 70)
    
    analyzer = HeaderAnalyzer()
    
    # Poor security headers
    poor_headers = {
        "Content-Type": "text/html",
        "Server": "Apache/2.4.41",
        "X-Powered-By": "PHP/7.4.3"
    }
    
    print("\nScenario 1: Poor Security Headers")
    print("-" * 70)
    score = analyzer.calculate_security_score(poor_headers)
    print(f"Security Score: {score.total_score}/100 (Grade: {score.grade})")
    print(f"Total Findings: {score.total_findings}")
    print(f"Security Headers Present: {score.security_headers_present}/7")
    print(f"Security Headers Missing: {score.security_headers_missing}")
    
    # Good security headers
    analyzer2 = HeaderAnalyzer()
    good_headers = {
        "Content-Type": "text/html",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "X-XSS-Protection": "1; mode=block"
    }
    
    print("\n\nScenario 2: Good Security Headers")
    print("-" * 70)
    score2 = analyzer2.calculate_security_score(good_headers)
    print(f"Security Score: {score2.total_score}/100 (Grade: {score2.grade})")
    print(f"Total Findings: {score2.total_findings}")
    print(f"Security Headers Present: {score2.security_headers_present}/7")
    print(f"Security Headers Missing: {score2.security_headers_missing}")


def demo_misconfiguration_detection():
    """Demonstrate misconfiguration detection"""
    print("\n\n" + "=" * 70)
    print("DEMO 3: Misconfiguration Detection")
    print("=" * 70)
    
    analyzer = HeaderAnalyzer()
    
    # Headers with misconfigurations
    headers = {
        "Content-Security-Policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
        "Strict-Transport-Security": "max-age=3600",  # Too short
        "X-Frame-Options": "SAMEORIGIN"
    }
    
    print("\nAnalyzing headers with misconfigurations:")
    for key, value in headers.items():
        print(f"  {key}: {value}")
    
    findings = analyzer.analyze_headers(headers)
    
    # Filter misconfigured headers
    misconfigured = analyzer.get_findings_by_type("misconfigured")
    
    print(f"\nFound {len(misconfigured)} misconfiguration(s):")
    for finding in misconfigured:
        print(f"\n- {finding.header_name}")
        print(f"  Issue: {finding.description}")
        print(f"  Current: {finding.current_value}")
        print(f"  Recommended: {finding.recommended_value}")


def demo_information_disclosure():
    """Demonstrate information disclosure detection"""
    print("\n\n" + "=" * 70)
    print("DEMO 4: Information Disclosure Detection")
    print("=" * 70)
    
    analyzer = HeaderAnalyzer()
    
    # Headers that disclose information
    headers = {
        "Server": "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f",
        "X-Powered-By": "PHP/7.4.3",
        "X-AspNet-Version": "4.0.30319",
        "X-AspNetMvc-Version": "5.2",
        "X-Generator": "WordPress 5.8"
    }
    
    print("\nAnalyzing headers for information disclosure:")
    for key, value in headers.items():
        print(f"  {key}: {value}")
    
    findings = analyzer.analyze_headers(headers)
    
    # Filter information disclosure
    info_disclosure = analyzer.get_findings_by_type("information_disclosure")
    
    print(f"\nFound {len(info_disclosure)} information disclosure issue(s):")
    for finding in info_disclosure:
        print(f"\n- {finding.header_name}: {finding.current_value}")
        print(f"  Risk: {finding.description}")
        print(f"  Remediation: {finding.remediation}")


def demo_report_generation():
    """Demonstrate report generation in different formats"""
    print("\n\n" + "=" * 70)
    print("DEMO 5: Report Generation")
    print("=" * 70)
    
    analyzer = HeaderAnalyzer()
    
    headers = {
        "Content-Type": "text/html",
        "Content-Security-Policy": "default-src 'unsafe-inline'",
        "Server": "Apache/2.4.41",
        "X-Powered-By": "PHP/7.4.3"
    }
    
    # Text report
    print("\n--- TEXT REPORT ---")
    text_report = analyzer.generate_report(headers, format="text")
    print(text_report)
    
    # Markdown report (just show first few lines)
    print("\n\n--- MARKDOWN REPORT (excerpt) ---")
    markdown_report = analyzer.generate_report(headers, format="markdown")
    print("\n".join(markdown_report.split("\n")[:15]))
    print("...")
    
    # JSON report
    print("\n\n--- JSON REPORT ---")
    json_report = analyzer.generate_report(headers, format="json")
    print(json_report)


def demo_filtering_findings():
    """Demonstrate filtering findings by severity"""
    print("\n\n" + "=" * 70)
    print("DEMO 6: Filtering Findings by Severity")
    print("=" * 70)
    
    analyzer = HeaderAnalyzer()
    
    headers = {
        "Content-Security-Policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
        "Strict-Transport-Security": "max-age=0",
        "Server": "Apache/2.4.41",
        "X-Powered-By": "PHP/7.4.3"
    }
    
    analyzer.analyze_headers(headers)
    
    # Get high severity findings
    high_findings = analyzer.get_findings_by_severity(Severity.HIGH)
    print(f"\nHIGH Severity Findings ({len(high_findings)}):")
    for finding in high_findings:
        print(f"  - {finding.header_name}: {finding.description}")
    
    # Get medium severity findings
    medium_findings = analyzer.get_findings_by_severity(Severity.MEDIUM)
    print(f"\nMEDIUM Severity Findings ({len(medium_findings)}):")
    for finding in medium_findings:
        print(f"  - {finding.header_name}: {finding.description}")
    
    # Get low severity findings
    low_findings = analyzer.get_findings_by_severity(Severity.LOW)
    print(f"\nLOW Severity Findings ({len(low_findings)}):")
    for finding in low_findings:
        print(f"  - {finding.header_name}: {finding.description}")


def demo_real_world_scenario():
    """Demonstrate analysis of real-world scenario"""
    print("\n\n" + "=" * 70)
    print("DEMO 7: Real-World CTF Scenario")
    print("=" * 70)
    
    print("\nScenario: Analyzing a CTF challenge web application")
    print("-" * 70)
    
    analyzer = HeaderAnalyzer()
    
    # Typical CTF challenge headers (intentionally insecure)
    ctf_headers = {
        "Content-Type": "text/html; charset=utf-8",
        "Server": "nginx/1.18.0 (Ubuntu)",
        "X-Powered-By": "Express",
        "Date": "Mon, 01 Jan 2024 00:00:00 GMT",
        "Connection": "keep-alive"
    }
    
    print("\nTarget headers:")
    for key, value in ctf_headers.items():
        print(f"  {key}: {value}")
    
    findings = analyzer.analyze_headers(ctf_headers)
    score = analyzer.calculate_security_score(ctf_headers)
    
    print(f"\n{'='*70}")
    print(f"SECURITY ASSESSMENT")
    print(f"{'='*70}")
    print(f"Overall Score: {score.total_score}/100 (Grade: {score.grade})")
    print(f"Total Issues: {score.total_findings}")
    
    print(f"\nIssue Breakdown:")
    print(f"  - Missing Headers: {len(analyzer.get_findings_by_type('missing'))}")
    print(f"  - Misconfigurations: {len(analyzer.get_findings_by_type('misconfigured'))}")
    print(f"  - Info Disclosure: {len(analyzer.get_findings_by_type('information_disclosure'))}")
    
    print(f"\nSeverity Breakdown:")
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = score.findings_by_severity[severity]
        if count > 0:
            print(f"  - {severity.value.upper()}: {count}")
    
    print(f"\n{'='*70}")
    print("EXPLOITATION OPPORTUNITIES")
    print(f"{'='*70}")
    
    # Identify potential attack vectors based on missing headers
    missing = analyzer.get_findings_by_type("missing")
    
    if any(f.header_name == "Content-Security-Policy" for f in missing):
        print("\n✓ XSS attacks likely possible (no CSP)")
    
    if any(f.header_name == "X-Frame-Options" for f in missing):
        print("✓ Clickjacking attacks possible (no X-Frame-Options)")
    
    if any(f.header_name == "Strict-Transport-Security" for f in missing):
        print("✓ MITM attacks possible (no HSTS)")
    
    # Check for information disclosure
    info_disclosure = analyzer.get_findings_by_type("information_disclosure")
    if info_disclosure:
        print(f"\n✓ Technology stack revealed:")
        for finding in info_disclosure:
            print(f"  - {finding.header_name}: {finding.current_value}")


def main():
    """Run all demos"""
    print("\n")
    print("*" * 70)
    print("*" + " " * 68 + "*")
    print("*" + "  HEADER ANALYZER MODULE - DEMONSTRATION".center(68) + "*")
    print("*" + " " * 68 + "*")
    print("*" * 70)
    
    demo_basic_analysis()
    demo_security_score()
    demo_misconfiguration_detection()
    demo_information_disclosure()
    demo_report_generation()
    demo_filtering_findings()
    demo_real_world_scenario()
    
    print("\n\n" + "=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)
    print("\nThe Header Analyzer module provides comprehensive security header")
    print("analysis for CTF challenges and penetration testing engagements.")
    print("\nKey capabilities:")
    print("  ✓ Identifies missing security headers")
    print("  ✓ Detects weak configurations")
    print("  ✓ Flags information disclosure")
    print("  ✓ Calculates security scores")
    print("  ✓ Generates detailed reports")
    print("=" * 70)


if __name__ == "__main__":
    main()
