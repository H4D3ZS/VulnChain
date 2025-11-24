"""Header Analyzer Integration Demo

Demonstrates integration of Header Analyzer with other VulnChain modules.
Shows how to analyze headers from HTTP responses in a real workflow.
"""

from datetime import datetime
from app.core.http_models import Request, Response
from app.core.header_analyzer import HeaderAnalyzer, Severity


def demo_response_analysis():
    """Demonstrate analyzing headers from a Response object"""
    print("=" * 70)
    print("INTEGRATION DEMO: Analyzing Response Headers")
    print("=" * 70)
    
    # Simulate an HTTP response from a CTF challenge
    request = Request(
        method="GET",
        url="https://ctf-challenge.example.com",
        headers={"User-Agent": "VulnChain/1.0"}
    )
    
    response = Response(
        status_code=200,
        headers={
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": "5432",
            "Server": "nginx/1.18.0 (Ubuntu)",
            "X-Powered-By": "Express",
            "Date": "Mon, 01 Jan 2024 00:00:00 GMT",
            "Connection": "keep-alive"
        },
        body=b"<html><body>CTF Challenge</body></html>",
        text="<html><body>CTF Challenge</body></html>",
        elapsed_time=0.234,
        request=request
    )
    
    print(f"\nTarget: {response.request.url}")
    print(f"Status: {response.status_code}")
    print(f"Response Time: {response.elapsed_time}s")
    
    # Analyze headers
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze_headers(response.headers)
    score = analyzer.calculate_security_score(response.headers)
    
    print(f"\n{'='*70}")
    print("SECURITY HEADER ANALYSIS")
    print(f"{'='*70}")
    print(f"Security Score: {score.total_score}/100 (Grade: {score.grade})")
    print(f"Total Findings: {score.total_findings}")
    
    # Show critical and high severity findings
    critical_high = [
        f for f in findings 
        if f.severity in [Severity.CRITICAL, Severity.HIGH]
    ]
    
    if critical_high:
        print(f"\n⚠️  CRITICAL/HIGH Severity Issues ({len(critical_high)}):")
        for finding in critical_high:
            print(f"  • {finding.header_name}: {finding.description}")
    
    # Show information disclosure
    info_disclosure = analyzer.get_findings_by_type("information_disclosure")
    if info_disclosure:
        print(f"\n🔍 Information Disclosure ({len(info_disclosure)}):")
        for finding in info_disclosure:
            print(f"  • {finding.header_name}: {finding.current_value}")
    
    # Suggest attack vectors based on findings
    print(f"\n{'='*70}")
    print("SUGGESTED ATTACK VECTORS")
    print(f"{'='*70}")
    
    missing = analyzer.get_findings_by_type("missing")
    
    if any(f.header_name == "Content-Security-Policy" for f in missing):
        print("✓ XSS Testing - No CSP protection detected")
    
    if any(f.header_name == "X-Frame-Options" for f in missing):
        print("✓ Clickjacking - No frame protection")
    
    if any(f.header_name == "Strict-Transport-Security" for f in missing):
        print("✓ MITM Attacks - No HSTS enforcement")
    
    # Technology fingerprinting from headers
    print(f"\n{'='*70}")
    print("TECHNOLOGY FINGERPRINTING")
    print(f"{'='*70}")
    
    if "Server" in response.headers:
        print(f"Web Server: {response.headers['Server']}")
    
    if "X-Powered-By" in response.headers:
        print(f"Framework: {response.headers['X-Powered-By']}")
    
    return analyzer, score


def demo_multiple_targets():
    """Demonstrate analyzing multiple targets and comparing scores"""
    print("\n\n" + "=" * 70)
    print("INTEGRATION DEMO: Comparing Multiple Targets")
    print("=" * 70)
    
    targets = [
        {
            "name": "Target A (Insecure)",
            "url": "http://target-a.ctf",
            "headers": {
                "Content-Type": "text/html",
                "Server": "Apache/2.4.41",
                "X-Powered-By": "PHP/7.4.3"
            }
        },
        {
            "name": "Target B (Moderate)",
            "url": "https://target-b.ctf",
            "headers": {
                "Content-Type": "text/html",
                "X-Frame-Options": "SAMEORIGIN",
                "X-Content-Type-Options": "nosniff",
                "Server": "nginx"
            }
        },
        {
            "name": "Target C (Secure)",
            "url": "https://target-c.ctf",
            "headers": {
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
                "X-XSS-Protection": "1; mode=block"
            }
        }
    ]
    
    results = []
    
    for target in targets:
        analyzer = HeaderAnalyzer()
        score = analyzer.calculate_security_score(target["headers"])
        results.append({
            "name": target["name"],
            "url": target["url"],
            "score": score.total_score,
            "grade": score.grade,
            "findings": score.total_findings
        })
    
    # Display comparison
    print("\nSecurity Score Comparison:")
    print("-" * 70)
    print(f"{'Target':<25} {'Score':<15} {'Grade':<10} {'Findings':<10}")
    print("-" * 70)
    
    for result in results:
        print(f"{result['name']:<25} {result['score']:>3}/100{'':<7} {result['grade']:<10} {result['findings']:<10}")
    
    # Recommend prioritization
    print("\n" + "=" * 70)
    print("ATTACK PRIORITIZATION")
    print("=" * 70)
    
    # Sort by score (lower = more vulnerable)
    sorted_results = sorted(results, key=lambda x: x['score'])
    
    print("\nRecommended attack order (most vulnerable first):")
    for i, result in enumerate(sorted_results, 1):
        print(f"{i}. {result['name']} - Score: {result['score']}/100 (Grade: {result['grade']})")


def demo_workspace_integration():
    """Demonstrate saving findings to workspace"""
    print("\n\n" + "=" * 70)
    print("INTEGRATION DEMO: Workspace Integration")
    print("=" * 70)
    
    print("\nScenario: Analyzing target and saving findings to workspace")
    print("-" * 70)
    
    # Simulate response
    request = Request(
        method="GET",
        url="https://vulnerable-app.ctf",
        headers={"User-Agent": "VulnChain/1.0"}
    )
    
    response = Response(
        status_code=200,
        headers={
            "Content-Type": "text/html",
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3",
            "X-AspNet-Version": "4.0.30319"
        },
        body=b"<html></html>",
        text="<html></html>",
        elapsed_time=0.156,
        request=request
    )
    
    # Analyze
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze_headers(response.headers)
    score = analyzer.calculate_security_score(response.headers)
    
    print(f"\nAnalyzed: {response.request.url}")
    print(f"Security Score: {score.total_score}/100 (Grade: {score.grade})")
    print(f"Total Findings: {len(findings)}")
    
    # Simulate saving to workspace
    print("\nSaving findings to workspace...")
    
    workspace_id = "ctf-challenge-001"
    saved_findings = []
    
    for finding in findings:
        # In real implementation, this would use WorkspaceManager
        finding_data = {
            "workspace_id": workspace_id,
            "vulnerability_type": "security_header_issue",
            "severity": finding.severity.value,
            "title": f"{finding.issue_type.title()}: {finding.header_name}",
            "description": finding.description,
            "affected_url": response.request.url,
            "proof_of_concept": f"Header: {finding.header_name}\nCurrent: {finding.current_value}\nRecommended: {finding.recommended_value}",
            "remediation": finding.remediation,
            "discovered_at": datetime.now()
        }
        saved_findings.append(finding_data)
    
    print(f"✓ Saved {len(saved_findings)} findings to workspace '{workspace_id}'")
    
    # Show summary by severity
    print("\nFindings Summary:")
    severity_counts = {}
    for finding in findings:
        severity = finding.severity.value
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity.upper()}: {count}")


def main():
    """Run all integration demos"""
    print("\n")
    print("*" * 70)
    print("*" + " " * 68 + "*")
    print("*" + "  HEADER ANALYZER - INTEGRATION DEMONSTRATIONS".center(68) + "*")
    print("*" + " " * 68 + "*")
    print("*" * 70)
    
    demo_response_analysis()
    demo_multiple_targets()
    demo_workspace_integration()
    
    print("\n\n" + "=" * 70)
    print("INTEGRATION DEMOS COMPLETE")
    print("=" * 70)
    print("\nThe Header Analyzer seamlessly integrates with:")
    print("  ✓ HTTP Response objects")
    print("  ✓ Request Handler module")
    print("  ✓ Workspace Manager")
    print("  ✓ Reconnaissance workflows")
    print("  ✓ Report generation")
    print("=" * 70)


if __name__ == "__main__":
    main()
