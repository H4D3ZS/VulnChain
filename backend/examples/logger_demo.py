"""Demo of the Logger and Report Generator functionality"""

import asyncio
from datetime import datetime, timezone

from app.core.logger import Logger
from app.core.http_models import Request, Response


async def main():
    """Demonstrate logger functionality"""
    print("=== VulnChain Logger Demo ===\n")
    
    # Create logger
    logger = Logger()
    
    # 1. Log HTTP request and response
    print("1. Logging HTTP request and response...")
    request = Request(
        method="GET",
        url="https://example.com/api/users",
        headers={"User-Agent": "VulnChain/1.0"},
    )
    
    response = Response(
        status_code=200,
        headers={"Content-Type": "application/json"},
        body=b'{"users": ["admin", "user1"], "flag": "CTF{demo_flag_123}"}',
        text='{"users": ["admin", "user1"], "flag": "CTF{demo_flag_123}"}',
        elapsed_time=0.234,
        request=request,
    )
    
    logger.log_request(request)
    logger.log_response(response)
    print(f"  ✓ Logged request and response")
    print(f"  ✓ Automatically extracted flag: CTF{{demo_flag_123}}\n")
    
    # 2. Log security findings
    print("2. Logging security findings...")
    finding1 = {
        "finding_id": "find_001",
        "title": "SQL Injection in Login Form",
        "severity": "CRITICAL",
        "vulnerability_type": "SQL Injection",
        "description": "The login form is vulnerable to SQL injection attacks.",
        "affected_url": "https://example.com/login",
        "proof_of_concept": "username: admin' OR '1'='1\npassword: anything",
        "remediation": "Use parameterized queries to prevent SQL injection.",
        "workspace_id": "demo_workspace",
        "flags": ["CTF{sql_injection_found}"],
    }
    
    finding2 = {
        "finding_id": "find_002",
        "title": "Reflected XSS in Search",
        "severity": "HIGH",
        "vulnerability_type": "XSS",
        "description": "The search parameter reflects user input without sanitization.",
        "affected_url": "https://example.com/search?q=<script>alert(1)</script>",
        "proof_of_concept": "<script>alert(document.cookie)</script>",
        "remediation": "Sanitize and encode all user input before rendering.",
        "workspace_id": "demo_workspace",
    }
    
    logger.log_finding(finding1)
    logger.log_finding(finding2)
    print(f"  ✓ Logged 2 security findings\n")
    
    # 3. Search and filter logs
    print("3. Searching and filtering logs...")
    all_entries = logger.get_entries()
    print(f"  Total log entries: {len(all_entries)}")
    
    flags = logger.get_flags()
    print(f"  Flag entries: {len(flags)}")
    for flag_entry in flags:
        print(f"    - {flag_entry.data['flag']}")
    
    findings = logger.get_findings()
    print(f"  Finding entries: {len(findings)}")
    for finding_entry in findings:
        print(f"    - {finding_entry.message} ({finding_entry.level.value})")
    print()
    
    # 4. Export logs
    print("4. Exporting logs...")
    json_logs = logger.export_logs(format="json")
    print(f"  ✓ Exported logs as JSON ({len(json_logs)} bytes)")
    
    jsonl_logs = logger.export_logs(format="jsonl")
    print(f"  ✓ Exported logs as JSON Lines ({len(jsonl_logs)} bytes)\n")
    
    # 5. Generate reports
    print("5. Generating security assessment reports...")
    
    # Markdown report
    md_report = logger.generate_report(
        format="markdown",
        workspace_id="demo_workspace",
        workspace_name="Demo Workspace",
        target_url="https://example.com",
    )
    print(f"  ✓ Generated Markdown report ({len(md_report)} bytes)")
    
    # HTML report
    html_report = logger.generate_report(
        format="html",
        workspace_id="demo_workspace",
        workspace_name="Demo Workspace",
        target_url="https://example.com",
    )
    print(f"  ✓ Generated HTML report ({len(html_report)} bytes)")
    
    # JSON report
    json_report = logger.generate_report(
        format="json",
        workspace_id="demo_workspace",
        workspace_name="Demo Workspace",
        target_url="https://example.com",
    )
    print(f"  ✓ Generated JSON report ({len(json_report)} bytes)\n")
    
    # 6. Display sample Markdown report
    print("6. Sample Markdown Report (first 1000 chars):")
    print("-" * 60)
    print(md_report.decode("utf-8")[:1000])
    print("...")
    print("-" * 60)
    print()
    
    # 7. Custom flag patterns
    print("7. Adding custom flag pattern...")
    logger.add_flag_pattern(r"CUSTOM\{[^}]+\}")
    
    custom_response = Response(
        status_code=200,
        headers={},
        body=b'{"data": "CUSTOM{my_custom_flag}"}',
        text='{"data": "CUSTOM{my_custom_flag}"}',
        elapsed_time=0.1,
        request=request,
    )
    
    logger.log_response(custom_response)
    
    custom_flags = [f for f in logger.get_flags() if "CUSTOM" in f.data.get("flag", "")]
    print(f"  ✓ Detected custom flag: {custom_flags[0].data['flag']}\n")
    
    print("=== Demo Complete ===")


if __name__ == "__main__":
    asyncio.run(main())
