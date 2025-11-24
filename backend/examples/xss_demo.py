"""Demo script for XSS module

This script demonstrates the XSS testing capabilities including:
- Reflected XSS detection
- Multiple encoding techniques
- Filter bypass payloads
- Non-standard tags and event handlers
- PoC generation
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.modules.xss import (
    XSSTester,
    XSSPoCGenerator,
    InjectionPoint,
    XSSTechnique,
    XSSType,
)
from app.core.request_handler import RequestHandler


async def demo_basic_xss():
    """Demonstrate basic XSS testing"""
    print("\n" + "=" * 60)
    print("DEMO: Basic XSS Testing")
    print("=" * 60)
    
    # Initialize
    # Initialize
    request_handler = RequestHandler()
    xss_tester = XSSTester(request_handler)
    
    # Define injection point (example vulnerable endpoint)
    injection_point = InjectionPoint(
        parameter="search",
        location="query",
        original_value="test",
        url="https://example.com/search?q=test",
        method="GET"
    )
    
    print(f"\nTesting injection point:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    print(f"  Location: {injection_point.location}")
    
    # Test for XSS
    print("\nTesting for XSS vulnerabilities...")
    results = await xss_tester.test_injection_point(
        injection_point,
        techniques=[XSSTechnique.BASIC]
    )
    
    # Display results
    for result in results:
        print(f"\nResult:")
        print(f"  Vulnerable: {result.is_vulnerable}")
        print(f"  Technique: {result.technique.value if result.technique else 'N/A'}")
        print(f"  Confidence: {result.confidence:.2f}")
        
        if result.is_vulnerable:
            print(f"  XSS Type: {result.xss_type.value}")
            print(f"  Payload: {result.payload}")
            print(f"  Evidence:")
            for evidence in result.evidence:
                print(f"    - {evidence}")


async def demo_encoded_xss():
    """Demonstrate encoded XSS testing"""
    print("\n" + "=" * 60)
    print("DEMO: Encoded XSS Testing")
    print("=" * 60)
    
    # Initialize
    # Initialize
    request_handler = RequestHandler()
    xss_tester = XSSTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="name",
        location="query",
        original_value="",
        url="https://example.com/profile?name=",
        method="GET"
    )
    
    print(f"\nTesting with encoded payloads:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    
    # Test encoded XSS
    print("\nTesting encoded XSS...")
    results = await xss_tester.test_injection_point(
        injection_point,
        techniques=[XSSTechnique.ENCODED]
    )
    
    # Display results
    for result in results:
        if result.is_vulnerable:
            print(f"\nEncoded XSS found!")
            print(f"  Payload: {result.payload}")
            print(f"  Confidence: {result.confidence:.2f}")


async def demo_filter_bypass():
    """Demonstrate filter bypass techniques"""
    print("\n" + "=" * 60)
    print("DEMO: Filter Bypass Techniques")
    print("=" * 60)
    
    # Initialize
    # Initialize
    request_handler = RequestHandler()
    xss_tester = XSSTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="comment",
        location="post",
        original_value="",
        url="https://example.com/comment",
        method="POST",
        data={"comment": "", "user": "testuser"}
    )
    
    print(f"\nTesting filter bypass techniques:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    print(f"  Method: {injection_point.method}")
    
    # Test filter bypass
    print("\nTesting filter bypass payloads...")
    results = await xss_tester.test_injection_point(
        injection_point,
        techniques=[XSSTechnique.FILTER_BYPASS]
    )
    
    # Display results
    for result in results:
        if result.is_vulnerable:
            print(f"\nFilter bypass successful!")
            print(f"  Payload: {result.payload}")
            print(f"  Technique: {result.technique.value}")


async def demo_event_handlers():
    """Demonstrate non-standard event handler testing"""
    print("\n" + "=" * 60)
    print("DEMO: Non-Standard Event Handlers")
    print("=" * 60)
    
    # Initialize
    # Initialize
    request_handler = RequestHandler()
    xss_tester = XSSTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="title",
        location="query",
        original_value="",
        url="https://example.com/page?title=",
        method="GET"
    )
    
    print(f"\nTesting non-standard event handlers:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    
    # Show some example payloads
    print("\nExample non-standard tag payloads:")
    for i, payload in enumerate(xss_tester.NON_STANDARD_TAGS[:5], 1):
        print(f"  {i}. {payload}")
    
    # Test event handlers
    print("\nTesting event handler payloads...")
    results = await xss_tester.test_injection_point(
        injection_point,
        techniques=[XSSTechnique.EVENT_HANDLER]
    )
    
    # Display results
    for result in results:
        if result.is_vulnerable:
            print(f"\nEvent handler XSS found!")
            print(f"  Payload: {result.payload}")


async def demo_poc_generation():
    """Demonstrate PoC generation"""
    print("\n" + "=" * 60)
    print("DEMO: PoC Generation")
    print("=" * 60)
    
    # Create example injection point and payload
    injection_point = InjectionPoint(
        parameter="search",
        location="query",
        original_value="test",
        url="https://example.com/search?q=test",
        method="GET"
    )
    
    payload = "<script>alert(document.domain)</script>"
    xss_type = XSSType.REFLECTED
    
    print(f"\nGenerating PoC for:")
    print(f"  Parameter: {injection_point.parameter}")
    print(f"  Payload: {payload}")
    print(f"  XSS Type: {xss_type.value}")
    
    # Generate PoC
    poc_generator = XSSPoCGenerator()
    
    # Generate HTML PoC
    poc_html = poc_generator.generate_poc(
        injection_point,
        payload,
        xss_type
    )
    
    print("\nGenerated PoC HTML:")
    print("-" * 60)
    print(poc_html[:500] + "...")
    print("-" * 60)
    
    # Generate exploit script
    exploit_js = poc_generator.generate_exploit_script(
        injection_point,
        payload,
        xss_type
    )
    
    print("\nGenerated Exploit Script:")
    print("-" * 60)
    print(exploit_js[:500] + "...")
    print("-" * 60)


async def demo_all_techniques():
    """Demonstrate testing all techniques"""
    print("\n" + "=" * 60)
    print("DEMO: All XSS Techniques")
    print("=" * 60)
    
    # Initialize
    # Initialize
    request_handler = RequestHandler()
    xss_tester = XSSTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="input",
        location="query",
        original_value="",
        url="https://example.com/test?input=",
        method="GET"
    )
    
    print(f"\nTesting all techniques:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    
    # List all techniques
    print("\nTechniques to test:")
    for technique in XSSTechnique:
        print(f"  - {technique.value}")
    
    # Test all techniques
    print("\nTesting...")
    results = await xss_tester.test_injection_point(injection_point)
    
    # Display summary
    print(f"\nTested {len(results)} technique(s)")
    vulnerable_count = sum(1 for r in results if r.is_vulnerable)
    print(f"Found {vulnerable_count} vulnerability(ies)")


async def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("XSS MODULE DEMONSTRATION")
    print("=" * 60)
    print("\nThis demo shows the XSS testing capabilities.")
    print("Note: These are simulated tests against example URLs.")
    
    try:
        # Run demos
        await demo_basic_xss()
        await demo_encoded_xss()
        await demo_filter_bypass()
        await demo_event_handlers()
        await demo_poc_generation()
        await demo_all_techniques()
        
        print("\n" + "=" * 60)
        print("DEMO COMPLETE")
        print("=" * 60)
        print("\nKey Features Demonstrated:")
        print("  ✓ Basic XSS detection")
        print("  ✓ Encoded payload testing")
        print("  ✓ Filter bypass techniques")
        print("  ✓ Non-standard event handlers")
        print("  ✓ PoC generation")
        print("  ✓ Comprehensive testing")
        
    except Exception as e:
        print(f"\nError during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
