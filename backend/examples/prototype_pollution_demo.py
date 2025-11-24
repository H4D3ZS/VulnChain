"""Demo script for Prototype Pollution module

This script demonstrates how to use the Prototype Pollution module
to test for prototype pollution vulnerabilities.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.modules.prototype_pollution import (
    PrototypePollutionTester,
    InjectionPoint,
    InjectionLocation,
    PollutionTechnique,
    create_injection_points_from_request,
)
from app.core.request_handler import RequestHandler
# No config import needed - RequestHandler accepts dict


async def demo_basic_testing():
    """Demonstrate basic prototype pollution testing"""
    print("=" * 80)
    print("Demo 1: Basic Prototype Pollution Testing")
    print("=" * 80)
    
    # Initialize
    config = {}
    request_handler = RequestHandler(config)
    tester = PrototypePollutionTester(request_handler)
    
    # Create a JSON body injection point
    injection_point = InjectionPoint(
        parameter="user_data",
        location=InjectionLocation.JSON_BODY,
        original_value='{"name": "test", "email": "test@example.com"}',
        url="https://example.com/api/user/update",
        method="POST",
        headers={"Content-Type": "application/json"},
        json_data={"name": "test", "email": "test@example.com"},
    )
    
    print(f"\nTesting injection point: {injection_point.parameter}")
    print(f"Location: {injection_point.location.value}")
    print(f"URL: {injection_point.url}")
    
    # Test for prototype pollution
    results = await tester.test_injection_point(injection_point)
    
    # Display results
    print(f"\nTested {len(results)} payloads")
    
    vulnerable_results = [r for r in results if r.is_vulnerable]
    if vulnerable_results:
        print(f"\n✓ Found {len(vulnerable_results)} vulnerable injection(s)!")
        
        for result in vulnerable_results:
            print(f"\n  Technique: {result.technique.value}")
            print(f"  Polluted property: {result.polluted_property}")
            print(f"  Confidence: {result.confidence * 100}%")
            print(f"  Payload: {result.payload}")
            
            print("\n  Evidence:")
            for evidence in result.evidence:
                print(f"    - {evidence}")
    else:
        print("\n✗ No prototype pollution vulnerabilities found")


async def demo_multiple_injection_points():
    """Demonstrate testing multiple injection points"""
    print("\n" + "=" * 80)
    print("Demo 2: Testing Multiple Injection Points")
    print("=" * 80)
    
    # Initialize
    config = {}
    request_handler = RequestHandler(config)
    tester = PrototypePollutionTester(request_handler)
    
    # Create injection points from a request
    injection_points = create_injection_points_from_request(
        url="https://example.com/api/settings",
        method="POST",
        query_params={
            "id": "123",
            "action": "update",
        },
        json_data={
            "user": {
                "name": "test",
                "email": "test@example.com",
                "settings": {
                    "theme": "dark",
                    "notifications": True,
                },
            },
        },
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer token123",
        },
    )
    
    print(f"\nCreated {len(injection_points)} injection points:")
    for ip in injection_points:
        print(f"  - {ip.parameter} ({ip.location.value})")
    
    # Test all injection points
    all_results = []
    for injection_point in injection_points:
        print(f"\nTesting {injection_point.parameter}...")
        results = await tester.test_injection_point(injection_point)
        all_results.extend(results)
    
    # Summary
    vulnerable = [r for r in all_results if r.is_vulnerable]
    print(f"\n{'=' * 80}")
    print(f"Summary: Tested {len(all_results)} payloads across {len(injection_points)} injection points")
    print(f"Found {len(vulnerable)} vulnerable injection(s)")


async def demo_specific_techniques():
    """Demonstrate testing specific pollution techniques"""
    print("\n" + "=" * 80)
    print("Demo 3: Testing Specific Pollution Techniques")
    print("=" * 80)
    
    # Initialize
    config = {}
    request_handler = RequestHandler(config)
    tester = PrototypePollutionTester(request_handler)
    
    # Create injection point
    injection_point = InjectionPoint(
        parameter="config",
        location=InjectionLocation.JSON_BODY,
        original_value='{"theme": "light"}',
        url="https://example.com/api/config",
        method="POST",
        headers={"Content-Type": "application/json"},
        json_data={"theme": "light"},
    )
    
    # Test each technique individually
    techniques = [
        PollutionTechnique.PROTO_PROPERTY,
        PollutionTechnique.CONSTRUCTOR_PROTOTYPE,
        PollutionTechnique.PROTO_ARRAY,
        PollutionTechnique.NESTED_PROTO,
    ]
    
    for technique in techniques:
        print(f"\nTesting technique: {technique.value}")
        results = await tester.test_injection_point(
            injection_point,
            techniques=[technique],
        )
        
        vulnerable = [r for r in results if r.is_vulnerable]
        if vulnerable:
            print(f"  ✓ Vulnerable! Found {len(vulnerable)} working payload(s)")
            for result in vulnerable:
                print(f"    Payload: {result.payload}")
        else:
            print(f"  ✗ Not vulnerable to this technique")


async def demo_escalation_guidance():
    """Demonstrate escalation guidance generation"""
    print("\n" + "=" * 80)
    print("Demo 4: Escalation Guidance")
    print("=" * 80)
    
    # Initialize
    config = {}
    request_handler = RequestHandler(config)
    tester = PrototypePollutionTester(request_handler)
    
    # Create injection point
    injection_point = InjectionPoint(
        parameter="user",
        location=InjectionLocation.JSON_BODY,
        original_value='{"name": "test"}',
        url="https://example.com/api/user",
        method="POST",
        headers={"Content-Type": "application/json"},
        json_data={"name": "test"},
    )
    
    print("\nTesting for prototype pollution...")
    results = await tester.test_injection_point(injection_point)
    
    # Find vulnerable result
    vulnerable = [r for r in results if r.is_vulnerable]
    
    if vulnerable:
        result = vulnerable[0]
        print(f"\n✓ Vulnerability found!")
        print(f"  Technique: {result.technique.value}")
        print(f"  Polluted property: {result.polluted_property}")
        
        print("\n" + "=" * 80)
        print("Escalation Guidance:")
        print("=" * 80)
        
        for guidance_line in result.escalation_paths:
            print(guidance_line)
    else:
        print("\n✗ No vulnerabilities found (simulated)")
        print("\nShowing example escalation guidance:")
        
        # Generate example guidance
        example_guidance = tester._generate_escalation_guidance(
            injection_point,
            "isAdmin",
        )
        
        for guidance_line in example_guidance:
            print(guidance_line)


async def demo_payload_variations():
    """Demonstrate different payload variations"""
    print("\n" + "=" * 80)
    print("Demo 5: Payload Variations")
    print("=" * 80)
    
    # Initialize
    config = {}
    request_handler = RequestHandler(config)
    tester = PrototypePollutionTester(request_handler)
    
    print("\nAvailable pollution payloads:")
    print("\n1. __proto__ Property Injection:")
    for payload in tester.POLLUTION_PAYLOADS[PollutionTechnique.PROTO_PROPERTY][:2]:
        print(f"   {payload}")
    
    print("\n2. constructor.prototype Injection:")
    for payload in tester.POLLUTION_PAYLOADS[PollutionTechnique.CONSTRUCTOR_PROTOTYPE][:2]:
        print(f"   {payload}")
    
    print("\n3. Array-based Injection:")
    for payload in tester.POLLUTION_PAYLOADS[PollutionTechnique.PROTO_ARRAY][:2]:
        print(f"   {payload}")
    
    print("\n4. Nested Object Pollution:")
    for payload in tester.POLLUTION_PAYLOADS[PollutionTechnique.NESTED_PROTO][:2]:
        print(f"   {payload}")
    
    print("\nTest properties used for detection:")
    for prop in tester.TEST_PROPERTIES:
        print(f"  - {prop}")


async def main():
    """Run all demos"""
    print("\n" + "=" * 80)
    print("Prototype Pollution Module - Demo")
    print("=" * 80)
    print("\nThis demo shows how to use the Prototype Pollution module")
    print("to test for prototype pollution vulnerabilities.")
    print("\nNote: These demos use example URLs and will not make real requests")
    print("unless you modify them to point to actual test targets.")
    
    try:
        # Run demos
        await demo_basic_testing()
        await demo_multiple_injection_points()
        await demo_specific_techniques()
        await demo_escalation_guidance()
        await demo_payload_variations()
        
        print("\n" + "=" * 80)
        print("Demo completed!")
        print("=" * 80)
        
    except Exception as e:
        print(f"\nError during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run the demo
    asyncio.run(main())
