"""Demo script for CSRF module

This script demonstrates the CSRF testing capabilities including:
- Token omission testing
- Token reuse testing
- Method switching attacks
- PoC generation
- Safe demonstration practices
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.modules.csrf import (
    CSRFTester,
    CSRFPoCGenerator,
    CSRFTestPoint,
    CSRFTechnique,
)
from app.core.request_handler import RequestHandler


async def demo_token_omission():
    """Demonstrate token omission testing"""
    print("\n" + "=" * 60)
    print("DEMO: Token Omission Testing")
    print("=" * 60)
    
    # Initialize
    request_handler = RequestHandler()
    csrf_tester = CSRFTester(request_handler)
    
    # Define test point
    test_point = CSRFTestPoint(
        url="https://example.com/transfer",
        method="POST",
        parameters={
            "amount": "1000",
            "to_account": "attacker_account",
            "csrf_token": "abc123xyz"
        },
        csrf_token_name="csrf_token",
        csrf_token_value="abc123xyz",
        csrf_token_location="parameter"
    )
    
    print(f"\nTesting endpoint:")
    print(f"  URL: {test_point.url}")
    print(f"  Method: {test_point.method}")
    print(f"  CSRF Token: {test_point.csrf_token_name}")
    
    # Test for CSRF
    print("\nTesting token omission...")
    results = await csrf_tester.test_endpoint(
        test_point,
        techniques=[CSRFTechnique.TOKEN_OMISSION]
    )
    
    # Display results
    for result in results:
        print(f"\nResult:")
        print(f"  Vulnerable: {result.is_vulnerable}")
        print(f"  Technique: {result.technique.value if result.technique else 'N/A'}")
        print(f"  Confidence: {result.confidence:.2f}")
        
        if result.is_vulnerable:
            print(f"  Evidence:")
            for evidence in result.evidence:
                print(f"    - {evidence}")


async def demo_token_reuse():
    """Demonstrate token reuse testing"""
    print("\n" + "=" * 60)
    print("DEMO: Token Reuse Testing")
    print("=" * 60)
    
    # Initialize
    request_handler = RequestHandler()
    csrf_tester = CSRFTester(request_handler)
    
    # Define test point
    test_point = CSRFTestPoint(
        url="https://example.com/delete",
        method="POST",
        parameters={
            "id": "123",
            "csrf_token": "reusable_token"
        },
        csrf_token_name="csrf_token",
        csrf_token_value="reusable_token",
        csrf_token_location="parameter"
    )
    
    print(f"\nTesting token reuse:")
    print(f"  URL: {test_point.url}")
    print(f"  Token: {test_point.csrf_token_value}")
    
    # Test token reuse
    print("\nTesting if token can be reused...")
    results = await csrf_tester.test_endpoint(
        test_point,
        techniques=[CSRFTechnique.TOKEN_REUSE]
    )
    
    # Display results
    for result in results:
        if result.is_vulnerable:
            print(f"\nToken reuse vulnerability found!")
            print(f"  Confidence: {result.confidence:.2f}")
            print(f"  Token can be used multiple times")


async def demo_method_switching():
    """Demonstrate method switching attack"""
    print("\n" + "=" * 60)
    print("DEMO: Method Switching Attack")
    print("=" * 60)
    
    # Initialize
    request_handler = RequestHandler()
    csrf_tester = CSRFTester(request_handler)
    
    # Define test point
    test_point = CSRFTestPoint(
        url="https://example.com/update_email",
        method="POST",
        parameters={
            "email": "attacker@evil.com",
            "csrf_token": "token123"
        },
        csrf_token_name="csrf_token",
        csrf_token_value="token123",
        csrf_token_location="parameter"
    )
    
    print(f"\nTesting method switching:")
    print(f"  URL: {test_point.url}")
    print(f"  Original Method: {test_point.method}")
    print(f"  Testing: POST → GET conversion")
    
    # Test method switching
    print("\nAttempting to convert POST to GET...")
    results = await csrf_tester.test_endpoint(
        test_point,
        techniques=[CSRFTechnique.METHOD_SWITCHING]
    )
    
    # Display results
    for result in results:
        if result.is_vulnerable:
            print(f"\nMethod switching vulnerability found!")
            print(f"  Confidence: {result.confidence:.2f}")
            print(f"  Attack URL: {result.metadata.get('attack_url', 'N/A')}")


async def demo_all_techniques():
    """Demonstrate testing all techniques"""
    print("\n" + "=" * 60)
    print("DEMO: All CSRF Techniques")
    print("=" * 60)
    
    # Initialize
    request_handler = RequestHandler()
    csrf_tester = CSRFTester(request_handler)
    
    # Define test point
    test_point = CSRFTestPoint(
        url="https://example.com/change_password",
        method="POST",
        parameters={
            "new_password": "hacked123",
            "csrf_token": "weak_token"
        },
        csrf_token_name="csrf_token",
        csrf_token_value="weak_token",
        csrf_token_location="parameter"
    )
    
    print(f"\nTesting all techniques:")
    print(f"  URL: {test_point.url}")
    
    # List all techniques
    print("\nTechniques to test:")
    for technique in CSRFTechnique:
        print(f"  - {technique.value}")
    
    # Test all techniques
    print("\nTesting...")
    results = await csrf_tester.test_endpoint(test_point)
    
    # Display summary
    print(f"\nTested {len(results)} technique(s)")
    vulnerable_count = sum(1 for r in results if r.is_vulnerable)
    print(f"Found {vulnerable_count} vulnerability(ies)")
    
    for result in results:
        if result.is_vulnerable:
            print(f"\n  ✗ {result.technique.value}: VULNERABLE")
        else:
            print(f"  ✓ {result.technique.value}: Protected")


def demo_poc_generation():
    """Demonstrate PoC generation"""
    print("\n" + "=" * 60)
    print("DEMO: PoC Generation")
    print("=" * 60)
    
    # Create test point
    test_point = CSRFTestPoint(
        url="https://example.com/transfer",
        method="POST",
        parameters={
            "amount": "1000",
            "to_account": "attacker",
            "csrf_token": "abc123"
        },
        csrf_token_name="csrf_token",
        csrf_token_value="abc123",
        csrf_token_location="parameter"
    )
    
    print(f"\nGenerating PoC for:")
    print(f"  URL: {test_point.url}")
    print(f"  Method: {test_point.method}")
    
    # Generate PoCs
    poc_generator = CSRFPoCGenerator()
    
    # HTML PoC
    print("\n1. Generating HTML PoC...")
    html_poc = poc_generator.generate_html_poc(
        test_point,
        CSRFTechnique.TOKEN_OMISSION
    )
    print(f"   Generated {len(html_poc)} characters")
    print("\n   Preview:")
    print("   " + "-" * 56)
    print("   " + html_poc[:200].replace("\n", "\n   ") + "...")
    print("   " + "-" * 56)
    
    # JavaScript PoC
    print("\n2. Generating JavaScript PoC...")
    js_poc = poc_generator.generate_javascript_poc(
        test_point,
        CSRFTechnique.TOKEN_OMISSION
    )
    print(f"   Generated {len(js_poc)} characters")
    print("\n   Preview:")
    print("   " + "-" * 56)
    print("   " + js_poc[:200].replace("\n", "\n   ") + "...")
    print("   " + "-" * 56)
    
    # Method switching PoC
    print("\n3. Generating Method Switching PoC...")
    method_switch_poc = poc_generator.generate_html_poc(
        test_point,
        CSRFTechnique.METHOD_SWITCHING
    )
    print(f"   Generated {len(method_switch_poc)} characters")
    print("   This PoC converts POST to GET for easy exploitation")


def demo_csrf_token_detection():
    """Demonstrate CSRF token detection"""
    print("\n" + "=" * 60)
    print("DEMO: CSRF Token Detection")
    print("=" * 60)
    
    # Test different token locations
    test_cases = [
        {
            "name": "Parameter Token",
            "test_point": CSRFTestPoint(
                url="https://example.com/action",
                method="POST",
                parameters={"action": "delete", "_csrf": "token123"}
            )
        },
        {
            "name": "Header Token",
            "test_point": CSRFTestPoint(
                url="https://example.com/action",
                method="POST",
                parameters={"action": "delete"},
                headers={"X-CSRF-Token": "header_token"}
            )
        },
        {
            "name": "Cookie Token",
            "test_point": CSRFTestPoint(
                url="https://example.com/action",
                method="POST",
                parameters={"action": "delete"},
                cookies={"csrftoken": "cookie_token"}
            )
        }
    ]
    
    print("\nTesting token detection in different locations:")
    
    # Note: This is a synchronous demo, so we'll manually check the logic
    for test_case in test_cases:
        print(f"\n{test_case['name']}:")
        test_point = test_case['test_point']
        
        # Manually detect tokens for demo purposes
        # In real usage, this would be done automatically by the tester
        
        # Check parameters
        for param_name in test_point.parameters.keys():
            if any(csrf_name in param_name.lower() for csrf_name in ["csrf", "token", "xsrf"]):
                test_point.csrf_token_name = param_name
                test_point.csrf_token_value = test_point.parameters[param_name]
                test_point.csrf_token_location = "parameter"
                break
        
        # Check headers
        if not test_point.csrf_token_name:
            for header_name in test_point.headers.keys():
                if any(csrf_name in header_name.lower() for csrf_name in ["csrf", "token", "xsrf"]):
                    test_point.csrf_token_name = header_name
                    test_point.csrf_token_value = test_point.headers[header_name]
                    test_point.csrf_token_location = "header"
                    break
        
        # Check cookies
        if not test_point.csrf_token_name:
            for cookie_name in test_point.cookies.keys():
                if any(csrf_name in cookie_name.lower() for csrf_name in ["csrf", "token", "xsrf"]):
                    test_point.csrf_token_name = cookie_name
                    test_point.csrf_token_value = test_point.cookies[cookie_name]
                    test_point.csrf_token_location = "cookie"
                    break
        
        if test_point.csrf_token_name:
            print(f"  ✓ Token detected!")
            print(f"    Name: {test_point.csrf_token_name}")
            print(f"    Value: {test_point.csrf_token_value}")
            print(f"    Location: {test_point.csrf_token_location}")
        else:
            print(f"  ✗ No token detected")


def demo_safe_testing_practices():
    """Demonstrate safe testing practices"""
    print("\n" + "=" * 60)
    print("DEMO: Safe Testing Practices")
    print("=" * 60)
    
    print("\nIMPORTANT SAFETY GUIDELINES:")
    print("\n1. Authorization")
    print("   - Only test applications you own")
    print("   - Get written permission for third-party testing")
    print("   - Never test production systems without approval")
    
    print("\n2. Test Environment")
    print("   - Use dedicated test accounts")
    print("   - Use test data only")
    print("   - Isolate test environment from production")
    
    print("\n3. CSRF Testing Specifics")
    print("   - CSRF attacks perform real actions")
    print("   - Test with reversible actions when possible")
    print("   - Document all test activities")
    print("   - Clean up after testing")
    
    print("\n4. PoC Handling")
    print("   - Include safety warnings in all PoCs")
    print("   - Add delays to allow cancellation")
    print("   - Never distribute PoCs without context")
    print("   - Follow responsible disclosure practices")
    
    print("\n5. Reporting")
    print("   - Document findings thoroughly")
    print("   - Include remediation recommendations")
    print("   - Follow responsible disclosure timeline")
    print("   - Respect confidentiality agreements")


async def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("CSRF MODULE DEMONSTRATION")
    print("=" * 60)
    print("\nThis demo shows the CSRF testing capabilities.")
    print("Note: These are simulated tests against example URLs.")
    
    try:
        # Run demos
        await demo_token_omission()
        await demo_token_reuse()
        await demo_method_switching()
        await demo_all_techniques()
        demo_poc_generation()
        demo_csrf_token_detection()
        demo_safe_testing_practices()
        
        print("\n" + "=" * 60)
        print("DEMO COMPLETE")
        print("=" * 60)
        print("\nKey Features Demonstrated:")
        print("  ✓ Token omission testing")
        print("  ✓ Token reuse testing")
        print("  ✓ Method switching attacks")
        print("  ✓ Comprehensive technique testing")
        print("  ✓ PoC generation (HTML & JavaScript)")
        print("  ✓ CSRF token detection")
        print("  ✓ Safe testing practices")
        
    except Exception as e:
        print(f"\nError during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
