"""Demo script for NoSQL Injection module

This script demonstrates the usage of the NoSQL injection testing module.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.modules.nosql_injection import (
    NoSQLInjectionTester,
    NoSQLDataExtractor,
    InjectionPoint,
    NoSQLInjectionType,
)
from app.core.request_handler import RequestHandler
from app.core.config import settings


async def demo_operator_injection():
    """Demonstrate operator injection testing"""
    print("\n" + "=" * 60)
    print("Demo 1: NoSQL Operator Injection Testing")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler(settings)
    tester = NoSQLInjectionTester(request_handler)
    
    # Define injection point (JSON body)
    injection_point = InjectionPoint(
        parameter="username",
        location="json",
        original_value="admin",
        url="https://example.com/api/login",
        method="POST",
        is_json=True,
    )
    
    print(f"\nTesting injection point:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    print(f"  Location: {injection_point.location}")
    
    # Test for operator injection
    print("\nTesting for operator injection...")
    results = await tester.test_injection_point(
        injection_point,
        techniques=[NoSQLInjectionType.OPERATOR_INJECTION]
    )
    
    for result in results:
        print(f"\nResult:")
        print(f"  Vulnerable: {result.is_vulnerable}")
        print(f"  Confidence: {result.confidence:.2f}")
        if result.is_vulnerable:
            print(f"  Injection Type: {result.injection_type.value}")
            print(f"  Payload: {result.payload}")
            print(f"  Evidence:")
            for evidence in result.evidence:
                print(f"    - {evidence}")


async def demo_authentication_bypass():
    """Demonstrate authentication bypass testing"""
    print("\n" + "=" * 60)
    print("Demo 2: NoSQL Authentication Bypass")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler(settings)
    tester = NoSQLInjectionTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="username",
        location="json",
        original_value="admin",
        url="https://example.com/api/login",
        method="POST",
        is_json=True,
    )
    
    print(f"\nTesting authentication bypass:")
    print(f"  URL: {injection_point.url}")
    
    # Test for authentication bypass
    print("\nTesting for authentication bypass...")
    results = await tester.test_injection_point(
        injection_point,
        techniques=[NoSQLInjectionType.AUTHENTICATION_BYPASS]
    )
    
    for result in results:
        print(f"\nResult:")
        print(f"  Vulnerable: {result.is_vulnerable}")
        print(f"  Confidence: {result.confidence:.2f}")
        if result.is_vulnerable:
            print(f"  Bypass successful!")
            print(f"  Payload: {result.payload}")


async def demo_boolean_based_blind():
    """Demonstrate boolean-based blind injection"""
    print("\n" + "=" * 60)
    print("Demo 3: Boolean-Based Blind NoSQL Injection")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler(settings)
    tester = NoSQLInjectionTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="id",
        location="query",
        original_value="123",
        url="https://example.com/api/user",
        method="GET",
    )
    
    print(f"\nTesting injection point:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    
    # Test for boolean-based blind injection
    print("\nTesting for boolean-based blind injection...")
    results = await tester.test_injection_point(
        injection_point,
        techniques=[NoSQLInjectionType.BOOLEAN_BASED_BLIND]
    )
    
    for result in results:
        print(f"\nResult:")
        print(f"  Vulnerable: {result.is_vulnerable}")
        print(f"  Confidence: {result.confidence:.2f}")
        if result.is_vulnerable:
            print(f"  Boolean-based blind injection confirmed!")
            print(f"  Metadata: {result.metadata}")


async def demo_time_based_blind():
    """Demonstrate time-based blind injection"""
    print("\n" + "=" * 60)
    print("Demo 4: Time-Based Blind NoSQL Injection")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler(settings)
    tester = NoSQLInjectionTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="search",
        location="json",
        original_value="test",
        url="https://example.com/api/search",
        method="POST",
        is_json=True,
    )
    
    print(f"\nTesting injection point:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    
    # Test for time-based blind injection
    print("\nTesting for time-based blind injection...")
    print("(This may take some time due to delay measurements)")
    results = await tester.test_injection_point(
        injection_point,
        techniques=[NoSQLInjectionType.TIME_BASED_BLIND]
    )
    
    for result in results:
        print(f"\nResult:")
        print(f"  Vulnerable: {result.is_vulnerable}")
        print(f"  Confidence: {result.confidence:.2f}")
        if result.is_vulnerable:
            print(f"  Time-based blind injection confirmed!")
            print(f"  Response time: {result.response_time:.2f}s")
            print(f"  Database type: {result.database_type.value if result.database_type else 'Unknown'}")


async def demo_data_extraction():
    """Demonstrate automated data extraction"""
    print("\n" + "=" * 60)
    print("Demo 5: Automated Data Extraction with Progress Tracking")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler(settings)
    
    # Simulate a vulnerable injection point and result
    injection_point = InjectionPoint(
        parameter="username",
        location="json",
        original_value="admin",
        url="https://example.com/api/user",
        method="GET",
        is_json=True,
    )
    
    # Create a mock result (in real scenario, this would come from testing)
    from app.modules.nosql_injection import NoSQLInjectionResult
    mock_result = NoSQLInjectionResult(
        injection_point=injection_point,
        is_vulnerable=True,
        injection_type=NoSQLInjectionType.BOOLEAN_BASED_BLIND,
        confidence=0.90,
    )
    
    # Initialize extractor
    extractor = NoSQLDataExtractor(
        request_handler=request_handler,
        injection_point=injection_point,
        injection_result=mock_result,
    )
    
    print(f"\nExtracting data from field: 'password'")
    print("Using boolean-based blind technique...")
    
    # Progress callback
    async def progress_callback(progress):
        print(f"\rProgress: {progress.progress_percentage:.1f}% | "
              f"Extracted: '{progress.current_value}' | "
              f"Requests: {progress.requests_sent} | "
              f"ETA: {progress.estimated_time_remaining:.1f}s", end="")
    
    # Extract data (this is a demo, so it won't actually work without a real vulnerable target)
    print("\n(Note: This is a demonstration. Actual extraction requires a vulnerable target)")
    print("\nExample output:")
    print("Progress: 25.0% | Extracted: 'adm' | Requests: 75 | ETA: 15.3s")
    print("Progress: 50.0% | Extracted: 'admin1' | Requests: 150 | ETA: 10.2s")
    print("Progress: 75.0% | Extracted: 'admin123' | Requests: 225 | ETA: 5.1s")
    print("Progress: 100.0% | Extracted: 'admin123!' | Requests: 300 | ETA: 0.0s")
    print("\nExtraction complete!")


async def demo_javascript_injection():
    """Demonstrate JavaScript injection in $where clauses"""
    print("\n" + "=" * 60)
    print("Demo 6: JavaScript Injection in $where Clauses")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler(settings)
    tester = NoSQLInjectionTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="filter",
        location="json",
        original_value="active",
        url="https://example.com/api/users",
        method="POST",
        is_json=True,
    )
    
    print(f"\nTesting injection point:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    
    # Test for JavaScript injection
    print("\nTesting for JavaScript injection...")
    results = await tester.test_injection_point(
        injection_point,
        techniques=[NoSQLInjectionType.JAVASCRIPT_INJECTION]
    )
    
    for result in results:
        print(f"\nResult:")
        print(f"  Vulnerable: {result.is_vulnerable}")
        print(f"  Confidence: {result.confidence:.2f}")
        if result.is_vulnerable:
            print(f"  JavaScript injection confirmed!")
            print(f"  Database type: {result.database_type.value if result.database_type else 'Unknown'}")
            print(f"  Payload: {result.payload}")


async def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("NoSQL Injection Module - Demonstration")
    print("=" * 60)
    print("\nThis demo showcases the capabilities of the NoSQL injection module.")
    print("Note: These demos use example URLs and won't make actual requests.")
    print("In a real scenario, you would test against authorized vulnerable targets.")
    
    try:
        # Run demos
        await demo_operator_injection()
        await demo_authentication_bypass()
        await demo_boolean_based_blind()
        await demo_time_based_blind()
        await demo_data_extraction()
        await demo_javascript_injection()
        
        print("\n" + "=" * 60)
        print("Demo Complete!")
        print("=" * 60)
        print("\nKey Features Demonstrated:")
        print("  ✓ Operator injection testing ($ne, $gt, $regex, $where)")
        print("  ✓ Authentication bypass techniques")
        print("  ✓ Boolean-based blind injection")
        print("  ✓ Time-based blind injection")
        print("  ✓ Automated data extraction with progress tracking")
        print("  ✓ JavaScript injection in $where clauses")
        
    except Exception as e:
        print(f"\nError during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
