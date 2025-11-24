"""SQL Injection Module Demo

This script demonstrates the SQL injection testing capabilities.
"""

import asyncio
from app.modules.sql_injection import (
    SQLInjectionTester,
    SQLMapIntegration,
    InjectionPoint,
    SQLInjectionType,
)
from app.core.request_handler import RequestHandler


async def demo_error_based():
    """Demonstrate error-based SQL injection testing"""
    print("\n" + "=" * 60)
    print("ERROR-BASED SQL INJECTION DEMO")
    print("=" * 60)
    
    request_handler = RequestHandler()
    tester = SQLInjectionTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="id",
        location="query",
        original_value="1",
        url="http://testphp.vulnweb.com/artists.php?artist=1",
        method="GET",
    )
    
    print(f"\nTesting URL: {injection_point.url}")
    print(f"Parameter: {injection_point.parameter}")
    print(f"Location: {injection_point.location}")
    
    # Test error-based injection
    results = await tester.test_injection_point(
        injection_point,
        techniques=[SQLInjectionType.ERROR_BASED]
    )
    
    for result in results:
        print(f"\n{'Vulnerable!' if result.is_vulnerable else 'Not vulnerable'}")
        if result.is_vulnerable:
            print(f"Injection Type: {result.injection_type.value}")
            print(f"Database Type: {result.database_type.value if result.database_type else 'Unknown'}")
            print(f"Payload: {result.payload}")
            print(f"Confidence: {result.confidence:.2%}")
            if result.error_message:
                print(f"Error Message: {result.error_message[:100]}...")
            print("\nEvidence:")
            for evidence in result.evidence:
                print(f"  - {evidence}")


async def demo_boolean_based():
    """Demonstrate boolean-based SQL injection testing"""
    print("\n" + "=" * 60)
    print("BOOLEAN-BASED SQL INJECTION DEMO")
    print("=" * 60)
    
    request_handler = RequestHandler()
    tester = SQLInjectionTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="username",
        location="post",
        original_value="admin",
        url="http://example.com/login",
        method="POST",
        data={"username": "admin", "password": "test"},
    )
    
    print(f"\nTesting URL: {injection_point.url}")
    print(f"Parameter: {injection_point.parameter}")
    print(f"Location: {injection_point.location}")
    
    # Test boolean-based injection
    results = await tester.test_injection_point(
        injection_point,
        techniques=[SQLInjectionType.BOOLEAN_BASED]
    )
    
    for result in results:
        print(f"\n{'Vulnerable!' if result.is_vulnerable else 'Not vulnerable'}")
        if result.is_vulnerable:
            print(f"Injection Type: {result.injection_type.value}")
            print(f"Payload: {result.payload}")
            print(f"Confidence: {result.confidence:.2%}")
            print("\nEvidence:")
            for evidence in result.evidence:
                print(f"  - {evidence}")
            print("\nMetadata:")
            for key, value in result.metadata.items():
                print(f"  {key}: {value}")


async def demo_time_based():
    """Demonstrate time-based blind SQL injection testing"""
    print("\n" + "=" * 60)
    print("TIME-BASED BLIND SQL INJECTION DEMO")
    print("=" * 60)
    
    request_handler = RequestHandler()
    tester = SQLInjectionTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="id",
        location="query",
        original_value="1",
        url="http://example.com/product?id=1",
        method="GET",
    )
    
    print(f"\nTesting URL: {injection_point.url}")
    print(f"Parameter: {injection_point.parameter}")
    print(f"Location: {injection_point.location}")
    print("\nMeasuring baseline response times...")
    
    # Test time-based injection
    results = await tester.test_injection_point(
        injection_point,
        techniques=[SQLInjectionType.TIME_BASED_BLIND]
    )
    
    for result in results:
        print(f"\n{'Vulnerable!' if result.is_vulnerable else 'Not vulnerable'}")
        if result.is_vulnerable:
            print(f"Injection Type: {result.injection_type.value}")
            print(f"Database Type: {result.database_type.value if result.database_type else 'Unknown'}")
            print(f"Payload: {result.payload}")
            print(f"Confidence: {result.confidence:.2%}")
            print(f"Response Time: {result.response_time:.2f}s")
            print("\nEvidence:")
            for evidence in result.evidence:
                print(f"  - {evidence}")


async def demo_all_techniques():
    """Demonstrate testing with all techniques"""
    print("\n" + "=" * 60)
    print("ALL TECHNIQUES SQL INJECTION DEMO")
    print("=" * 60)
    
    request_handler = RequestHandler()
    tester = SQLInjectionTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="id",
        location="query",
        original_value="1",
        url="http://testphp.vulnweb.com/artists.php?artist=1",
        method="GET",
    )
    
    print(f"\nTesting URL: {injection_point.url}")
    print(f"Parameter: {injection_point.parameter}")
    print("\nTesting all techniques...")
    
    # Test all techniques
    results = await tester.test_injection_point(injection_point)
    
    print(f"\nFound {len([r for r in results if r.is_vulnerable])} vulnerabilities")
    
    for result in results:
        if result.is_vulnerable:
            print(f"\n{'=' * 40}")
            print(f"Injection Type: {result.injection_type.value}")
            print(f"Database Type: {result.database_type.value if result.database_type else 'Unknown'}")
            print(f"Payload: {result.payload}")
            print(f"Confidence: {result.confidence:.2%}")


async def demo_sqlmap_integration():
    """Demonstrate SQLMap integration"""
    print("\n" + "=" * 60)
    print("SQLMAP INTEGRATION DEMO")
    print("=" * 60)
    
    request_handler = RequestHandler()
    tester = SQLInjectionTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="id",
        location="query",
        original_value="1",
        url="http://testphp.vulnweb.com/artists.php?artist=1",
        method="GET",
    )
    
    print(f"\nTesting URL: {injection_point.url}")
    
    # Test for vulnerability
    results = await tester.test_injection_point(
        injection_point,
        techniques=[SQLInjectionType.ERROR_BASED]
    )
    
    vulnerable_result = next((r for r in results if r.is_vulnerable), None)
    
    if vulnerable_result:
        print(f"\nVulnerability found: {vulnerable_result.injection_type.value}")
        
        # Initialize SQLMap integration
        sqlmap = SQLMapIntegration()
        
        # Export to SQLMap format
        sqlmap_request = sqlmap.export_to_sqlmap_format(
            injection_point,
            vulnerable_result
        )
        
        print("\nSQLMap Request Format:")
        print(f"  URL: {sqlmap_request['url']}")
        print(f"  Method: {sqlmap_request['method']}")
        print(f"  Vulnerable Parameter: {sqlmap_request['vulnerable_parameter']}")
        print(f"  Injection Type: {sqlmap_request['injection_type']}")
        print(f"  Database Type: {sqlmap_request['database_type']}")
        
        # Generate SQLMap command
        command = sqlmap.generate_sqlmap_command(
            injection_point,
            vulnerable_result,
            options={
                "batch": True,
                "threads": 5,
                "level": 3,
                "risk": 2,
                "dbs": True,
            }
        )
        
        print("\nGenerated SQLMap Command:")
        print(command)
        
        print("\nNote: To execute SQLMap, uncomment the following line:")
        print("# return_code, stdout, stderr = await sqlmap.execute_sqlmap(command)")
    else:
        print("\nNo vulnerability found for SQLMap integration demo")


async def demo_cookie_injection():
    """Demonstrate SQL injection in cookies"""
    print("\n" + "=" * 60)
    print("COOKIE SQL INJECTION DEMO")
    print("=" * 60)
    
    request_handler = RequestHandler()
    tester = SQLInjectionTester(request_handler)
    
    # Define injection point in cookie
    injection_point = InjectionPoint(
        parameter="session_id",
        location="cookie",
        original_value="abc123",
        url="http://example.com/dashboard",
        method="GET",
    )
    
    print(f"\nTesting URL: {injection_point.url}")
    print(f"Parameter: {injection_point.parameter}")
    print(f"Location: {injection_point.location}")
    
    # Test cookie injection
    results = await tester.test_injection_point(injection_point)
    
    for result in results:
        if result.is_vulnerable:
            print(f"\n{'Vulnerable!' if result.is_vulnerable else 'Not vulnerable'}")
            print(f"Injection Type: {result.injection_type.value}")
            print(f"Payload: {result.payload}")
            print(f"Confidence: {result.confidence:.2%}")


async def demo_header_injection():
    """Demonstrate SQL injection in headers"""
    print("\n" + "=" * 60)
    print("HEADER SQL INJECTION DEMO")
    print("=" * 60)
    
    request_handler = RequestHandler()
    tester = SQLInjectionTester(request_handler)
    
    # Define injection point in header
    injection_point = InjectionPoint(
        parameter="X-User-Id",
        location="header",
        original_value="1",
        url="http://example.com/api/user",
        method="GET",
        headers={"X-User-Id": "1"},
    )
    
    print(f"\nTesting URL: {injection_point.url}")
    print(f"Parameter: {injection_point.parameter}")
    print(f"Location: {injection_point.location}")
    
    # Test header injection
    results = await tester.test_injection_point(injection_point)
    
    for result in results:
        if result.is_vulnerable:
            print(f"\n{'Vulnerable!' if result.is_vulnerable else 'Not vulnerable'}")
            print(f"Injection Type: {result.injection_type.value}")
            print(f"Payload: {result.payload}")
            print(f"Confidence: {result.confidence:.2%}")


async def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("SQL INJECTION MODULE DEMONSTRATION")
    print("=" * 60)
    print("\nThis demo showcases the SQL injection testing capabilities")
    print("of the VulnChain framework.")
    
    demos = [
        ("Error-Based", demo_error_based),
        ("Boolean-Based", demo_boolean_based),
        ("Time-Based", demo_time_based),
        ("All Techniques", demo_all_techniques),
        ("SQLMap Integration", demo_sqlmap_integration),
        ("Cookie Injection", demo_cookie_injection),
        ("Header Injection", demo_header_injection),
    ]
    
    print("\nAvailable demos:")
    for i, (name, _) in enumerate(demos, 1):
        print(f"  {i}. {name}")
    print(f"  {len(demos) + 1}. Run all demos")
    
    try:
        choice = input("\nSelect demo (1-{}): ".format(len(demos) + 1))
        choice = int(choice)
        
        if 1 <= choice <= len(demos):
            await demos[choice - 1][1]()
        elif choice == len(demos) + 1:
            for name, demo_func in demos:
                try:
                    await demo_func()
                except Exception as e:
                    print(f"\nError in {name} demo: {e}")
        else:
            print("Invalid choice")
    
    except ValueError:
        print("Invalid input")
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
    
    print("\n" + "=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
