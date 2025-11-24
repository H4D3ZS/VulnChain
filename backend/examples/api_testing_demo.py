"""Demo script for API Testing module

This script demonstrates the usage of the API Testing module for
REST and GraphQL API security testing.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.request_handler import RequestHandler
from app.models.target import TargetConfig
from app.modules.api_testing import APITestingModule


async def demo_rest_api_testing():
    """Demonstrate REST API testing capabilities"""
    print("=" * 60)
    print("REST API Testing Demo")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    api_module = APITestingModule(request_handler)
    
    # Configure target (example: public API)
    target = TargetConfig(
        url="https://petstore.swagger.io/v2",
        custom_headers={}
    )
    
    print(f"\nTarget: {target.url}")
    print("\n1. Discovering OpenAPI/Swagger documentation...")
    
    # Discover OpenAPI spec
    openapi_spec = await api_module.rest_discovery.discover_openapi_spec(target)
    
    if openapi_spec:
        print(f"   ✓ Found OpenAPI spec at: {openapi_spec.url}")
        print(f"   - Version: {openapi_spec.version}")
        print(f"   - Title: {openapi_spec.title}")
        print(f"   - Description: {openapi_spec.description}")
        print(f"   - Endpoints discovered: {len(openapi_spec.endpoints)}")
        
        print("\n2. Discovered Endpoints:")
        for i, endpoint in enumerate(openapi_spec.endpoints[:5], 1):
            print(f"   {i}. {endpoint.method} {endpoint.path}")
            if endpoint.description:
                print(f"      Description: {endpoint.description}")
            print(f"      Requires Auth: {endpoint.requires_auth}")
        
        if len(openapi_spec.endpoints) > 5:
            print(f"   ... and {len(openapi_spec.endpoints) - 5} more endpoints")
        
        print("\n3. Testing for authentication/authorization flaws...")
        auth_vulns = await api_module.rest_discovery.test_endpoints_for_auth_bypass(
            target, openapi_spec.endpoints[:3]  # Test first 3 endpoints
        )
        
        if auth_vulns:
            print(f"   ⚠ Found {len(auth_vulns)} potential vulnerabilities:")
            for vuln in auth_vulns:
                print(f"   - [{vuln.severity.upper()}] {vuln.vulnerability_type}")
                print(f"     Endpoint: {vuln.method} {vuln.endpoint}")
                print(f"     Description: {vuln.description}")
        else:
            print("   ✓ No authentication bypass vulnerabilities found")
        
        print("\n4. Testing for API vulnerabilities...")
        
        # Test first endpoint for various vulnerabilities
        if openapi_spec.endpoints:
            test_endpoint = openapi_spec.endpoints[0]
            print(f"   Testing endpoint: {test_endpoint.method} {test_endpoint.path}")
            
            # Test excessive data exposure
            vuln = await api_module.vulnerability_detector.detect_excessive_data_exposure(
                target, test_endpoint
            )
            if vuln:
                print(f"   ⚠ Excessive data exposure detected")
                print(f"     Sensitive fields: {vuln.metadata.get('sensitive_fields', [])}")
            else:
                print("   ✓ No excessive data exposure")
            
            # Test mass assignment (for POST/PUT/PATCH)
            if test_endpoint.method in ['POST', 'PUT', 'PATCH']:
                vuln = await api_module.vulnerability_detector.detect_mass_assignment(
                    target, test_endpoint
                )
                if vuln:
                    print(f"   ⚠ Mass assignment vulnerability detected")
                else:
                    print("   ✓ No mass assignment vulnerability")
    else:
        print("   ✗ No OpenAPI/Swagger documentation found")
    
    print("\n" + "=" * 60)


async def demo_graphql_testing():
    """Demonstrate GraphQL testing capabilities"""
    print("\n" + "=" * 60)
    print("GraphQL Testing Demo")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    api_module = APITestingModule(request_handler)
    
    # Configure target (example: public GraphQL API)
    # Note: Using a hypothetical endpoint for demonstration
    target = TargetConfig(
        url="https://api.example.com",
        custom_headers={}
    )
    
    print(f"\nTarget: {target.url}")
    print("\n1. Detecting GraphQL endpoint...")
    
    # Detect GraphQL endpoint
    graphql_url = await api_module.graphql_testing.detect_graphql_endpoint(target)
    
    if graphql_url:
        print(f"   ✓ Found GraphQL endpoint: {graphql_url}")
        
        print("\n2. Executing introspection query...")
        schema = await api_module.graphql_testing.execute_introspection(target, graphql_url)
        
        if schema:
            print(f"   ✓ Schema introspection successful")
            print(f"   - Queries: {len(schema.queries)}")
            print(f"   - Mutations: {len(schema.mutations)}")
            print(f"   - Types: {len(schema.types)}")
            
            if schema.queries:
                print("\n   Available Queries:")
                for i, query in enumerate(schema.queries[:5], 1):
                    print(f"   {i}. {query.get('name', 'Unknown')}")
                    if 'description' in query and query['description']:
                        print(f"      {query['description']}")
            
            if schema.mutations:
                print("\n   Available Mutations:")
                for i, mutation in enumerate(schema.mutations[:5], 1):
                    print(f"   {i}. {mutation.get('name', 'Unknown')}")
            
            print("\n3. Testing for GraphQL vulnerabilities...")
            
            # Test query depth limits
            depth_vulns = await api_module.graphql_testing.test_query_depth_limits(
                target, graphql_url, schema
            )
            if depth_vulns:
                print("   ⚠ Query depth limits not enforced")
            else:
                print("   ✓ Query depth limits properly enforced")
            
            # Test query batching
            batch_vulns = await api_module.graphql_testing.test_query_batching(
                target, graphql_url, schema
            )
            if batch_vulns:
                print("   ⚠ Query batching not limited")
            else:
                print("   ✓ Query batching properly limited")
        else:
            print("   ✗ Introspection query failed or disabled")
        
        # Test field suggestions
        print("\n4. Testing field suggestions...")
        suggestion_vulns = await api_module.graphql_testing.test_field_suggestions(
            target, graphql_url
        )
        if suggestion_vulns:
            print("   ⚠ Field suggestions enabled (information disclosure)")
        else:
            print("   ✓ Field suggestions disabled or not present")
    else:
        print("   ✗ No GraphQL endpoint detected")
    
    print("\n" + "=" * 60)


async def demo_comprehensive_testing():
    """Demonstrate comprehensive API testing"""
    print("\n" + "=" * 60)
    print("Comprehensive API Testing Demo")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    api_module = APITestingModule(request_handler)
    
    # Configure target
    target = TargetConfig(
        url="https://petstore.swagger.io/v2",
        custom_headers={}
    )
    
    print(f"\nTarget: {target.url}")
    print("\nRunning comprehensive API tests (REST + GraphQL)...")
    
    # Run comprehensive tests
    results = await api_module.comprehensive_api_test(target)
    
    # Display REST results
    print("\n--- REST API Results ---")
    rest_results = results['rest_api']
    if rest_results['openapi_spec']:
        print(f"OpenAPI Spec: {rest_results['openapi_spec']['title']}")
        print(f"Endpoints: {rest_results['openapi_spec']['endpoints_count']}")
    print(f"Vulnerabilities Found: {len(rest_results['vulnerabilities'])}")
    
    # Display GraphQL results
    print("\n--- GraphQL API Results ---")
    graphql_results = results['graphql_api']
    if graphql_results['graphql_endpoint']:
        print(f"GraphQL Endpoint: {graphql_results['graphql_endpoint']}")
        if graphql_results['schema']:
            print(f"Queries: {graphql_results['schema']['queries_count']}")
            print(f"Mutations: {graphql_results['schema']['mutations_count']}")
    else:
        print("No GraphQL endpoint detected")
    print(f"Vulnerabilities Found: {len(graphql_results['vulnerabilities'])}")
    
    # Summary
    total_vulns = len(rest_results['vulnerabilities']) + len(graphql_results['vulnerabilities'])
    print(f"\n--- Summary ---")
    print(f"Total Vulnerabilities: {total_vulns}")
    
    if total_vulns > 0:
        print("\nVulnerability Breakdown:")
        all_vulns = rest_results['vulnerabilities'] + graphql_results['vulnerabilities']
        
        # Group by severity
        by_severity = {}
        for vuln in all_vulns:
            severity = vuln['severity']
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if severity in by_severity:
                print(f"  {severity.upper()}: {len(by_severity[severity])}")
    
    print("\n" + "=" * 60)


async def main():
    """Main demo function"""
    print("\n" + "=" * 60)
    print("API Testing Module - Demonstration")
    print("=" * 60)
    
    try:
        # Run REST API testing demo
        await demo_rest_api_testing()
        
        # Run GraphQL testing demo
        # Note: This will fail if no GraphQL endpoint is available
        # await demo_graphql_testing()
        
        # Run comprehensive testing demo
        await demo_comprehensive_testing()
        
        print("\n✓ Demo completed successfully!")
        
    except KeyboardInterrupt:
        print("\n\n⚠ Demo interrupted by user")
    except Exception as e:
        print(f"\n✗ Error during demo: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
