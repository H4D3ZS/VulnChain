"""Demo script for Cache Poisoning module

This script demonstrates the usage of the cache poisoning testing module.

WARNING: Only use on systems you own or have explicit permission to test!
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.request_handler import RequestHandler
from app.core.config import Config
from app.modules.cache_poisoning import (
    CachePoisoningTester,
    CacheTestPoint,
    test_cache_poisoning,
)


async def demo_cache_key_analysis():
    """Demonstrate cache key analysis"""
    print("\n" + "=" * 60)
    print("DEMO: Cache Key Analysis")
    print("=" * 60)
    
    config = Config()
    request_handler = RequestHandler(config)
    tester = CachePoisoningTester(request_handler)
    
    # Test point
    test_point = CacheTestPoint(
        url="https://example.com/",
        method="GET",
        headers={"User-Agent": "VulnChain-Demo/1.0"},
    )
    
    print(f"\nAnalyzing cache keys for: {test_point.url}")
    
    try:
        # Analyze cache keys
        cache_analysis = await tester.analyze_cache_keys(test_point)
        
        print(f"\n✓ Cache Analysis Complete")
        print(f"  - Keyed components: {', '.join(cache_analysis.keyed_components) or 'None identified'}")
        print(f"  - Unkeyed headers: {', '.join(cache_analysis.unkeyed_headers) or 'None found'}")
        print(f"  - Cache status: {cache_analysis.cache_status.value}")
        print(f"  - CDN detected: {cache_analysis.cdn_detected or 'None'}")
        
        if cache_analysis.cache_control_headers:
            print(f"\n  Cache Control Headers:")
            for header, value in cache_analysis.cache_control_headers.items():
                print(f"    - {header}: {value}")
        
        return cache_analysis
        
    except Exception as e:
        print(f"\n✗ Error during cache analysis: {e}")
        return None


async def demo_unkeyed_header_poisoning():
    """Demonstrate unkeyed header poisoning detection"""
    print("\n" + "=" * 60)
    print("DEMO: Unkeyed Header Poisoning")
    print("=" * 60)
    
    config = Config()
    request_handler = RequestHandler(config)
    tester = CachePoisoningTester(request_handler)
    
    # Test point
    test_point = CacheTestPoint(
        url="https://example.com/api/data",
        method="GET",
    )
    
    print(f"\nTesting for unkeyed header poisoning: {test_point.url}")
    
    try:
        # First analyze cache
        cache_analysis = await tester.analyze_cache_keys(test_point)
        
        if not cache_analysis.unkeyed_headers:
            print("\n✓ No unkeyed headers found - application is secure")
            return
        
        # Test for poisoning
        results = await tester.test_unkeyed_header_poisoning(test_point, cache_analysis)
        
        if not results:
            print("\n✓ No cache poisoning vulnerabilities found")
            return
        
        for result in results:
            if result.is_vulnerable:
                print(f"\n⚠ VULNERABILITY FOUND!")
                print(f"  - Type: {result.poisoning_type.value}")
                print(f"  - Unkeyed header: {result.unkeyed_header}")
                print(f"  - Confidence: {result.confidence * 100:.0f}%")
                print(f"\n  Evidence:")
                for evidence in result.evidence:
                    print(f"    • {evidence}")
                
                if result.exploitation_guidance:
                    print(f"\n  Exploitation Guidance:")
                    print(result.exploitation_guidance)
        
    except Exception as e:
        print(f"\n✗ Error during testing: {e}")


async def demo_web_cache_deception():
    """Demonstrate web cache deception detection"""
    print("\n" + "=" * 60)
    print("DEMO: Web Cache Deception")
    print("=" * 60)
    
    config = Config()
    request_handler = RequestHandler(config)
    tester = CachePoisoningTester(request_handler)
    
    # Test point - typically an authenticated endpoint
    test_point = CacheTestPoint(
        url="https://example.com/account/settings",
        method="GET",
        headers={
            "Cookie": "session=demo_session_token",
            "User-Agent": "VulnChain-Demo/1.0",
        },
    )
    
    print(f"\nTesting for web cache deception: {test_point.url}")
    print("  (Testing if sensitive content can be cached as static resources)")
    
    try:
        results = await tester.test_web_cache_deception(test_point)
        
        if not results:
            print("\n✓ No web cache deception vulnerabilities found")
            return
        
        for result in results:
            if result.is_vulnerable:
                print(f"\n⚠ VULNERABILITY FOUND!")
                print(f"  - Type: {result.poisoning_type.value}")
                print(f"  - Deception path: {result.payload}")
                print(f"  - Confidence: {result.confidence * 100:.0f}%")
                print(f"\n  Evidence:")
                for evidence in result.evidence:
                    print(f"    • {evidence}")
                
                if result.exploitation_guidance:
                    print(f"\n  Exploitation Guidance:")
                    print(result.exploitation_guidance)
        
    except Exception as e:
        print(f"\n✗ Error during testing: {e}")


async def demo_cdn_normalization():
    """Demonstrate CDN normalization testing"""
    print("\n" + "=" * 60)
    print("DEMO: CDN Cache Key Normalization")
    print("=" * 60)
    
    config = Config()
    request_handler = RequestHandler(config)
    tester = CachePoisoningTester(request_handler)
    
    # Test point
    test_point = CacheTestPoint(
        url="https://example.com/",
        method="GET",
    )
    
    print(f"\nTesting for CDN normalization issues: {test_point.url}")
    
    try:
        results = await tester.test_cdn_normalization(test_point)
        
        if not results:
            print("\n✓ No CDN normalization issues found")
            return
        
        for result in results:
            if result.is_vulnerable:
                print(f"\n⚠ VULNERABILITY FOUND!")
                print(f"  - Type: {result.poisoning_type.value}")
                print(f"  - Normalization issue: {result.payload}")
                print(f"  - Confidence: {result.confidence * 100:.0f}%")
                print(f"\n  Evidence:")
                for evidence in result.evidence:
                    print(f"    • {evidence}")
        
    except Exception as e:
        print(f"\n✗ Error during testing: {e}")


async def demo_origin_bypass():
    """Demonstrate origin server bypass testing"""
    print("\n" + "=" * 60)
    print("DEMO: Origin Server Bypass")
    print("=" * 60)
    
    config = Config()
    request_handler = RequestHandler(config)
    tester = CachePoisoningTester(request_handler)
    
    # Test point
    test_point = CacheTestPoint(
        url="https://example.com/",
        method="GET",
    )
    
    print(f"\nTesting for origin server bypass: {test_point.url}")
    
    try:
        results = await tester.test_origin_bypass(test_point)
        
        if not results:
            print("\n✓ No origin bypass vulnerabilities found")
            return
        
        for result in results:
            if result.is_vulnerable:
                print(f"\n⚠ VULNERABILITY FOUND!")
                print(f"  - Type: {result.poisoning_type.value}")
                print(f"  - Bypass header: {result.unkeyed_header}")
                print(f"  - Payload: {result.payload}")
                print(f"  - Confidence: {result.confidence * 100:.0f}%")
                print(f"\n  Evidence:")
                for evidence in result.evidence:
                    print(f"    • {evidence}")
        
    except Exception as e:
        print(f"\n✗ Error during testing: {e}")


async def demo_comprehensive_testing():
    """Demonstrate comprehensive cache poisoning testing"""
    print("\n" + "=" * 60)
    print("DEMO: Comprehensive Cache Poisoning Testing")
    print("=" * 60)
    
    config = Config()
    request_handler = RequestHandler(config)
    
    target_url = "https://example.com/"
    
    print(f"\nRunning comprehensive cache poisoning tests on: {target_url}")
    print("  (This tests all vulnerability types)")
    
    try:
        # Run all tests
        all_results = await test_cache_poisoning(target_url, request_handler)
        
        # Summary
        total_vulns = sum(
            len([r for r in results if r.is_vulnerable])
            for results in all_results.values()
        )
        
        print(f"\n{'=' * 60}")
        print(f"SUMMARY: Found {total_vulns} vulnerabilities")
        print(f"{'=' * 60}")
        
        for vuln_type, results in all_results.items():
            vuln_count = len([r for r in results if r.is_vulnerable])
            if vuln_count > 0:
                print(f"\n{vuln_type.upper()}: {vuln_count} vulnerabilities")
                for result in results:
                    if result.is_vulnerable:
                        print(f"  • {result.evidence[0] if result.evidence else 'Vulnerability detected'}")
        
        if total_vulns == 0:
            print("\n✓ No cache poisoning vulnerabilities found")
        
    except Exception as e:
        print(f"\n✗ Error during comprehensive testing: {e}")


async def main():
    """Main demo function"""
    print("\n" + "=" * 60)
    print("Cache Poisoning Module Demo")
    print("=" * 60)
    print("\nWARNING: Only use on systems you own or have permission to test!")
    print("\nThis demo will test various cache poisoning techniques:")
    print("  1. Cache key analysis")
    print("  2. Unkeyed header poisoning")
    print("  3. Web cache deception")
    print("  4. CDN normalization issues")
    print("  5. Origin server bypass")
    print("  6. Comprehensive testing")
    
    # Run demos
    await demo_cache_key_analysis()
    await demo_unkeyed_header_poisoning()
    await demo_web_cache_deception()
    await demo_cdn_normalization()
    await demo_origin_bypass()
    await demo_comprehensive_testing()
    
    print("\n" + "=" * 60)
    print("Demo Complete")
    print("=" * 60)


if __name__ == "__main__":
    # Run the demo
    asyncio.run(main())
