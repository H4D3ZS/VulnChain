"""
Demonstration of the Reconnaissance Module

This script shows how to use the reconnaissance module for:
- Technology fingerprinting (WhatWeb, Wappalyzer)
- Attack module suggestions
- Directory and file fuzzing
- Subdomain enumeration
- Parameter discovery
- JavaScript analysis and endpoint extraction
"""

import asyncio
from pathlib import Path

from app.core.request_handler import RequestHandler
from app.models.target import TargetConfig
from app.modules.reconnaissance import ReconnaissanceModule


async def demo_technology_fingerprinting():
    """Demonstrate technology fingerprinting"""
    print("\n" + "=" * 80)
    print("TECHNOLOGY FINGERPRINTING DEMO")
    print("=" * 80)
    
    # Create target configuration
    target = TargetConfig(
        url="https://example.com",
        custom_headers={"User-Agent": "VulnChain/1.0"}
    )
    
    # Initialize request handler and reconnaissance module
    request_handler = RequestHandler()
    recon = ReconnaissanceModule(request_handler)
    
    # 1. WhatWeb Fingerprinting
    print("\n1. WhatWeb Fingerprinting:")
    print("-" * 40)
    whatweb_result = await recon.fingerprint_whatweb(target)
    
    if whatweb_result.error:
        print(f"Error: {whatweb_result.error}")
    else:
        print(f"Target: {whatweb_result.url}")
        print(f"Server: {whatweb_result.server}")
        print(f"Powered By: {whatweb_result.powered_by}")
        print(f"\nDetected Technologies ({len(whatweb_result.technologies)}):")
        for tech in whatweb_result.technologies:
            version_str = f" v{tech.version}" if tech.version else ""
            print(f"  - {tech.name}{version_str}")
    
    # 2. Wappalyzer-style Detection
    print("\n2. Wappalyzer-style Detection:")
    print("-" * 40)
    wappalyzer_result = await recon.fingerprint_wappalyzer(target)
    
    if wappalyzer_result.error:
        print(f"Error: {wappalyzer_result.error}")
    else:
        print(f"Detected Technologies ({len(wappalyzer_result.technologies)}):")
        for tech in wappalyzer_result.technologies:
            version_str = f" v{tech.version}" if tech.version else ""
            category_str = f" [{tech.category}]" if tech.category else ""
            print(f"  - {tech.name}{version_str}{category_str}")
    
    # 3. Attack Module Suggestions
    print("\n3. Attack Module Suggestions:")
    print("-" * 40)
    all_technologies = whatweb_result.technologies + wappalyzer_result.technologies
    suggestions = recon.suggest_attack_modules(all_technologies)
    
    if suggestions:
        for tech_name, modules in suggestions.items():
            print(f"\n{tech_name}:")
            for module in modules:
                print(f"  → {module}")
    else:
        print("No specific attack module suggestions")
    
    await request_handler.close()


async def demo_directory_fuzzing():
    """Demonstrate directory and file fuzzing"""
    print("\n" + "=" * 80)
    print("DIRECTORY FUZZING DEMO")
    print("=" * 80)
    
    # Create target configuration
    target = TargetConfig(url="https://example.com")
    
    # Initialize request handler and reconnaissance module
    request_handler = RequestHandler()
    recon = ReconnaissanceModule(request_handler)
    
    # Create a sample wordlist
    wordlist_path = Path("/tmp/sample_wordlist.txt")
    wordlist_path.write_text("admin\nlogin\napi\n.git\nrobots.txt\n")
    
    print(f"\nFuzzing target: {target.url}")
    print(f"Wordlist: {wordlist_path} (5 entries)")
    print("-" * 40)
    
    try:
        results = await recon.fuzz_directories(
            target,
            str(wordlist_path),
            status_codes=[200, 301, 302, 403],
            max_concurrent=10
        )
        
        print(f"\nDiscovered {len(results)} entries:")
        for entry in results:
            sensitive_marker = " [SENSITIVE]" if entry.is_sensitive else ""
            redirect_info = f" → {entry.redirect_location}" if entry.redirect_location else ""
            print(f"  [{entry.status_code}] {entry.path} "
                  f"({entry.content_length} bytes, {entry.response_time:.2f}s)"
                  f"{sensitive_marker}{redirect_info}")
    
    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        # Cleanup
        wordlist_path.unlink(missing_ok=True)
        await request_handler.close()


async def demo_subdomain_enumeration():
    """Demonstrate subdomain enumeration"""
    print("\n" + "=" * 80)
    print("SUBDOMAIN ENUMERATION DEMO")
    print("=" * 80)
    
    domain = "example.com"
    
    # Initialize request handler and reconnaissance module
    request_handler = RequestHandler()
    recon = ReconnaissanceModule(request_handler)
    
    # Create a sample subdomain wordlist
    wordlist_path = Path("/tmp/subdomains.txt")
    wordlist_path.write_text("www\napi\nmail\ndev\nstaging\n")
    
    print(f"\nEnumerating subdomains for: {domain}")
    print("Methods: Certificate Transparency, DNS Brute-force")
    print("-" * 40)
    
    try:
        subdomains = await recon.enumerate_subdomains(
            domain,
            wordlist_path=str(wordlist_path),
            use_crt_sh=True,
            use_dns_brute=True,
            max_concurrent=10
        )
        
        print(f"\nDiscovered {len(subdomains)} subdomains:")
        for subdomain in subdomains:
            alive_marker = "✓" if subdomain.is_alive else "✗"
            method_info = f" [{subdomain.discovery_method}]"
            tech_info = ""
            if subdomain.technologies:
                tech_names = ", ".join(t.name for t in subdomain.technologies)
                tech_info = f" - {tech_names}"
            
            print(f"  {alive_marker} {subdomain.subdomain}{method_info}{tech_info}")
    
    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        # Cleanup
        wordlist_path.unlink(missing_ok=True)
        await request_handler.close()


async def demo_parameter_discovery():
    """Demonstrate parameter discovery"""
    print("\n" + "=" * 80)
    print("PARAMETER DISCOVERY DEMO")
    print("=" * 80)
    
    # Create target configuration
    target = TargetConfig(url="https://example.com/search?q=test")
    
    # Initialize request handler and reconnaissance module
    request_handler = RequestHandler()
    recon = ReconnaissanceModule(request_handler)
    
    print(f"\nDiscovering parameters for: {target.url}")
    print("Sources: URL, Forms, JavaScript")
    print("-" * 40)
    
    try:
        # Optionally provide common parameter names to fuzz
        common_params = ["id", "user", "page", "limit", "debug", "admin"]
        
        parameters = await recon.discover_parameters(target, common_params)
        
        # Group parameters by location
        by_location = {}
        for param in parameters:
            if param.location not in by_location:
                by_location[param.location] = []
            by_location[param.location].append(param)
        
        print(f"\nDiscovered {len(parameters)} parameters:")
        for location, params in by_location.items():
            print(f"\n{location.upper()}:")
            for param in params:
                example = f" = {param.example_value}" if param.example_value else ""
                print(f"  - {param.name}{example}")
    
    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        await request_handler.close()


async def demo_javascript_analysis():
    """Demonstrate JavaScript analysis"""
    print("\n" + "=" * 80)
    print("JAVASCRIPT ANALYSIS DEMO")
    print("=" * 80)
    
    # Create target configuration
    target = TargetConfig(url="https://example.com")
    
    # Initialize request handler and reconnaissance module
    request_handler = RequestHandler()
    recon = ReconnaissanceModule(request_handler)
    
    print(f"\nAnalyzing JavaScript for: {target.url}")
    print("Extracting: Files, Endpoints, API Keys, Tokens, Comments")
    print("-" * 40)
    
    try:
        result = await recon.analyze_javascript(target)
        
        # JavaScript Files
        print(f"\nJavaScript Files ({len(result['js_files'])}):")
        for js_file in result['js_files'][:5]:  # Show first 5
            print(f"  - {js_file}")
        if len(result['js_files']) > 5:
            print(f"  ... and {len(result['js_files']) - 5} more")
        
        # API Endpoints
        print(f"\nAPI Endpoints ({len(result['endpoints'])}):")
        for endpoint in result['endpoints'][:10]:  # Show first 10
            method = f"[{endpoint.method}] " if endpoint.method else ""
            print(f"  - {method}{endpoint.url}")
        if len(result['endpoints']) > 10:
            print(f"  ... and {len(result['endpoints']) - 10} more")
        
        # API Keys
        if result['api_keys']:
            print(f"\nAPI Keys Found ({len(result['api_keys'])}):")
            for key in result['api_keys'][:3]:  # Show first 3
                # Mask the key for security
                masked = key[:10] + "..." + key[-5:] if len(key) > 15 else key
                print(f"  - {masked}")
        
        # Tokens
        if result['tokens']:
            print(f"\nTokens Found ({len(result['tokens'])}):")
            for token in result['tokens'][:3]:  # Show first 3
                masked = token[:10] + "..." + token[-5:] if len(token) > 15 else token
                print(f"  - {masked}")
        
        # Sensitive Comments
        if result['comments']:
            print(f"\nSensitive Comments ({len(result['comments'])}):")
            for comment in result['comments'][:5]:  # Show first 5
                # Truncate long comments
                truncated = comment[:80] + "..." if len(comment) > 80 else comment
                print(f"  - {truncated}")
    
    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        await request_handler.close()


async def main():
    """Run all demonstrations"""
    print("\n" + "=" * 80)
    print("RECONNAISSANCE MODULE DEMONSTRATION")
    print("=" * 80)
    print("\nThis demo shows the capabilities of the reconnaissance module.")
    print("Note: Some demos may fail if the target is not accessible or")
    print("if required tools (like WhatWeb) are not installed.")
    
    # Run demonstrations
    await demo_technology_fingerprinting()
    await demo_directory_fuzzing()
    await demo_subdomain_enumeration()
    await demo_parameter_discovery()
    await demo_javascript_analysis()
    
    print("\n" + "=" * 80)
    print("DEMO COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
