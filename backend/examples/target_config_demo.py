"""
Demo script showing how to use Target Configuration and WAF Bypass Profiles.

This demonstrates:
1. Creating and configuring targets
2. Applying WAF bypass profiles
3. Saving and loading configurations
4. Using targets with the Request Handler
"""

import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory

from app.models.target import TargetConfig, RateLimit, URLValidationError
from app.core.waf_profiles import (
    list_waf_profiles,
    get_waf_profile,
    apply_waf_profile,
    WAFProfileManager,
)
from app.core.request_handler import RequestHandler


def demo_basic_target_config():
    """Demonstrate basic target configuration"""
    print("=" * 60)
    print("DEMO: Basic Target Configuration")
    print("=" * 60)
    
    # Create a simple target
    target = TargetConfig(
        url="https://example.com",
        name="Example Target",
        description="A simple example target"
    )
    
    print(f"Created target: {target.name}")
    print(f"URL: {target.url}")
    print(f"Created at: {target.created_at}")
    print()


def demo_target_with_headers():
    """Demonstrate target with custom headers"""
    print("=" * 60)
    print("DEMO: Target with Custom Headers")
    print("=" * 60)
    
    # Create target with custom headers
    target = TargetConfig(
        url="https://api.example.com",
        custom_headers={
            "Authorization": "Bearer secret-token-123",
            "X-API-Key": "my-api-key",
            "User-Agent": "VulnChain/1.0",
        },
        name="API Target"
    )
    
    print(f"Target: {target.name}")
    print(f"Custom headers: {target.custom_headers}")
    print()


def demo_target_with_proxy():
    """Demonstrate target with proxy configuration"""
    print("=" * 60)
    print("DEMO: Target with Proxy")
    print("=" * 60)
    
    # Create target with proxy
    target = TargetConfig(
        url="https://example.com",
        proxy="http://proxy.example.com:8080",
        name="Proxied Target"
    )
    
    print(f"Target: {target.name}")
    print(f"Proxy: {target.proxy}")
    print()


def demo_target_with_rate_limit():
    """Demonstrate target with rate limiting"""
    print("=" * 60)
    print("DEMO: Target with Rate Limiting")
    print("=" * 60)
    
    # Create target with rate limiting
    rate_limit = RateLimit(
        requests_per_second=5.0,
        burst_size=10
    )
    
    target = TargetConfig(
        url="https://api.example.com",
        rate_limit=rate_limit,
        name="Rate-Limited Target"
    )
    
    print(f"Target: {target.name}")
    print(f"Rate limit: {target.rate_limit.requests_per_second} req/s")
    print(f"Burst size: {target.rate_limit.burst_size}")
    print()


def demo_url_validation():
    """Demonstrate URL validation"""
    print("=" * 60)
    print("DEMO: URL Validation")
    print("=" * 60)
    
    valid_urls = [
        "https://example.com",
        "http://192.168.1.1:8080",
        "https://sub.domain.example.com/path?query=value",
    ]
    
    invalid_urls = [
        "not-a-url",
        "ftp://example.com",
        "http://example.com:99999",
    ]
    
    print("Valid URLs:")
    for url in valid_urls:
        try:
            target = TargetConfig(url=url)
            print(f"  ✓ {url}")
        except URLValidationError as e:
            print(f"  ✗ {url}: {e}")
    
    print("\nInvalid URLs:")
    for url in invalid_urls:
        try:
            target = TargetConfig(url=url)
            print(f"  ✓ {url}")
        except URLValidationError as e:
            print(f"  ✗ {url}: {e}")
    print()


def demo_save_and_load():
    """Demonstrate saving and loading configurations"""
    print("=" * 60)
    print("DEMO: Save and Load Configuration")
    print("=" * 60)
    
    with TemporaryDirectory() as tmpdir:
        filepath = Path(tmpdir) / "target.json"
        
        # Create and save
        original = TargetConfig(
            url="https://example.com",
            custom_headers={"X-Test": "value"},
            waf_bypass_profile="cloudflare",
            name="Saved Target"
        )
        
        print(f"Saving target to: {filepath}")
        original.save(filepath)
        print("✓ Saved")
        
        # Load
        print(f"Loading target from: {filepath}")
        loaded = TargetConfig.load(filepath)
        print("✓ Loaded")
        
        print(f"\nLoaded target: {loaded.name}")
        print(f"URL: {loaded.url}")
        print(f"Headers: {loaded.custom_headers}")
        print(f"WAF Profile: {loaded.waf_bypass_profile}")
    print()


def demo_list_waf_profiles():
    """Demonstrate listing WAF profiles"""
    print("=" * 60)
    print("DEMO: List WAF Bypass Profiles")
    print("=" * 60)
    
    profiles = list_waf_profiles()
    print(f"Available profiles ({len(profiles)}):")
    
    manager = WAFProfileManager()
    for profile_name in profiles:
        info = manager.get_profile_info(profile_name)
        print(f"  • {profile_name}")
        print(f"    Vendor: {info['vendor']}")
        print(f"    Effectiveness: {info['effectiveness']}")
        print(f"    Headers: {info['header_count']}")
    print()


def demo_waf_profile_details():
    """Demonstrate WAF profile details"""
    print("=" * 60)
    print("DEMO: WAF Profile Details")
    print("=" * 60)
    
    # Show details for a few profiles
    profiles_to_show = ["cloudflare", "akamai", "generic", "aggressive"]
    
    for profile_name in profiles_to_show:
        profile = get_waf_profile(profile_name)
        print(f"\n{profile.name.upper()} Profile:")
        print(f"Description: {profile.description}")
        print(f"Vendor: {profile.vendor}")
        print(f"Effectiveness: {profile.effectiveness}")
        print("Headers:")
        for header, value in profile.headers.items():
            print(f"  {header}: {value}")
    print()


def demo_apply_waf_profile():
    """Demonstrate applying WAF profiles to headers"""
    print("=" * 60)
    print("DEMO: Apply WAF Profile to Headers")
    print("=" * 60)
    
    # Original headers
    original_headers = {
        "User-Agent": "VulnChain/1.0",
        "Accept": "application/json",
    }
    
    print("Original headers:")
    for k, v in original_headers.items():
        print(f"  {k}: {v}")
    
    # Apply Cloudflare bypass profile
    print("\nApplying 'cloudflare' profile...")
    updated_headers = apply_waf_profile("cloudflare", original_headers)
    
    print("Updated headers:")
    for k, v in updated_headers.items():
        if k in original_headers:
            print(f"  {k}: {v}")
        else:
            print(f"  {k}: {v}  [NEW]")
    print()


def demo_target_with_waf_profile():
    """Demonstrate target with WAF bypass profile"""
    print("=" * 60)
    print("DEMO: Target with WAF Bypass Profile")
    print("=" * 60)
    
    # Create target with WAF profile
    target = TargetConfig(
        url="https://protected.example.com",
        waf_bypass_profile="cloudflare",
        custom_headers={"User-Agent": "VulnChain/1.0"},
        name="Protected Target"
    )
    
    print(f"Target: {target.name}")
    print(f"URL: {target.url}")
    print(f"WAF Profile: {target.waf_bypass_profile}")
    print(f"Custom Headers: {target.custom_headers}")
    
    # Show what headers would be applied
    profile = get_waf_profile(target.waf_bypass_profile)
    print(f"\nWAF bypass headers that will be applied:")
    for header, value in profile.headers.items():
        print(f"  {header}: {value}")
    print()


async def demo_request_with_waf_profile():
    """Demonstrate making requests with WAF bypass profile"""
    print("=" * 60)
    print("DEMO: Request with WAF Bypass Profile")
    print("=" * 60)
    
    # Create request handler
    handler = RequestHandler()
    
    # Apply WAF bypass profile
    handler.apply_waf_bypass_profile("cloudflare")
    print("Applied 'cloudflare' WAF bypass profile to request handler")
    
    # Note: This would make an actual request in production
    print("\nIn production, all requests would now include:")
    profile = get_waf_profile("cloudflare")
    for header, value in profile.headers.items():
        print(f"  {header}: {value}")
    
    print("\nNote: Not making actual request in demo mode")
    print()


def demo_custom_waf_profile():
    """Demonstrate creating custom WAF profiles"""
    print("=" * 60)
    print("DEMO: Custom WAF Profile")
    print("=" * 60)
    
    from app.core.waf_profiles import WAFBypassProfile
    
    # Create custom profile
    custom_profile = WAFBypassProfile(
        name="my_custom_waf",
        description="Custom WAF bypass for my specific target",
        vendor="CustomVendor",
        effectiveness="high",
        headers={
            "X-Custom-Header": "bypass-value",
            "X-Forwarded-For": "10.0.0.1",
            "X-Real-IP": "10.0.0.1",
        }
    )
    
    # Add to manager
    manager = WAFProfileManager()
    manager.add_custom_profile(custom_profile)
    
    print(f"Created custom profile: {custom_profile.name}")
    print(f"Description: {custom_profile.description}")
    print("Headers:")
    for header, value in custom_profile.headers.items():
        print(f"  {header}: {value}")
    
    # Use it
    print("\nApplying custom profile...")
    headers = {"User-Agent": "Test"}
    updated = manager.apply_profile_to_headers("my_custom_waf", headers)
    print("Updated headers:")
    for k, v in updated.items():
        print(f"  {k}: {v}")
    print()


def main():
    """Run all demos"""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 10 + "TARGET CONFIGURATION & WAF PROFILES DEMO" + " " * 8 + "║")
    print("╚" + "=" * 58 + "╝")
    print()
    
    # Run synchronous demos
    demo_basic_target_config()
    demo_target_with_headers()
    demo_target_with_proxy()
    demo_target_with_rate_limit()
    demo_url_validation()
    demo_save_and_load()
    demo_list_waf_profiles()
    demo_waf_profile_details()
    demo_apply_waf_profile()
    demo_target_with_waf_profile()
    demo_custom_waf_profile()
    
    # Run async demo
    asyncio.run(demo_request_with_waf_profile())
    
    print("=" * 60)
    print("All demos completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
