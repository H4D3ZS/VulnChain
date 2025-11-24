"""Demo script for Quick-Scan module"""

import asyncio
from app.modules.quick_scan import (
    QuickScanModule,
    QuickScanPreset,
    VulnerabilityCategory
)
from app.core.request_handler import RequestHandler
from app.models.target import TargetConfig


async def demo_basic_quick_scan():
    """Demonstrate basic quick-scan functionality"""
    print("=" * 80)
    print("DEMO 1: Basic Quick-Scan")
    print("=" * 80)
    
    # Initialize
    request_handler = RequestHandler()
    quick_scan = QuickScanModule(request_handler)
    
    # Configure target
    target = TargetConfig(
        url="http://testphp.vulnweb.com",  # Public test site
        custom_headers={"User-Agent": "VulnChain-QuickScan/1.0"}
    )
    
    print(f"\nTarget: {target.url}")
    print("Starting quick-scan...")
    
    # Perform quick-scan
    result = await quick_scan.quick_scan(target)
    
    # Display results
    print(f"\n✓ Scan completed in {result.scan_duration:.2f} seconds")
    print(f"✓ Found {len(result.indicators)} vulnerability indicators")
    print(f"✓ Found {len(result.ctf_patterns)} CTF patterns")
    
    if result.error:
        print(f"\n⚠ Error: {result.error}")
        return
    
    # Show top indicators
    print("\n" + "-" * 80)
    print("TOP VULNERABILITY INDICATORS (by confidence)")
    print("-" * 80)
    
    for i, indicator in enumerate(result.indicators[:5], 1):
        print(f"\n{i}. [{indicator.category.value}]")
        print(f"   Confidence: {indicator.confidence:.1%}")
        print(f"   Description: {indicator.description}")
        print(f"   Evidence: {indicator.evidence}")
        if indicator.recommended_modules:
            print(f"   Recommended: {', '.join(indicator.recommended_modules)}")
    
    # Show recommended modules
    print("\n" + "-" * 80)
    print("RECOMMENDED ATTACK MODULES (prioritized)")
    print("-" * 80)
    
    for i, module in enumerate(result.recommended_modules[:10], 1):
        print(f"{i}. {module}")
    
    # Show CTF patterns
    if result.ctf_patterns:
        print("\n" + "-" * 80)
        print("CTF PATTERNS DETECTED")
        print("-" * 80)
        
        for pattern in result.ctf_patterns:
            print(f"\n[{pattern.pattern_type}] {pattern.description}")
            print(f"  Location: {pattern.location}")
            print(f"  Value: {pattern.value[:100]}...")  # Truncate long values


async def demo_preset_usage():
    """Demonstrate using presets"""
    print("\n\n" + "=" * 80)
    print("DEMO 2: Using Presets")
    print("=" * 80)
    
    # List available presets
    print("\nAvailable Presets:")
    print("-" * 80)
    
    presets = QuickScanPreset.list_presets()
    for preset in presets:
        print(f"\n{preset['name']}")
        print(f"  Description: {preset['description']}")
        print(f"  Categories: {len(preset['categories'])} vulnerability types")
        print(f"  Timeout: {preset['timeout']}s")
    
    # Use HackTheBox preset
    print("\n" + "-" * 80)
    print("Using HackTheBox Preset")
    print("-" * 80)
    
    request_handler = RequestHandler()
    quick_scan = QuickScanModule(request_handler)
    
    target = TargetConfig(url="http://testphp.vulnweb.com")
    
    htb_preset = QuickScanPreset.get_preset('hackthebox')
    print(f"\nPreset: {htb_preset['name']}")
    print(f"Testing {len(htb_preset['categories'])} categories...")
    
    result = await quick_scan.quick_scan(
        target,
        categories=htb_preset['categories']
    )
    
    print(f"\n✓ Scan completed in {result.scan_duration:.2f} seconds")
    print(f"✓ Found {len(result.indicators)} indicators")
    
    # Group by category
    from collections import defaultdict
    by_category = defaultdict(list)
    for indicator in result.indicators:
        by_category[indicator.category].append(indicator)
    
    print("\nResults by Category:")
    for category, indicators in by_category.items():
        print(f"\n{category.value}: {len(indicators)} indicator(s)")
        for ind in indicators[:2]:  # Show top 2 per category
            print(f"  - {ind.description} ({ind.confidence:.1%})")


async def demo_custom_preset():
    """Demonstrate creating custom presets"""
    print("\n\n" + "=" * 80)
    print("DEMO 3: Custom Preset")
    print("=" * 80)
    
    # Create custom preset focusing on injection vulnerabilities
    custom_preset = QuickScanPreset.create_custom_preset(
        name="Injection Focus",
        description="Deep scan for injection vulnerabilities",
        categories=[
            VulnerabilityCategory.SQL_INJECTION,
            VulnerabilityCategory.COMMAND_INJECTION,
            VulnerabilityCategory.SSTI,
            VulnerabilityCategory.XXE,
        ],
        timeout=40
    )
    
    print(f"\nCustom Preset: {custom_preset['name']}")
    print(f"Description: {custom_preset['description']}")
    print(f"Categories: {[cat.value for cat in custom_preset['categories']]}")
    print(f"Timeout: {custom_preset['timeout']}s")
    
    # Use custom preset
    request_handler = RequestHandler()
    quick_scan = QuickScanModule(request_handler)
    
    target = TargetConfig(url="http://testphp.vulnweb.com")
    
    print("\nRunning custom scan...")
    result = await quick_scan.quick_scan(
        target,
        categories=custom_preset['categories']
    )
    
    print(f"\n✓ Scan completed in {result.scan_duration:.2f} seconds")
    
    # Show injection-related findings
    injection_categories = [
        VulnerabilityCategory.SQL_INJECTION,
        VulnerabilityCategory.COMMAND_INJECTION,
        VulnerabilityCategory.SSTI,
    ]
    
    print("\nInjection Vulnerability Findings:")
    for indicator in result.indicators:
        if indicator.category in injection_categories:
            print(f"\n[{indicator.category.value}] {indicator.confidence:.1%}")
            print(f"  {indicator.description}")


async def demo_category_specific_scan():
    """Demonstrate scanning specific categories"""
    print("\n\n" + "=" * 80)
    print("DEMO 4: Category-Specific Scan")
    print("=" * 80)
    
    request_handler = RequestHandler()
    quick_scan = QuickScanModule(request_handler)
    
    target = TargetConfig(url="http://testphp.vulnweb.com")
    
    # Test only SQL injection and XSS
    categories = [
        VulnerabilityCategory.SQL_INJECTION,
        VulnerabilityCategory.XSS,
    ]
    
    print(f"\nTesting only: {[cat.value for cat in categories]}")
    
    result = await quick_scan.quick_scan(target, categories=categories)
    
    print(f"\n✓ Scan completed in {result.scan_duration:.2f} seconds")
    print(f"✓ Found {len(result.indicators)} indicators")
    
    for indicator in result.indicators:
        print(f"\n[{indicator.category.value}]")
        print(f"  Confidence: {indicator.confidence:.1%}")
        print(f"  {indicator.description}")
        print(f"  Evidence: {indicator.evidence}")


async def demo_result_analysis():
    """Demonstrate analyzing scan results"""
    print("\n\n" + "=" * 80)
    print("DEMO 5: Result Analysis")
    print("=" * 80)
    
    request_handler = RequestHandler()
    quick_scan = QuickScanModule(request_handler)
    
    target = TargetConfig(url="http://testphp.vulnweb.com")
    
    result = await quick_scan.quick_scan(target)
    
    # Analyze confidence distribution
    print("\nConfidence Distribution:")
    print("-" * 80)
    
    high_conf = [i for i in result.indicators if i.confidence >= 0.7]
    medium_conf = [i for i in result.indicators if 0.4 <= i.confidence < 0.7]
    low_conf = [i for i in result.indicators if i.confidence < 0.4]
    
    print(f"High confidence (≥70%): {len(high_conf)} indicators")
    print(f"Medium confidence (40-69%): {len(medium_conf)} indicators")
    print(f"Low confidence (<40%): {len(low_conf)} indicators")
    
    # Analyze by category
    print("\n\nIndicators by Category:")
    print("-" * 80)
    
    from collections import Counter
    category_counts = Counter(ind.category for ind in result.indicators)
    
    for category, count in category_counts.most_common():
        print(f"{category.value}: {count}")
    
    # Most recommended modules
    print("\n\nTop 5 Recommended Modules:")
    print("-" * 80)
    
    for i, module in enumerate(result.recommended_modules[:5], 1):
        # Count how many indicators recommend this module
        recommending = sum(
            1 for ind in result.indicators
            if module in ind.recommended_modules
        )
        print(f"{i}. {module} (recommended by {recommending} indicators)")
    
    # CTF pattern analysis
    if result.ctf_patterns:
        print("\n\nCTF Pattern Analysis:")
        print("-" * 80)
        
        pattern_types = Counter(p.pattern_type for p in result.ctf_patterns)
        for pattern_type, count in pattern_types.items():
            print(f"{pattern_type}: {count}")


async def main():
    """Run all demos"""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "QUICK-SCAN MODULE DEMO" + " " * 36 + "║")
    print("╚" + "=" * 78 + "╝")
    
    try:
        await demo_basic_quick_scan()
        await demo_preset_usage()
        await demo_custom_preset()
        await demo_category_specific_scan()
        await demo_result_analysis()
        
        print("\n\n" + "=" * 80)
        print("All demos completed successfully!")
        print("=" * 80)
        
    except Exception as e:
        print(f"\n\n⚠ Error during demo: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
