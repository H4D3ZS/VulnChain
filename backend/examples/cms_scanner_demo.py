"""
Demo script for CMS scanner functionality.

This script demonstrates how to use the CMS-specific scanners
to detect and scan WordPress, Drupal, and Joomla installations.
"""

import asyncio
from app.core.request_handler import RequestHandler
from app.core.config import Config
from app.modules.reconnaissance import ReconnaissanceModule
from app.models.target import TargetConfig


async def demo_wordpress_scan():
    """Demonstrate WordPress scanning"""
    print("\n=== WordPress Scan Demo ===\n")
    
    # Initialize components
    config = Config()
    request_handler = RequestHandler(config)
    recon_module = ReconnaissanceModule(request_handler)
    
    # Configure target
    target = TargetConfig(
        url="https://example-wordpress-site.com",
        custom_headers={"User-Agent": "VulnChain/1.0"}
    )
    
    print(f"Scanning WordPress site: {target.url}")
    
    # Run WordPress scan
    result = await recon_module.scan_wordpress(target)
    
    if result.error:
        print(f"Error: {result.error}")
        return
    
    print(f"\nWordPress Version: {result.version}")
    
    print(f"\nPlugins Found: {len(result.plugins)}")
    for plugin in result.plugins[:5]:  # Show first 5
        print(f"  - {plugin['name']} (v{plugin['version']})")
        if plugin['vulnerabilities']:
            print(f"    ⚠️  {len(plugin['vulnerabilities'])} vulnerabilities found")
    
    print(f"\nThemes Found: {len(result.themes)}")
    for theme in result.themes[:3]:  # Show first 3
        print(f"  - {theme['name']} (v{theme['version']})")
    
    print(f"\nUsers Enumerated: {len(result.users)}")
    for user in result.users[:5]:  # Show first 5
        print(f"  - {user}")
    
    print(f"\nVulnerabilities Found: {len(result.vulnerabilities)}")
    for vuln in result.vulnerabilities[:5]:  # Show first 5
        print(f"  - [{vuln.severity.upper()}] {vuln.title}")
        if vuln.cve_id:
            print(f"    CVE: {vuln.cve_id}")
        if vuln.fixed_in:
            print(f"    Fixed in: {vuln.fixed_in}")


async def demo_drupal_scan():
    """Demonstrate Drupal scanning"""
    print("\n=== Drupal Scan Demo ===\n")
    
    # Initialize components
    config = Config()
    request_handler = RequestHandler(config)
    recon_module = ReconnaissanceModule(request_handler)
    
    # Configure target
    target = TargetConfig(
        url="https://example-drupal-site.com",
        custom_headers={"User-Agent": "VulnChain/1.0"}
    )
    
    print(f"Scanning Drupal site: {target.url}")
    
    # Run Drupal scan
    result = await recon_module.scan_drupal(target)
    
    if result.error:
        print(f"Error: {result.error}")
        return
    
    print(f"\nDrupal Version: {result.version}")
    
    print(f"\nModules Found: {len(result.plugins)}")
    for module in result.plugins[:5]:  # Show first 5
        print(f"  - {module['name']}")
    
    print(f"\nVulnerabilities Found: {len(result.vulnerabilities)}")
    for vuln in result.vulnerabilities:
        print(f"  - [{vuln.severity.upper()}] {vuln.title}")
        if vuln.cve_id:
            print(f"    CVE: {vuln.cve_id}")


async def demo_joomla_scan():
    """Demonstrate Joomla scanning"""
    print("\n=== Joomla Scan Demo ===\n")
    
    # Initialize components
    config = Config()
    request_handler = RequestHandler(config)
    recon_module = ReconnaissanceModule(request_handler)
    
    # Configure target
    target = TargetConfig(
        url="https://example-joomla-site.com",
        custom_headers={"User-Agent": "VulnChain/1.0"}
    )
    
    print(f"Scanning Joomla site: {target.url}")
    
    # Run Joomla scan
    result = await recon_module.scan_joomla(target)
    
    if result.error:
        print(f"Error: {result.error}")
        return
    
    print(f"\nJoomla Version: {result.version}")
    
    print(f"\nComponents Found: {len(result.plugins)}")
    for component in result.plugins[:5]:  # Show first 5
        print(f"  - {component['name']}")
    
    print(f"\nConfiguration Issues: {len(result.config_issues)}")
    for issue in result.config_issues:
        print(f"  - {issue}")


async def demo_auto_detect_and_scan():
    """Demonstrate automatic CMS detection and scanning"""
    print("\n=== Auto-Detect and Scan Demo ===\n")
    
    # Initialize components
    config = Config()
    request_handler = RequestHandler(config)
    recon_module = ReconnaissanceModule(request_handler)
    
    # Configure target
    target = TargetConfig(
        url="https://example-cms-site.com",
        custom_headers={"User-Agent": "VulnChain/1.0"}
    )
    
    print(f"Auto-detecting CMS for: {target.url}")
    
    # Automatically detect and scan CMS
    result = await recon_module.detect_and_scan_cms(target)
    
    if result is None:
        print("No CMS detected on this site")
        return
    
    print(f"\nDetected CMS: {result.cms_type.upper()}")
    print(f"Version: {result.version}")
    print(f"Vulnerabilities: {len(result.vulnerabilities)}")
    print(f"Plugins/Modules: {len(result.plugins)}")


async def demo_cve_cross_reference():
    """Demonstrate CVE cross-referencing"""
    print("\n=== CVE Cross-Reference Demo ===\n")
    
    # Initialize components
    config = Config()
    request_handler = RequestHandler(config)
    recon_module = ReconnaissanceModule(request_handler)
    
    # Example CVE ID
    cve_id = "CVE-2018-7600"  # Drupalgeddon 2
    
    print(f"Looking up CVE: {cve_id}")
    
    # Cross-reference CVE
    cve_info = await recon_module.cross_reference_cve(cve_id)
    
    if cve_info['error']:
        print(f"Error: {cve_info['error']}")
        return
    
    print(f"\nCVE ID: {cve_info['cve_id']}")
    print(f"Description: {cve_info['description']}")
    print(f"CVSS Score: {cve_info['cvss_score']}")
    print(f"Severity: {cve_info['severity'].upper()}")
    print(f"Published: {cve_info['published_date']}")
    
    print(f"\nReferences: {len(cve_info['references'])}")
    for ref in cve_info['references'][:3]:  # Show first 3
        print(f"  - {ref}")
    
    print(f"\nExploit Availability: {len(cve_info['exploits'])}")
    for exploit in cve_info['exploits']:
        print(f"  - {exploit['source']}: {exploit['type']}")
        print(f"    {exploit['url']}")


async def demo_enrich_vulnerabilities():
    """Demonstrate vulnerability enrichment with CVE data"""
    print("\n=== Vulnerability Enrichment Demo ===\n")
    
    # Initialize components
    config = Config()
    request_handler = RequestHandler(config)
    recon_module = ReconnaissanceModule(request_handler)
    
    # Configure target
    target = TargetConfig(
        url="https://example-wordpress-site.com",
        custom_headers={"User-Agent": "VulnChain/1.0"}
    )
    
    print(f"Scanning and enriching vulnerabilities for: {target.url}")
    
    # Run WordPress scan
    result = await recon_module.scan_wordpress(target)
    
    if result.error:
        print(f"Error: {result.error}")
        return
    
    print(f"\nFound {len(result.vulnerabilities)} vulnerabilities")
    print("Enriching with CVE data...")
    
    # Enrich vulnerabilities with CVE information
    enriched_result = await recon_module.enrich_vulnerabilities_with_cve(result)
    
    print("\nEnriched Vulnerabilities:")
    for vuln in enriched_result.vulnerabilities[:3]:  # Show first 3
        print(f"\n  [{vuln.severity.upper()}] {vuln.title}")
        if vuln.cve_id:
            print(f"  CVE: {vuln.cve_id}")
        if vuln.description:
            print(f"  Description: {vuln.description[:100]}...")
        print(f"  References: {len(vuln.references)}")


async def main():
    """Run all demos"""
    print("=" * 60)
    print("CMS Scanner Demo")
    print("=" * 60)
    
    # Note: These demos will fail if the scanners are not installed
    # or if the target URLs are not accessible
    
    try:
        await demo_wordpress_scan()
    except Exception as e:
        print(f"WordPress scan demo failed: {e}")
    
    try:
        await demo_drupal_scan()
    except Exception as e:
        print(f"Drupal scan demo failed: {e}")
    
    try:
        await demo_joomla_scan()
    except Exception as e:
        print(f"Joomla scan demo failed: {e}")
    
    try:
        await demo_auto_detect_and_scan()
    except Exception as e:
        print(f"Auto-detect demo failed: {e}")
    
    try:
        await demo_cve_cross_reference()
    except Exception as e:
        print(f"CVE cross-reference demo failed: {e}")
    
    try:
        await demo_enrich_vulnerabilities()
    except Exception as e:
        print(f"Vulnerability enrichment demo failed: {e}")
    
    print("\n" + "=" * 60)
    print("Demo Complete")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
