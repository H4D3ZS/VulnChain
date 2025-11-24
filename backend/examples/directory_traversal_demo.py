#!/usr/bin/env python3
"""
Directory Traversal Module Demo

This script demonstrates the usage of the Directory Traversal module
for automated path traversal vulnerability testing.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.modules.directory_traversal import (
    DirectoryTraversalTester,
    InjectionPoint,
    TraversalTechnique,
    TraversalResult,
)
from app.core.request_handler import RequestHandler
from app.core.config import Config


async def demo_basic_traversal():
    """Demonstrate basic directory traversal testing"""
    print("=" * 80)
    print("Demo 1: Basic Directory Traversal Testing")
    print("=" * 80)
    
    # Initialize components
    config = Config()
    request_handler = RequestHandler(config)
    tester = DirectoryTraversalTester(request_handler)
    
    # Define injection point (query parameter)
    injection_point = InjectionPoint(
        parameter="file",
        location="query",
        original_value="index.php",
        url="http://vulnerable-site.local/view.php?file=index.php",
        method="GET",
    )
    
    print(f"\nTesting URL: {injection_point.url}")
    print(f"Parameter: {injection_point.parameter}")
    print(f"Location: {injection_point.location}")
    
    # Test for directory traversal
    print("\nTesting for directory traversal vulnerabilities...")
    results = await tester.test_injection_point(injection_point)
    
    # Display results
    print(f"\nFound {len(results)} results:")
    for i, result in enumerate(results, 1):
        print(f"\n--- Result {i} ---")
        print(f"Vulnerable: {result.is_vulnerable}")
        if result.is_vulnerable:
            print(f"Technique: {result.technique.value}")
            print(f"Confidence: {result.confidence * 100:.1f}%")
            print(f"Target file: {result.target_file}")
            print(f"Payload: {result.payload}")
            print(f"\nEvidence:")
            for evidence in result.evidence:
                print(f"  - {evidence}")
            if result.file_content:
                print(f"\nFile content preview:")
                print(f"  {result.file_content[:200]}...")


async def demo_specific_techniques():
    """Demonstrate testing with specific techniques"""
    print("\n" + "=" * 80)
    print("Demo 2: Testing Specific Techniques")
    print("=" * 80)
    
    # Initialize components
    config = Config()
    request_handler = RequestHandler(config)
    tester = DirectoryTraversalTester(request_handler)
    
    # Define injection point (POST parameter)
    injection_point = InjectionPoint(
        parameter="filename",
        location="post",
        original_value="document.pdf",
        url="http://vulnerable-site.local/download.php",
        method="POST",
        data={"filename": "document.pdf"},
    )
    
    print(f"\nTesting URL: {injection_point.url}")
    print(f"Parameter: {injection_point.parameter}")
    print(f"Location: {injection_point.location}")
    
    # Test only URL encoded traversal
    print("\nTesting URL encoded traversal...")
    results = await tester.test_injection_point(
        injection_point,
        techniques=[TraversalTechnique.URL_ENCODED],
    )
    
    # Display results
    for result in results:
        if result.is_vulnerable:
            print(f"\n✓ Vulnerable to URL encoded traversal!")
            print(f"  Payload: {result.payload}")
            print(f"  Target: {result.target_file}")
        else:
            print(f"\n✗ Not vulnerable to URL encoded traversal")
    
    # Test double encoded traversal
    print("\nTesting double URL encoded traversal...")
    results = await tester.test_injection_point(
        injection_point,
        techniques=[TraversalTechnique.DOUBLE_ENCODED],
    )
    
    # Display results
    for result in results:
        if result.is_vulnerable:
            print(f"\n✓ Vulnerable to double URL encoded traversal!")
            print(f"  Payload: {result.payload}")
            print(f"  Target: {result.target_file}")
        else:
            print(f"\n✗ Not vulnerable to double URL encoded traversal")


async def demo_custom_files():
    """Demonstrate testing with custom target files"""
    print("\n" + "=" * 80)
    print("Demo 3: Testing Custom Target Files")
    print("=" * 80)
    
    # Initialize components
    config = Config()
    request_handler = RequestHandler(config)
    tester = DirectoryTraversalTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="path",
        location="query",
        original_value="uploads/file.txt",
        url="http://vulnerable-site.local/read.php?path=uploads/file.txt",
        method="GET",
    )
    
    # Custom target files
    custom_files = [
        "/etc/passwd",
        "/etc/shadow",
        "/var/www/html/config.php",
        "/root/.ssh/id_rsa",
    ]
    
    print(f"\nTesting URL: {injection_point.url}")
    print(f"Custom target files:")
    for file in custom_files:
        print(f"  - {file}")
    
    # Test with custom files
    print("\nTesting for directory traversal...")
    results = await tester.test_injection_point(
        injection_point,
        target_files=custom_files,
    )
    
    # Display results
    for result in results:
        if result.is_vulnerable:
            print(f"\n✓ Successfully accessed: {result.target_file}")
            print(f"  Technique: {result.technique.value}")
            print(f"  Payload: {result.payload}")
            if result.file_content:
                print(f"  Content preview: {result.file_content[:100]}...")


async def demo_null_byte_injection():
    """Demonstrate null byte injection testing"""
    print("\n" + "=" * 80)
    print("Demo 4: Null Byte Injection Testing")
    print("=" * 80)
    
    # Initialize components
    config = Config()
    request_handler = RequestHandler(config)
    tester = DirectoryTraversalTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="image",
        location="query",
        original_value="photo.jpg",
        url="http://vulnerable-site.local/show.php?image=photo.jpg",
        method="GET",
    )
    
    print(f"\nTesting URL: {injection_point.url}")
    print(f"Parameter: {injection_point.parameter}")
    print("\nNull byte injection can bypass extension checks")
    print("Example: ../../etc/passwd%00.jpg")
    
    # Test null byte injection
    print("\nTesting null byte injection...")
    results = await tester.test_injection_point(
        injection_point,
        techniques=[TraversalTechnique.NULL_BYTE],
    )
    
    # Display results
    for result in results:
        if result.is_vulnerable:
            print(f"\n✓ Vulnerable to null byte injection!")
            print(f"  Payload: {result.payload}")
            print(f"  Target: {result.target_file}")
            print(f"  Confidence: {result.confidence * 100:.1f}%")
        else:
            print(f"\n✗ Not vulnerable to null byte injection")


async def demo_all_techniques():
    """Demonstrate testing all techniques"""
    print("\n" + "=" * 80)
    print("Demo 5: Testing All Techniques")
    print("=" * 80)
    
    # Initialize components
    config = Config()
    request_handler = RequestHandler(config)
    tester = DirectoryTraversalTester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="doc",
        location="query",
        original_value="readme.txt",
        url="http://vulnerable-site.local/docs.php?doc=readme.txt",
        method="GET",
    )
    
    print(f"\nTesting URL: {injection_point.url}")
    print(f"Parameter: {injection_point.parameter}")
    
    # Test all techniques
    print("\nTesting all traversal techniques...")
    print("Techniques:")
    for technique in TraversalTechnique:
        print(f"  - {technique.value}")
    
    results = await tester.test_injection_point(
        injection_point,
        techniques=list(TraversalTechnique),
    )
    
    # Display summary
    print(f"\n\nResults Summary:")
    print(f"Total tests: {len(results)}")
    vulnerable_results = [r for r in results if r.is_vulnerable]
    print(f"Vulnerabilities found: {len(vulnerable_results)}")
    
    if vulnerable_results:
        print(f"\nVulnerable techniques:")
        for result in vulnerable_results:
            print(f"  ✓ {result.technique.value}")
            print(f"    - Target: {result.target_file}")
            print(f"    - Confidence: {result.confidence * 100:.1f}%")
    else:
        print(f"\n✗ No vulnerabilities found")


async def main():
    """Run all demos"""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "Directory Traversal Module Demo" + " " * 27 + "║")
    print("╚" + "=" * 78 + "╝")
    
    try:
        # Run demos
        await demo_basic_traversal()
        await demo_specific_techniques()
        await demo_custom_files()
        await demo_null_byte_injection()
        await demo_all_techniques()
        
        print("\n" + "=" * 80)
        print("All demos completed successfully!")
        print("=" * 80)
        print("\nNote: These demos use mock vulnerable endpoints.")
        print("In real usage, replace with actual target URLs.")
        print("\n⚠️  Only test against authorized systems!")
        print("=" * 80 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
