"""Demo script for WebSocket and SSE testing module

This script demonstrates how to use the WebSocket and SSE testing module
to test for vulnerabilities in real-time communication endpoints.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.modules.websocket_sse import (
    WebSocketTester,
    SSETester,
    MessageAnalyzer,
    WebSocketClient,
    MessageType,
)
from app.core.request_handler import RequestHandler
from app.core.config import Config


async def demo_websocket_testing():
    """Demonstrate WebSocket vulnerability testing"""
    print("=" * 80)
    print("WebSocket Vulnerability Testing Demo")
    print("=" * 80)
    
    # Initialize components
    config = Config()
    request_handler = RequestHandler(config)
    tester = WebSocketTester(request_handler)
    
    # Example WebSocket URL (replace with actual target)
    ws_url = "wss://echo.websocket.org"  # Public echo server for testing
    
    print(f"\nTesting WebSocket endpoint: {ws_url}")
    print("-" * 80)
    
    try:
        # Test for vulnerabilities
        results = await tester.test_websocket(
            ws_url=ws_url,
            headers={"User-Agent": "VulnChain/1.0"},
        )
        
        if results:
            print(f"\n✓ Found {len(results)} potential vulnerabilities:")
            for i, result in enumerate(results, 1):
                print(f"\n{i}. {result.vulnerability_type.value.upper()}")
                print(f"   Confidence: {result.confidence * 100:.1f}%")
                print(f"   Evidence:")
                for evidence in result.evidence:
                    print(f"   - {evidence}")
        else:
            print("\n✓ No vulnerabilities detected")
    
    except Exception as e:
        print(f"\n✗ Error during testing: {e}")
    
    print("\n" + "=" * 80)


async def demo_websocket_interception():
    """Demonstrate WebSocket message interception and modification"""
    print("=" * 80)
    print("WebSocket Message Interception Demo")
    print("=" * 80)
    
    # Initialize components
    config = Config()
    request_handler = RequestHandler(config)
    tester = WebSocketTester(request_handler)
    
    # Example WebSocket URL
    ws_url = "wss://echo.websocket.org"
    
    print(f"\nIntercepting messages from: {ws_url}")
    print("-" * 80)
    
    try:
        # Define a message modifier
        def modify_message(message: str) -> str:
            """Modify intercepted messages"""
            print(f"Original message: {message}")
            modified = message.upper()  # Simple modification
            print(f"Modified message: {modified}")
            return modified
        
        # Intercept and modify messages
        messages = await tester.intercept_and_modify(
            ws_url=ws_url,
            modifier=modify_message,
        )
        
        print(f"\n✓ Intercepted {len(messages)} messages")
        for msg in messages:
            print(f"\n{msg.direction.upper()}: {msg.content[:100]}")
    
    except Exception as e:
        print(f"\n✗ Error during interception: {e}")
    
    print("\n" + "=" * 80)


async def demo_websocket_client():
    """Demonstrate interactive WebSocket client"""
    print("=" * 80)
    print("WebSocket Client Interface Demo")
    print("=" * 80)
    
    # Initialize client
    client = WebSocketClient()
    
    # Example WebSocket URL
    ws_url = "wss://echo.websocket.org"
    
    print(f"\nConnecting to: {ws_url}")
    print("-" * 80)
    
    try:
        # Connect
        connected = await client.connect(ws_url)
        
        if connected:
            print("✓ Connected successfully")
            
            # Send test messages
            test_messages = [
                "Hello, WebSocket!",
                '{"action": "test", "data": "demo"}',
                "<message>XML test</message>",
            ]
            
            for msg in test_messages:
                print(f"\nSending: {msg}")
                await client.send_message(msg)
                
                # Receive response
                response = await client.receive_message(timeout=3.0)
                if response:
                    print(f"Received: {response}")
                else:
                    print("No response received")
            
            # Get message history
            history = client.get_message_history()
            print(f"\n✓ Total messages in history: {len(history)}")
            
            # Close connection
            await client.close()
            print("✓ Connection closed")
        else:
            print("✗ Failed to connect")
    
    except Exception as e:
        print(f"\n✗ Error: {e}")
    
    print("\n" + "=" * 80)


async def demo_sse_testing():
    """Demonstrate Server-Sent Events testing"""
    print("=" * 80)
    print("Server-Sent Events (SSE) Testing Demo")
    print("=" * 80)
    
    # Initialize components
    config = Config()
    request_handler = RequestHandler(config)
    tester = SSETester(request_handler)
    
    # Example SSE URL (replace with actual target)
    sse_url = "https://example.com/events"
    
    print(f"\nTesting SSE endpoint: {sse_url}")
    print("-" * 80)
    
    try:
        # Test for vulnerabilities
        results = await tester.test_sse_endpoint(
            sse_url=sse_url,
            headers={"Accept": "text/event-stream"},
        )
        
        if results:
            print(f"\n✓ Found {len(results)} potential vulnerabilities:")
            for i, result in enumerate(results, 1):
                print(f"\n{i}. {result.vulnerability_type.value.upper()}")
                print(f"   Confidence: {result.confidence * 100:.1f}%")
                print(f"   Payload: {result.payload}")
                print(f"   Evidence:")
                for evidence in result.evidence:
                    print(f"   - {evidence}")
        else:
            print("\n✓ No vulnerabilities detected")
    
    except Exception as e:
        print(f"\n✗ Error during testing: {e}")
    
    print("\n" + "=" * 80)


async def demo_message_analysis():
    """Demonstrate message format analysis and fuzzing"""
    print("=" * 80)
    print("Message Format Analysis Demo")
    print("=" * 80)
    
    # Initialize analyzer
    analyzer = MessageAnalyzer()
    
    # Create sample messages
    from app.modules.websocket_sse import WebSocketMessage
    import time
    
    sample_messages = [
        WebSocketMessage(
            message_id="1",
            direction="sent",
            message_type=MessageType.JSON,
            content='{"action": "login", "username": "admin", "password": "secret"}',
            timestamp=time.time(),
        ),
        WebSocketMessage(
            message_id="2",
            direction="received",
            message_type=MessageType.JSON,
            content='{"status": "success", "token": "abc123"}',
            timestamp=time.time(),
        ),
        WebSocketMessage(
            message_id="3",
            direction="sent",
            message_type=MessageType.TEXT,
            content='plain text message',
            timestamp=time.time(),
        ),
    ]
    
    print("\nAnalyzing message formats...")
    print("-" * 80)
    
    # Analyze messages
    analysis = analyzer.analyze_message_format(sample_messages)
    
    print("\nMessage Type Distribution:")
    for msg_type, count in analysis["message_types"].items():
        print(f"  {msg_type}: {count}")
    
    print("\nJSON Fields Detected:")
    for field in analysis["json_fields"]:
        print(f"  - {field}")
    
    # Generate fuzz payloads
    print("\nGenerating fuzz payloads...")
    print("-" * 80)
    
    base_message = '{"action": "test", "data": "hello"}'
    payloads = analyzer.generate_fuzz_payloads(base_message, MessageType.JSON)
    
    print(f"\n✓ Generated {len(payloads)} fuzz payloads:")
    for i, payload in enumerate(payloads[:5], 1):  # Show first 5
        print(f"\n{i}. {payload}")
    
    if len(payloads) > 5:
        print(f"\n... and {len(payloads) - 5} more")
    
    print("\n" + "=" * 80)


async def main():
    """Run all demos"""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "WebSocket & SSE Testing Module Demo" + " " * 23 + "║")
    print("╚" + "=" * 78 + "╝")
    print("\n")
    
    demos = [
        ("WebSocket Testing", demo_websocket_testing),
        ("WebSocket Interception", demo_websocket_interception),
        ("WebSocket Client", demo_websocket_client),
        ("SSE Testing", demo_sse_testing),
        ("Message Analysis", demo_message_analysis),
    ]
    
    for i, (name, demo_func) in enumerate(demos, 1):
        print(f"\n[{i}/{len(demos)}] Running: {name}")
        try:
            await demo_func()
        except Exception as e:
            print(f"\n✗ Demo failed: {e}")
        
        if i < len(demos):
            print("\n" + "─" * 80)
            await asyncio.sleep(1)  # Brief pause between demos
    
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 30 + "Demo Complete!" + " " * 33 + "║")
    print("╚" + "=" * 78 + "╝")
    print("\n")


if __name__ == "__main__":
    # Run demos
    asyncio.run(main())
