"""
Demo script showing how to use the Request Handler

This script demonstrates the basic usage of the RequestHandler class
for making HTTP requests with various configurations.
"""

import asyncio
from app.core.request_handler import RequestHandler


async def main():
    """Demonstrate Request Handler usage"""
    
    # Create a request handler
    async with RequestHandler() as handler:
        print("=== Basic GET Request ===")
        try:
            response = await handler.send_request(
                method="GET",
                url="https://httpbin.org/get"
            )
            print(f"Status: {response.status_code}")
            print(f"Elapsed: {response.elapsed_time:.2f}s")
            print(f"Body length: {len(response.body)} bytes")
            print()
        except Exception as e:
            print(f"Error: {e}")
            print()

        print("=== POST Request with JSON ===")
        try:
            response = await handler.send_request(
                method="POST",
                url="https://httpbin.org/post",
                headers={"Content-Type": "application/json"},
                data={"test": "data", "framework": "VulnChain"}
            )
            print(f"Status: {response.status_code}")
            print(f"Elapsed: {response.elapsed_time:.2f}s")
            print()
        except Exception as e:
            print(f"Error: {e}")
            print()

        print("=== Request with Custom Headers ===")
        try:
            response = await handler.send_request(
                method="GET",
                url="https://httpbin.org/headers",
                headers={
                    "User-Agent": "VulnChain/0.1.0",
                    "X-Custom-Header": "test-value"
                }
            )
            print(f"Status: {response.status_code}")
            print(f"Response headers: {list(response.headers.keys())[:5]}")
            print()
        except Exception as e:
            print(f"Error: {e}")
            print()

        print("=== Batch Requests ===")
        try:
            from app.core.http_models import Request
            
            requests = [
                Request(method="GET", url=f"https://httpbin.org/delay/{i}", headers={})
                for i in range(1, 4)
            ]
            
            responses = await handler.send_batch(requests)
            print(f"Sent {len(requests)} requests concurrently")
            for i, resp in enumerate(responses, 1):
                print(f"  Request {i}: Status {resp.status_code}, Time {resp.elapsed_time:.2f}s")
            print()
        except Exception as e:
            print(f"Error: {e}")
            print()

        print("=== WAF Bypass Profile ===")
        handler.apply_waf_bypass_profile("cloudflare")
        try:
            response = await handler.send_request(
                method="GET",
                url="https://httpbin.org/headers"
            )
            print(f"Status: {response.status_code}")
            print(f"WAF bypass headers applied: {handler.waf_bypass_profile}")
            print()
        except Exception as e:
            print(f"Error: {e}")
            print()


if __name__ == "__main__":
    asyncio.run(main())
