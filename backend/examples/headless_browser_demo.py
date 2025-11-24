"""Demo script for headless browser module

This script demonstrates:
1. Rendering JavaScript-heavy pages
2. Executing JavaScript in browser context
3. Testing SPAs with API interception
4. Testing for clickjacking vulnerabilities
5. Extracting client-side storage
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.modules.headless_browser import HeadlessBrowser, StorageType
from app.core.request_handler import RequestHandler
from app.models.target import TargetConfig


async def demo_render_page():
    """Demo: Render a JavaScript-heavy page"""
    print("\n" + "=" * 60)
    print("DEMO 1: Rendering JavaScript-Heavy Page")
    print("=" * 60)
    
    request_handler = RequestHandler()
    browser = HeadlessBrowser(request_handler)
    
    try:
        # Target a page with JavaScript
        target = TargetConfig(url="https://example.com")
        
        print(f"\n[*] Rendering page: {target.url}")
        
        result = await browser.render_page(
            target=target,
            wait_time=2.0,
            capture_screenshot=True,
            capture_network=True
        )
        
        if result.success:
            print(f"\n[+] Page rendered successfully!")
            print(f"    Final URL: {result.metadata.get('final_url')}")
            print(f"    Rendered HTML length: {len(result.rendered_html)} bytes")
            print(f"    Console logs: {len(result.console_logs)}")
            print(f"    Network requests: {len(result.network_requests)}")
            print(f"    Storage items: {len(result.storage_data)}")
            
            if result.screenshot:
                print(f"    Screenshot captured: {len(result.screenshot)} bytes")
            
            # Show console logs
            if result.console_logs:
                print("\n[*] Console Logs:")
                for log in result.console_logs[:5]:  # Show first 5
                    print(f"    {log}")
                if len(result.console_logs) > 5:
                    print(f"    ... and {len(result.console_logs) - 5} more")
            
            # Show network requests
            if result.network_requests:
                print("\n[*] Network Requests:")
                for req in result.network_requests[:5]:  # Show first 5
                    print(f"    {req['method']} {req['url']}")
                if len(result.network_requests) > 5:
                    print(f"    ... and {len(result.network_requests) - 5} more")
        else:
            print(f"\n[!] Failed to render page: {result.error}")
    
    finally:
        await browser.close()


async def demo_execute_javascript():
    """Demo: Execute custom JavaScript"""
    print("\n" + "=" * 60)
    print("DEMO 2: Executing Custom JavaScript")
    print("=" * 60)
    
    request_handler = RequestHandler()
    browser = HeadlessBrowser(request_handler)
    
    try:
        target = TargetConfig(url="https://example.com")
        
        # JavaScript to extract page information
        javascript_code = """
        () => {
            return {
                title: document.title,
                url: window.location.href,
                cookies: document.cookie,
                localStorageKeys: Object.keys(localStorage),
                sessionStorageKeys: Object.keys(sessionStorage),
                forms: document.forms.length,
                links: document.links.length,
                scripts: document.scripts.length
            };
        }
        """
        
        print(f"\n[*] Executing JavaScript on: {target.url}")
        
        result = await browser.execute_javascript(
            target=target,
            javascript_code=javascript_code,
            wait_time=1.0
        )
        
        if result.success:
            print(f"\n[+] JavaScript executed successfully!")
            
            js_result = result.metadata.get('javascript_result', {})
            print("\n[*] Extracted Information:")
            print(f"    Title: {js_result.get('title')}")
            print(f"    URL: {js_result.get('url')}")
            print(f"    Cookies: {js_result.get('cookies') or '(none)'}")
            print(f"    localStorage keys: {js_result.get('localStorageKeys')}")
            print(f"    sessionStorage keys: {js_result.get('sessionStorageKeys')}")
            print(f"    Forms: {js_result.get('forms')}")
            print(f"    Links: {js_result.get('links')}")
            print(f"    Scripts: {js_result.get('scripts')}")
        else:
            print(f"\n[!] Failed to execute JavaScript: {result.error}")
    
    finally:
        await browser.close()


async def demo_spa_interception():
    """Demo: Test SPA with API interception"""
    print("\n" + "=" * 60)
    print("DEMO 3: Testing SPA with API Interception")
    print("=" * 60)
    
    request_handler = RequestHandler()
    browser = HeadlessBrowser(request_handler)
    
    try:
        # Use a site that makes API calls
        target = TargetConfig(url="https://jsonplaceholder.typicode.com/")
        
        print(f"\n[*] Testing SPA: {target.url}")
        
        # Define request modifier
        def modify_api_request(api_call):
            print(f"    [Intercepted] {api_call.method} {api_call.url}")
            
            # Add custom header
            api_call.headers['X-Injected-Header'] = 'test'
            
            return api_call
        
        # Interaction script to trigger API calls
        interaction_script = """
        () => {
            // Fetch some data to trigger API calls
            fetch('/posts/1')
                .then(response => response.json())
                .then(data => console.log('Fetched post:', data.title));
        }
        """
        
        result = await browser.test_spa_with_interception(
            target=target,
            interaction_script=interaction_script,
            modify_requests=modify_api_request
        )
        
        if result.success:
            print(f"\n[+] SPA testing complete!")
            print(f"    Intercepted {len(result.api_calls)} API calls")
            
            if result.api_calls:
                print("\n[*] API Calls:")
                for api_call in result.api_calls:
                    print(f"    {api_call.method} {api_call.url}")
                    if api_call.response_status:
                        print(f"      Status: {api_call.response_status}")
        else:
            print(f"\n[!] Failed to test SPA: {result.error}")
    
    finally:
        await browser.close()


async def demo_clickjacking():
    """Demo: Test for clickjacking vulnerabilities"""
    print("\n" + "=" * 60)
    print("DEMO 4: Testing for Clickjacking")
    print("=" * 60)
    
    request_handler = RequestHandler()
    browser = HeadlessBrowser(request_handler)
    
    try:
        # Test a site for clickjacking
        target = TargetConfig(url="https://example.com")
        
        print(f"\n[*] Testing for clickjacking: {target.url}")
        
        result = await browser.test_clickjacking(
            target=target,
            generate_poc=True
        )
        
        print(f"\n[*] Clickjacking Test Results:")
        print(f"    Vulnerable: {result.is_vulnerable}")
        print(f"    X-Frame-Options: {result.x_frame_options or '(not set)'}")
        print(f"    CSP frame-ancestors: {result.csp_frame_ancestors or '(not set)'}")
        print(f"    Frame-busting present: {result.frame_busting_present}")
        print(f"    Frame-busting bypassed: {result.frame_busting_bypassed}")
        
        if result.evidence:
            print("\n[*] Evidence:")
            for evidence in result.evidence:
                print(f"    - {evidence}")
        
        if result.is_vulnerable and result.poc_html:
            # Save PoC to file
            poc_file = "clickjacking_poc.html"
            with open(poc_file, 'w') as f:
                f.write(result.poc_html)
            print(f"\n[+] Proof-of-concept saved to: {poc_file}")
            print(f"    Open this file in a browser to see the clickjacking demo")
    
    finally:
        await browser.close()


async def demo_storage_extraction():
    """Demo: Extract client-side storage"""
    print("\n" + "=" * 60)
    print("DEMO 5: Extracting Client-Side Storage")
    print("=" * 60)
    
    request_handler = RequestHandler()
    browser = HeadlessBrowser(request_handler)
    
    try:
        # Test a site that uses storage
        target = TargetConfig(url="https://example.com")
        
        print(f"\n[*] Extracting storage from: {target.url}")
        
        storage_data = await browser.extract_client_storage(
            target=target,
            storage_types=[
                StorageType.LOCAL_STORAGE,
                StorageType.SESSION_STORAGE,
                StorageType.INDEXED_DB,
                StorageType.COOKIES
            ]
        )
        
        print(f"\n[+] Extracted {len(storage_data)} storage items")
        
        # Group by storage type
        by_type = {}
        for item in storage_data:
            storage_type = item.storage_type.value
            if storage_type not in by_type:
                by_type[storage_type] = []
            by_type[storage_type].append(item)
        
        # Display results
        for storage_type, items in by_type.items():
            print(f"\n[*] {storage_type} ({len(items)} items):")
            for item in items[:5]:  # Show first 5
                print(f"    Key: {item.key}")
                value_str = str(item.value)
                if len(value_str) > 50:
                    value_str = value_str[:50] + "..."
                print(f"    Value: {value_str}")
                if item.domain:
                    print(f"    Domain: {item.domain}")
                if item.metadata:
                    print(f"    Metadata: {item.metadata}")
                print()
            
            if len(items) > 5:
                print(f"    ... and {len(items) - 5} more items")
    
    finally:
        await browser.close()


async def demo_complete_workflow():
    """Demo: Complete workflow for testing a JavaScript application"""
    print("\n" + "=" * 60)
    print("DEMO 6: Complete Workflow")
    print("=" * 60)
    
    request_handler = RequestHandler()
    browser = HeadlessBrowser(request_handler)
    
    try:
        target = TargetConfig(url="https://example.com")
        
        print(f"\n[*] Testing JavaScript application: {target.url}")
        
        # Step 1: Render page
        print("\n[1/4] Rendering page...")
        render_result = await browser.render_page(
            target=target,
            capture_screenshot=True,
            capture_network=True
        )
        
        if render_result.success:
            print(f"  [+] Page rendered")
            print(f"      Console logs: {len(render_result.console_logs)}")
            print(f"      Network requests: {len(render_result.network_requests)}")
        else:
            print(f"  [!] Failed: {render_result.error}")
            return
        
        # Step 2: Extract storage
        print("\n[2/4] Extracting client-side storage...")
        storage_data = await browser.extract_client_storage(target)
        print(f"  [+] Extracted {len(storage_data)} storage items")
        
        # Step 3: Test clickjacking
        print("\n[3/4] Testing for clickjacking...")
        clickjacking_result = await browser.test_clickjacking(target)
        
        if clickjacking_result.is_vulnerable:
            print(f"  [!] VULNERABLE to clickjacking")
        else:
            print(f"  [+] Not vulnerable to clickjacking")
        
        # Step 4: Test SPA
        print("\n[4/4] Testing SPA with API interception...")
        spa_result = await browser.test_spa_with_interception(target)
        
        if spa_result.success:
            print(f"  [+] Intercepted {len(spa_result.api_calls)} API calls")
        
        # Summary
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Target: {target.url}")
        print(f"Console logs: {len(render_result.console_logs)}")
        print(f"Network requests: {len(render_result.network_requests)}")
        print(f"Storage items: {len(storage_data)}")
        print(f"API calls: {len(spa_result.api_calls)}")
        print(f"Clickjacking vulnerable: {clickjacking_result.is_vulnerable}")
        print("=" * 60)
    
    finally:
        await browser.close()


async def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("HEADLESS BROWSER MODULE DEMO")
    print("=" * 60)
    print("\nThis demo showcases the headless browser module capabilities:")
    print("1. Rendering JavaScript-heavy pages")
    print("2. Executing custom JavaScript")
    print("3. Testing SPAs with API interception")
    print("4. Testing for clickjacking vulnerabilities")
    print("5. Extracting client-side storage")
    print("6. Complete workflow")
    
    try:
        # Run demos
        await demo_render_page()
        await demo_execute_javascript()
        await demo_spa_interception()
        await demo_clickjacking()
        await demo_storage_extraction()
        await demo_complete_workflow()
        
        print("\n" + "=" * 60)
        print("ALL DEMOS COMPLETED")
        print("=" * 60)
    
    except KeyboardInterrupt:
        print("\n\n[!] Demo interrupted by user")
    except Exception as e:
        print(f"\n\n[!] Error during demo: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
