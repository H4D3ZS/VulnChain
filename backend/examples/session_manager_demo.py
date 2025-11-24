"""Demo script showing Session Manager usage"""

import asyncio
from app.core.request_handler import RequestHandler
from app.core.session_manager import SessionManager


async def main():
    """Demonstrate Session Manager functionality"""
    print("=== VulnChain Session Manager Demo ===\n")

    # Initialize components
    handler = RequestHandler()
    session_manager = SessionManager()

    # Example 1: Capture session from login response
    print("1. Simulating login and capturing session...")
    print("   Making request to login endpoint...")
    
    # In a real scenario, this would be an actual login request
    # For demo purposes, we'll simulate the response
    from app.core.http_models import Request, Response
    
    login_request = Request(
        method="POST",
        url="https://example.com/login",
        headers={"Content-Type": "application/json"},
        data={"username": "admin", "password": "password123"}
    )
    
    # Simulate a response with Set-Cookie headers
    login_response = Response(
        status_code=200,
        headers={
            "Set-Cookie": "session_id=abc123def456; Path=/; HttpOnly; Secure",
            "Content-Type": "application/json"
        },
        body=b'{"status": "success", "message": "Logged in"}',
        text='{"status": "success", "message": "Logged in"}',
        elapsed_time=0.25,
        request=login_request
    )
    
    # Capture the session
    session = session_manager.capture_session(login_response)
    print(f"   ✓ Session captured for domain: {session.domain}")
    print(f"   ✓ Cookies stored: {list(session.cookies.keys())}")
    print()

    # Example 2: Apply session to subsequent requests
    print("2. Applying session to subsequent requests...")
    
    # Create a new request to a protected endpoint
    profile_request = Request(
        method="GET",
        url="https://example.com/profile",
        headers={"Accept": "application/json"}
    )
    
    print(f"   Before applying session: {profile_request.cookies}")
    
    # Apply the session
    session_manager.apply_session(profile_request, session)
    
    print(f"   After applying session: {profile_request.cookies}")
    print(f"   ✓ Session cookies automatically added to request")
    print()

    # Example 3: Export session
    print("3. Exporting session to JSON...")
    exported_data = session_manager.export_session(session.session_id, format="json")
    print(f"   ✓ Session exported ({len(exported_data)} bytes)")
    print(f"   Preview: {exported_data[:100].decode('utf-8')}...")
    print()

    # Example 4: Import session
    print("4. Importing session from JSON...")
    
    # Clear all sessions first
    session_manager.clear_all_sessions()
    print("   Sessions cleared")
    
    # Import the session back
    imported_session = session_manager.import_session(exported_data, format="json")
    print(f"   ✓ Session imported for domain: {imported_session.domain}")
    print(f"   ✓ Cookies restored: {list(imported_session.cookies.keys())}")
    print()

    # Example 5: Retrieve session by domain
    print("5. Retrieving session by domain...")
    retrieved_session = session_manager.get_session("example.com")
    if retrieved_session:
        print(f"   ✓ Session found for example.com")
        print(f"   Session ID: {retrieved_session.session_id}")
        print(f"   Cookies: {list(retrieved_session.cookies.keys())}")
    else:
        print("   ✗ No session found")
    print()

    # Example 6: Multiple domains
    print("6. Managing multiple domain sessions...")
    
    # Simulate another domain
    api_request = Request(
        method="GET",
        url="https://api.example.com/data",
        headers={}
    )
    
    api_response = Response(
        status_code=200,
        headers={
            "Set-Cookie": "api_token=xyz789; Path=/; Secure"
        },
        body=b'{"data": "test"}',
        text='{"data": "test"}',
        elapsed_time=0.15,
        request=api_request
    )
    
    api_session = session_manager.capture_session(api_response)
    print(f"   ✓ Session captured for: {api_session.domain}")
    
    # List all sessions
    all_sessions = session_manager.get_all_sessions()
    print(f"   Total sessions: {len(all_sessions)}")
    for sess in all_sessions:
        print(f"     - {sess.domain}: {list(sess.cookies.keys())}")
    print()

    # Example 7: Path-based cookie matching
    print("7. Path-based cookie matching...")
    
    # Add a cookie with specific path
    from app.core.session_manager import Cookie
    api_cookie = Cookie(
        name="admin_token",
        value="secret123",
        domain="example.com",
        path="/admin"
    )
    retrieved_session.cookies["admin_token"] = api_cookie
    
    # Request to root path
    root_request = Request(method="GET", url="https://example.com/", headers={})
    session_manager.apply_session(root_request, retrieved_session)
    print(f"   Root path cookies: {list(root_request.cookies.keys())}")
    
    # Request to admin path
    admin_request = Request(method="GET", url="https://example.com/admin/users", headers={})
    session_manager.apply_session(admin_request, retrieved_session)
    print(f"   Admin path cookies: {list(admin_request.cookies.keys())}")
    print(f"   ✓ Path-based cookie filtering works correctly")
    print()

    print("=== Demo Complete ===")


if __name__ == "__main__":
    asyncio.run(main())
