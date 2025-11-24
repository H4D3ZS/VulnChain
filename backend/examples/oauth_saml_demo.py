"""OAuth and SAML exploitation module demonstration

This script demonstrates how to use the OAuth and SAML exploitation module
to test for authentication vulnerabilities in federated identity systems.
"""

import asyncio

from app.core.request_handler import RequestHandler
from app.modules.oauth_saml import (
    AccountTakeoverDemo,
    OAuthConfig,
    OAuthTester,
    SAMLTester,
    test_oauth_vulnerabilities,
    test_saml_vulnerabilities,
)


async def demo_oauth_testing():
    """Demonstrate OAuth vulnerability testing"""
    print("=" * 80)
    print("OAuth 2.0 Vulnerability Testing Demo")
    print("=" * 80)
    print()
    
    # Initialize request handler
    request_handler = RequestHandler()
    
    # Example OAuth configuration
    # Replace with actual OAuth endpoints for testing
    config = OAuthConfig(
        authorization_endpoint="https://oauth.example.com/authorize",
        token_endpoint="https://oauth.example.com/token",
        client_id="demo_client_id",
        client_secret="demo_client_secret",
        redirect_uri="https://app.example.com/callback",
        scope="openid profile email",
        response_type="code",
        use_pkce=True,
    )
    
    print("Testing OAuth configuration:")
    print(f"  Authorization Endpoint: {config.authorization_endpoint}")
    print(f"  Token Endpoint: {config.token_endpoint}")
    print(f"  Client ID: {config.client_id}")
    print(f"  Redirect URI: {config.redirect_uri}")
    print(f"  PKCE Enabled: {config.use_pkce}")
    print()
    
    # Test OAuth flow
    tester = OAuthTester(request_handler)
    results = await tester.test_oauth_flow(config)
    
    # Display results
    print(f"Found {len(results)} potential vulnerabilities:")
    print()
    
    for i, result in enumerate(results, 1):
        if result.is_vulnerable:
            print(f"Vulnerability #{i}:")
            print(f"  Type: {result.vulnerability_type.value if result.vulnerability_type else 'Unknown'}")
            print(f"  Confidence: {result.confidence * 100:.0f}%")
            print(f"  Evidence:")
            for evidence in result.evidence:
                print(f"    - {evidence}")
            
            if result.malicious_redirect_uri:
                print(f"  Malicious redirect_uri: {result.malicious_redirect_uri}")
            
            if result.exploitation_steps:
                print(f"  Exploitation Steps:")
                for step in result.exploitation_steps:
                    print(f"    {step}")
            
            print()
    
    # Generate account takeover demonstration
    print("=" * 80)
    print("Account Takeover Demonstration")
    print("=" * 80)
    print()
    
    takeover_steps = AccountTakeoverDemo.generate_oauth_takeover_steps(results)
    for step in takeover_steps:
        print(step)
    print()


async def demo_oauth_convenience_function():
    """Demonstrate OAuth testing using convenience function"""
    print("=" * 80)
    print("OAuth Testing - Convenience Function")
    print("=" * 80)
    print()
    
    # Initialize request handler
    request_handler = RequestHandler()
    
    # Test OAuth using convenience function
    results, takeover_steps = await test_oauth_vulnerabilities(
        authorization_endpoint="https://oauth.example.com/authorize",
        token_endpoint="https://oauth.example.com/token",
        client_id="demo_client_id",
        redirect_uri="https://app.example.com/callback",
        request_handler=request_handler,
        use_pkce=False,  # Test without PKCE
    )
    
    print(f"Found {len([r for r in results if r.is_vulnerable])} vulnerabilities")
    print()
    
    # Display takeover steps
    for step in takeover_steps:
        print(step)
    print()


async def demo_saml_testing():
    """Demonstrate SAML vulnerability testing"""
    print("=" * 80)
    print("SAML Vulnerability Testing Demo")
    print("=" * 80)
    print()
    
    # Initialize request handler
    request_handler = RequestHandler()
    
    # Example SAML assertion (simplified)
    # In real testing, capture this from a legitimate SAML flow
    assertion_xml = """<?xml version="1.0"?>
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                ID="_abc123"
                Version="2.0"
                IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <ds:Signature>
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="#_abc123">
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>...</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>...</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>
        <saml:NameID>user@example.com</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData
                NotOnOrAfter="2024-01-01T01:00:00Z"
                Recipient="https://app.example.com/saml/acs"/>
        </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2024-01-01T00:00:00Z"
                     NotOnOrAfter="2024-01-01T01:00:00Z">
        <saml:AudienceRestriction>
            <saml:Audience>https://app.example.com</saml:Audience>
        </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
        <saml:Attribute Name="email">
            <saml:AttributeValue>user@example.com</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="role">
            <saml:AttributeValue>user</saml:AttributeValue>
        </saml:Attribute>
    </saml:AttributeStatement>
</saml:Assertion>"""
    
    acs_url = "https://app.example.com/saml/acs"
    
    print("Testing SAML assertion:")
    print(f"  ACS URL: {acs_url}")
    print(f"  Assertion length: {len(assertion_xml)} bytes")
    print()
    
    # Test SAML assertion
    tester = SAMLTester(request_handler)
    results = await tester.test_saml_assertion(assertion_xml, acs_url)
    
    # Display results
    print(f"Found {len(results)} potential vulnerabilities:")
    print()
    
    for i, result in enumerate(results, 1):
        if result.is_vulnerable:
            print(f"Vulnerability #{i}:")
            print(f"  Type: {result.vulnerability_type.value if result.vulnerability_type else 'Unknown'}")
            print(f"  Confidence: {result.confidence * 100:.0f}%")
            print(f"  Evidence:")
            for evidence in result.evidence:
                print(f"    - {evidence}")
            
            if result.exploitation_steps:
                print(f"  Exploitation Steps:")
                for step in result.exploitation_steps:
                    print(f"    {step}")
            
            print()
    
    # Generate account takeover demonstration
    print("=" * 80)
    print("Account Takeover Demonstration")
    print("=" * 80)
    print()
    
    takeover_steps = AccountTakeoverDemo.generate_saml_takeover_steps(results)
    for step in takeover_steps:
        print(step)
    print()


async def demo_saml_convenience_function():
    """Demonstrate SAML testing using convenience function"""
    print("=" * 80)
    print("SAML Testing - Convenience Function")
    print("=" * 80)
    print()
    
    # Initialize request handler
    request_handler = RequestHandler()
    
    # Simplified SAML assertion for demo
    assertion_xml = """<saml:Assertion>...</saml:Assertion>"""
    acs_url = "https://app.example.com/saml/acs"
    
    # Test SAML using convenience function
    results, takeover_steps = await test_saml_vulnerabilities(
        assertion_xml=assertion_xml,
        acs_url=acs_url,
        request_handler=request_handler,
    )
    
    print(f"Found {len([r for r in results if r.is_vulnerable])} vulnerabilities")
    print()
    
    # Display takeover steps
    for step in takeover_steps:
        print(step)
    print()


async def main():
    """Run all demonstrations"""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "OAuth and SAML Exploitation Demo" + " " * 25 + "║")
    print("╚" + "=" * 78 + "╝")
    print("\n")
    
    # OAuth demonstrations
    await demo_oauth_testing()
    await demo_oauth_convenience_function()
    
    # SAML demonstrations
    await demo_saml_testing()
    await demo_saml_convenience_function()
    
    print("=" * 80)
    print("Demo Complete")
    print("=" * 80)
    print()
    print("Note: This demo uses example endpoints and assertions.")
    print("For real testing, replace with actual OAuth/SAML configurations.")
    print("Always obtain proper authorization before testing production systems.")
    print()


if __name__ == "__main__":
    asyncio.run(main())
