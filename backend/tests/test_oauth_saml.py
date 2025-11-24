"""Tests for OAuth and SAML exploitation module"""

import pytest
from unittest.mock import Mock, AsyncMock

from app.modules.oauth_saml import (
    OAuthTester,
    SAMLTester,
    OAuthConfig,
    OAuthTestResult,
    SAMLTestResult,
    OAuthVulnerabilityType,
    SAMLVulnerabilityType,
    SAMLAssertion,
    AccountTakeoverDemo,
    test_oauth_vulnerabilities,
    test_saml_vulnerabilities,
)
from app.core.request_handler import Response


@pytest.fixture
def mock_request_handler():
    """Create mock request handler"""
    handler = Mock()
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def oauth_tester(mock_request_handler):
    """Create OAuth tester instance"""
    return OAuthTester(mock_request_handler)


@pytest.fixture
def saml_tester(mock_request_handler):
    """Create SAML tester instance"""
    return SAMLTester(mock_request_handler)


@pytest.fixture
def sample_oauth_config():
    """Create sample OAuth configuration"""
    return OAuthConfig(
        authorization_endpoint="https://oauth.example.com/authorize",
        token_endpoint="https://oauth.example.com/token",
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://app.example.com/callback",
        scope="openid profile email",
        response_type="code",
        use_pkce=True,
    )


@pytest.fixture
def sample_saml_assertion():
    """Create sample SAML assertion XML"""
    return """<?xml version="1.0"?>
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                ID="_abc123"
                Version="2.0">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <ds:Signature>
        <ds:SignedInfo>
            <ds:SignatureMethod Algorithm="rsa-sha256"/>
        </ds:SignedInfo>
        <ds:SignatureValue>signature_value</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>
        <saml:NameID>user@example.com</saml:NameID>
        <saml:SubjectConfirmation>
            <saml:SubjectConfirmationData Recipient="https://app.example.com/acs"/>
        </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2024-01-01T01:00:00Z"/>
    <saml:AttributeStatement>
        <saml:Attribute Name="email">
            <saml:AttributeValue>user@example.com</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="role">
            <saml:AttributeValue>user</saml:AttributeValue>
        </saml:Attribute>
    </saml:AttributeStatement>
</saml:Assertion>"""



class TestOAuthTester:
    """Test OAuth tester functionality"""
    
    @pytest.mark.asyncio
    async def test_redirect_uri_bypass_vulnerable(
        self, oauth_tester, mock_request_handler, sample_oauth_config
    ):
        """Test OAuth redirect_uri bypass detection"""
        # Mock response that accepts malicious redirect_uri
        response = Mock(spec=Response)
        response.status_code = 302
        response.text = ""
        response.headers = {"Location": "https://attacker.com"}
        
        mock_request_handler.send_request.return_value = response
        
        # Test redirect_uri bypass
        malicious_uri = "https://app.example.com/callback?next=https://attacker.com"
        result = await oauth_tester._test_single_redirect_uri(
            sample_oauth_config, malicious_uri
        )
        
        # Verify results
        assert isinstance(result, OAuthTestResult)
        assert result.is_vulnerable == True
        assert result.vulnerability_type == OAuthVulnerabilityType.REDIRECT_URI_BYPASS
        assert result.malicious_redirect_uri == malicious_uri
        assert result.confidence > 0.8
        assert len(result.exploitation_steps) > 0
    
    @pytest.mark.asyncio
    async def test_redirect_uri_bypass_not_vulnerable(
        self, oauth_tester, mock_request_handler, sample_oauth_config
    ):
        """Test when redirect_uri validation is enforced"""
        # Mock response that rejects malicious redirect_uri
        response = Mock(spec=Response)
        response.status_code = 400
        response.text = "error=invalid_redirect_uri"
        response.headers = {}
        
        mock_request_handler.send_request.return_value = response
        
        # Test redirect_uri bypass
        malicious_uri = "https://attacker.com/callback"
        result = await oauth_tester._test_single_redirect_uri(
            sample_oauth_config, malicious_uri
        )
        
        # Verify results
        assert result.is_vulnerable == False
        assert result.confidence == 0.0
    
    @pytest.mark.asyncio
    async def test_state_parameter_missing_vulnerable(
        self, oauth_tester, mock_request_handler, sample_oauth_config
    ):
        """Test OAuth state parameter missing vulnerability"""
        # Mock response that accepts request without state
        response = Mock(spec=Response)
        response.status_code = 302
        response.text = ""
        response.headers = {}
        
        mock_request_handler.send_request.return_value = response
        
        # Test state parameter
        result = await oauth_tester._test_state_parameter(sample_oauth_config)
        
        # Verify results
        assert result.is_vulnerable == True
        assert result.vulnerability_type == OAuthVulnerabilityType.STATE_MISSING
        assert result.confidence > 0.8
        assert len(result.exploitation_steps) > 0
    
    @pytest.mark.asyncio
    async def test_token_leakage_implicit_flow(
        self, oauth_tester, sample_oauth_config
    ):
        """Test token leakage detection with implicit flow"""
        # Configure for implicit flow
        sample_oauth_config.response_type = "token"
        
        # Test token leakage
        result = await oauth_tester._test_token_leakage(sample_oauth_config)
        
        # Verify results
        assert result.is_vulnerable == True
        assert result.vulnerability_type == OAuthVulnerabilityType.IMPLICIT_FLOW
        assert result.confidence > 0.7
        assert len(result.exploitation_steps) > 0
    
    @pytest.mark.asyncio
    async def test_token_leakage_code_flow_secure(
        self, oauth_tester, sample_oauth_config
    ):
        """Test that authorization code flow is considered secure"""
        # Use authorization code flow (default)
        sample_oauth_config.response_type = "code"
        
        # Test token leakage
        result = await oauth_tester._test_token_leakage(sample_oauth_config)
        
        # Verify results
        assert result.is_vulnerable == False
        assert result.confidence == 0.0
    
    @pytest.mark.asyncio
    async def test_pkce_bypass_vulnerable(
        self, oauth_tester, mock_request_handler, sample_oauth_config
    ):
        """Test PKCE bypass detection"""
        # Mock response that accepts request without PKCE
        response = Mock(spec=Response)
        response.status_code = 302
        response.text = ""
        response.headers = {}
        
        mock_request_handler.send_request.return_value = response
        
        # Test PKCE bypass
        result = await oauth_tester._test_pkce_bypass(sample_oauth_config)
        
        # Verify results
        assert result.is_vulnerable == True
        assert result.vulnerability_type == OAuthVulnerabilityType.PKCE_BYPASS
        assert result.confidence > 0.8
        assert len(result.exploitation_steps) > 0
    
    @pytest.mark.asyncio
    async def test_code_interception_http_redirect(
        self, oauth_tester, sample_oauth_config
    ):
        """Test code interception risk with HTTP redirect_uri"""
        # Configure HTTP redirect_uri
        sample_oauth_config.redirect_uri = "http://app.example.com/callback"
        
        # Test code interception
        result = await oauth_tester._test_code_interception(sample_oauth_config)
        
        # Verify results
        assert result.is_vulnerable == True
        assert result.vulnerability_type == OAuthVulnerabilityType.CODE_INTERCEPTION
        assert result.confidence > 0.6
        assert len(result.exploitation_steps) > 0
    
    @pytest.mark.asyncio
    async def test_code_interception_https_secure(
        self, oauth_tester, sample_oauth_config
    ):
        """Test that HTTPS redirect_uri is considered secure"""
        # Use HTTPS redirect_uri (default)
        assert sample_oauth_config.redirect_uri.startswith("https://")
        
        # Test code interception
        result = await oauth_tester._test_code_interception(sample_oauth_config)
        
        # Verify results
        assert result.is_vulnerable == False
        assert result.confidence == 0.0



class TestSAMLTester:
    """Test SAML tester functionality"""
    
    def test_parse_saml_assertion(self, saml_tester, sample_saml_assertion):
        """Test SAML assertion parsing"""
        # Parse assertion
        assertion = saml_tester._parse_saml_assertion(sample_saml_assertion)
        
        # Verify parsing
        assert isinstance(assertion, SAMLAssertion)
        assert assertion.issuer == "https://idp.example.com"
        assert assertion.subject == "user@example.com"
        assert assertion.recipient == "https://app.example.com/acs"
        assert assertion.is_signed == True
        assert "email" in assertion.attributes
        assert assertion.attributes["email"] == "user@example.com"
        assert "role" in assertion.attributes
        assert assertion.attributes["role"] == "user"
    
    @pytest.mark.asyncio
    async def test_signature_wrapping_vulnerable(
        self, saml_tester, mock_request_handler, sample_saml_assertion
    ):
        """Test SAML signature wrapping detection"""
        # Mock response that accepts wrapped assertion
        response = Mock(spec=Response)
        response.status_code = 200
        response.text = "Login successful"
        response.headers = {}
        
        mock_request_handler.send_request.return_value = response
        
        # Parse assertion
        assertion = saml_tester._parse_saml_assertion(sample_saml_assertion)
        
        # Test signature wrapping
        result = await saml_tester._test_signature_wrapping(
            assertion, "https://app.example.com/acs"
        )
        
        # Verify results
        assert isinstance(result, SAMLTestResult)
        assert result.is_vulnerable == True
        assert result.vulnerability_type == SAMLVulnerabilityType.SIGNATURE_WRAPPING
        assert result.confidence > 0.9
        assert len(result.exploitation_steps) > 0
        assert result.modified_assertion is not None
    
    @pytest.mark.asyncio
    async def test_signature_wrapping_not_vulnerable(
        self, saml_tester, mock_request_handler, sample_saml_assertion
    ):
        """Test when signature wrapping is prevented"""
        # Mock response that rejects wrapped assertion
        response = Mock(spec=Response)
        response.status_code = 403
        response.text = "SAML error: signature verification failed"
        response.headers = {}
        
        mock_request_handler.send_request.return_value = response
        
        # Parse assertion
        assertion = saml_tester._parse_saml_assertion(sample_saml_assertion)
        
        # Test signature wrapping
        result = await saml_tester._test_signature_wrapping(
            assertion, "https://app.example.com/acs"
        )
        
        # Verify results
        assert result.is_vulnerable == False
        assert result.confidence == 0.0
    
    @pytest.mark.asyncio
    async def test_assertion_replay_vulnerable(
        self, saml_tester, mock_request_handler, sample_saml_assertion
    ):
        """Test SAML assertion replay detection"""
        # Mock responses that accept replayed assertion
        response1 = Mock(spec=Response)
        response1.status_code = 200
        response1.text = "Login successful"
        response1.headers = {}
        
        response2 = Mock(spec=Response)
        response2.status_code = 200
        response2.text = "Login successful"
        response2.headers = {}
        
        mock_request_handler.send_request.side_effect = [response1, response2]
        
        # Parse assertion
        assertion = saml_tester._parse_saml_assertion(sample_saml_assertion)
        
        # Test assertion replay
        result = await saml_tester._test_assertion_replay(
            assertion, "https://app.example.com/acs"
        )
        
        # Verify results
        assert result.is_vulnerable == True
        assert result.vulnerability_type == SAMLVulnerabilityType.ASSERTION_REPLAY
        assert result.confidence > 0.8
        assert len(result.exploitation_steps) > 0
    
    @pytest.mark.asyncio
    async def test_assertion_replay_not_vulnerable(
        self, saml_tester, mock_request_handler, sample_saml_assertion
    ):
        """Test when assertion replay is prevented"""
        # Mock responses - second one rejects replay
        response1 = Mock(spec=Response)
        response1.status_code = 200
        response1.text = "Login successful"
        response1.headers = {}
        
        response2 = Mock(spec=Response)
        response2.status_code = 403
        response2.text = "SAML error: replay detected"
        response2.headers = {}
        
        mock_request_handler.send_request.side_effect = [response1, response2]
        
        # Parse assertion
        assertion = saml_tester._parse_saml_assertion(sample_saml_assertion)
        
        # Test assertion replay
        result = await saml_tester._test_assertion_replay(
            assertion, "https://app.example.com/acs"
        )
        
        # Verify results
        assert result.is_vulnerable == False
        assert result.confidence == 0.0
    
    @pytest.mark.asyncio
    async def test_recipient_bypass_vulnerable(
        self, saml_tester, mock_request_handler, sample_saml_assertion
    ):
        """Test SAML recipient validation bypass"""
        # Mock response that accepts modified recipient
        response = Mock(spec=Response)
        response.status_code = 200
        response.text = "Login successful"
        response.headers = {}
        
        mock_request_handler.send_request.return_value = response
        
        # Parse assertion
        assertion = saml_tester._parse_saml_assertion(sample_saml_assertion)
        
        # Test recipient bypass
        result = await saml_tester._test_recipient_bypass(
            assertion, "https://app.example.com/acs"
        )
        
        # Verify results
        assert result.is_vulnerable == True
        assert result.vulnerability_type == SAMLVulnerabilityType.RECIPIENT_BYPASS
        assert result.confidence > 0.8
        assert len(result.exploitation_steps) > 0
        assert result.modified_assertion is not None
    
    @pytest.mark.asyncio
    async def test_attribute_injection_vulnerable(
        self, saml_tester, mock_request_handler, sample_saml_assertion
    ):
        """Test SAML attribute injection detection"""
        # Mock response that accepts injected attributes with admin indicators
        response = Mock(spec=Response)
        response.status_code = 200
        response.text = "Welcome Administrator! You have admin access."
        response.headers = {}
        
        mock_request_handler.send_request.return_value = response
        
        # Parse assertion
        assertion = saml_tester._parse_saml_assertion(sample_saml_assertion)
        
        # Test attribute injection
        result = await saml_tester._test_attribute_injection(
            assertion, "https://app.example.com/acs"
        )
        
        # Verify results
        assert result.is_vulnerable == True
        assert result.vulnerability_type == SAMLVulnerabilityType.ATTRIBUTE_INJECTION
        assert result.confidence > 0.8
        assert len(result.exploitation_steps) > 0
        assert result.modified_assertion is not None
    
    @pytest.mark.asyncio
    async def test_attribute_injection_not_vulnerable(
        self, saml_tester, mock_request_handler, sample_saml_assertion
    ):
        """Test when attribute injection is prevented"""
        # Mock response that rejects injected attributes
        response = Mock(spec=Response)
        response.status_code = 403
        response.text = "SAML error: invalid assertion"
        response.headers = {}
        
        mock_request_handler.send_request.return_value = response
        
        # Parse assertion
        assertion = saml_tester._parse_saml_assertion(sample_saml_assertion)
        
        # Test attribute injection
        result = await saml_tester._test_attribute_injection(
            assertion, "https://app.example.com/acs"
        )
        
        # Verify results
        assert result.is_vulnerable == False
        assert result.confidence == 0.0



class TestAccountTakeoverDemo:
    """Test account takeover demonstration functionality"""
    
    def test_generate_oauth_takeover_steps_with_vulnerabilities(self):
        """Test OAuth takeover steps generation with vulnerabilities"""
        # Create sample vulnerable results
        results = [
            OAuthTestResult(
                is_vulnerable=True,
                vulnerability_type=OAuthVulnerabilityType.REDIRECT_URI_BYPASS,
                confidence=0.95,
                evidence=["redirect_uri bypass detected"],
                malicious_redirect_uri="https://attacker.com",
                exploitation_steps=[
                    "1. Craft malicious URL",
                    "2. Send to victim",
                    "3. Capture authorization code",
                ],
            ),
        ]
        
        # Generate takeover steps
        steps = AccountTakeoverDemo.generate_oauth_takeover_steps(results)
        
        # Verify steps
        assert len(steps) > 0
        assert any("OAuth Account Takeover" in step for step in steps)
        assert any("redirect_uri_bypass" in step for step in steps)
        assert any("Impact" in step for step in steps)
        assert any("Remediation" in step for step in steps)
    
    def test_generate_oauth_takeover_steps_no_vulnerabilities(self):
        """Test OAuth takeover steps with no vulnerabilities"""
        # Create sample non-vulnerable results
        results = [
            OAuthTestResult(
                is_vulnerable=False,
                confidence=0.0,
                evidence=["No vulnerabilities found"],
            ),
        ]
        
        # Generate takeover steps
        steps = AccountTakeoverDemo.generate_oauth_takeover_steps(results)
        
        # Verify steps
        assert len(steps) > 0
        assert any("No exploitable" in step for step in steps)
    
    def test_generate_saml_takeover_steps_with_vulnerabilities(self):
        """Test SAML takeover steps generation with vulnerabilities"""
        # Create sample vulnerable results
        results = [
            SAMLTestResult(
                is_vulnerable=True,
                vulnerability_type=SAMLVulnerabilityType.SIGNATURE_WRAPPING,
                confidence=0.95,
                evidence=["Signature wrapping detected"],
                exploitation_steps=[
                    "1. Intercept assertion",
                    "2. Wrap malicious assertion",
                    "3. Send to ACS",
                ],
            ),
        ]
        
        # Generate takeover steps
        steps = AccountTakeoverDemo.generate_saml_takeover_steps(results)
        
        # Verify steps
        assert len(steps) > 0
        assert any("SAML Account Takeover" in step for step in steps)
        assert any("signature_wrapping" in step for step in steps)
        assert any("Impact" in step for step in steps)
        assert any("Remediation" in step for step in steps)
    
    def test_generate_saml_takeover_steps_no_vulnerabilities(self):
        """Test SAML takeover steps with no vulnerabilities"""
        # Create sample non-vulnerable results
        results = [
            SAMLTestResult(
                is_vulnerable=False,
                confidence=0.0,
                evidence=["No vulnerabilities found"],
            ),
        ]
        
        # Generate takeover steps
        steps = AccountTakeoverDemo.generate_saml_takeover_steps(results)
        
        # Verify steps
        assert len(steps) > 0
        assert any("No exploitable" in step for step in steps)


class TestConvenienceFunctions:
    """Test convenience functions"""
    
    @pytest.mark.asyncio
    async def test_test_oauth_vulnerabilities(self, mock_request_handler):
        """Test OAuth convenience function"""
        # Mock response
        response = Mock(spec=Response)
        response.status_code = 302
        response.text = ""
        response.headers = {}
        
        mock_request_handler.send_request.return_value = response
        
        # Test OAuth
        results, takeover_steps = await test_oauth_vulnerabilities(
            authorization_endpoint="https://oauth.example.com/authorize",
            token_endpoint="https://oauth.example.com/token",
            client_id="test_client",
            redirect_uri="https://app.example.com/callback",
            request_handler=mock_request_handler,
        )
        
        # Verify results
        assert isinstance(results, list)
        assert isinstance(takeover_steps, list)
        assert len(takeover_steps) > 0
    
    @pytest.mark.asyncio
    async def test_test_saml_vulnerabilities(
        self, mock_request_handler, sample_saml_assertion
    ):
        """Test SAML convenience function"""
        # Mock response
        response = Mock(spec=Response)
        response.status_code = 200
        response.text = "Login successful"
        response.headers = {}
        
        mock_request_handler.send_request.return_value = response
        
        # Test SAML
        results, takeover_steps = await test_saml_vulnerabilities(
            assertion_xml=sample_saml_assertion,
            acs_url="https://app.example.com/acs",
            request_handler=mock_request_handler,
        )
        
        # Verify results
        assert isinstance(results, list)
        assert isinstance(takeover_steps, list)
        assert len(takeover_steps) > 0


class TestOAuthConfig:
    """Test OAuth configuration"""
    
    def test_oauth_config_creation(self):
        """Test OAuth config creation"""
        config = OAuthConfig(
            authorization_endpoint="https://oauth.example.com/authorize",
            token_endpoint="https://oauth.example.com/token",
            client_id="test_client",
            redirect_uri="https://app.example.com/callback",
        )
        
        assert config.authorization_endpoint == "https://oauth.example.com/authorize"
        assert config.token_endpoint == "https://oauth.example.com/token"
        assert config.client_id == "test_client"
        assert config.redirect_uri == "https://app.example.com/callback"
        assert config.response_type == "code"  # default
        assert config.use_pkce == False  # default


class TestSAMLAssertion:
    """Test SAML assertion data structure"""
    
    def test_saml_assertion_creation(self):
        """Test SAML assertion creation"""
        assertion = SAMLAssertion(
            raw_xml="<saml:Assertion>...</saml:Assertion>",
            issuer="https://idp.example.com",
            subject="user@example.com",
            attributes={"email": "user@example.com", "role": "user"},
            recipient="https://app.example.com/acs",
            is_signed=True,
        )
        
        assert assertion.issuer == "https://idp.example.com"
        assert assertion.subject == "user@example.com"
        assert assertion.recipient == "https://app.example.com/acs"
        assert assertion.is_signed == True
        assert "email" in assertion.attributes
        assert assertion.attributes["email"] == "user@example.com"
