"""Tests for JWT manipulation module"""

import pytest
import json
import base64
from unittest.mock import AsyncMock, Mock, patch

from app.modules.jwt_manipulation import (
    JWTInspector,
    JWTTamperer,
    JWTReplacer,
    JWTVulnerabilityScanner,
    JWTToken,
    JWTAlgorithm,
)
from app.core.request_handler import RequestHandler
from app.core.http_models import Request, Response
from app.core.config import Settings


# Test fixtures

@pytest.fixture
def request_handler():
    """Create test request handler"""
    return RequestHandler()


@pytest.fixture
def jwt_inspector(request_handler):
    """Create JWT inspector"""
    return JWTInspector(request_handler)


@pytest.fixture
def jwt_tamperer():
    """Create JWT tamperer"""
    return JWTTamperer()


@pytest.fixture
def jwt_replacer(request_handler):
    """Create JWT replacer"""
    return JWTReplacer(request_handler)


@pytest.fixture
def sample_jwt():
    """Sample JWT token for testing"""
    # Header: {"alg": "HS256", "typ": "JWT"}
    # Payload: {"sub": "1234567890", "name": "John Doe", "isAdmin": false, "iat": 1516239022}
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaXNBZG1pbiI6ZmFsc2UsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


@pytest.fixture
def sample_jwt_token(jwt_inspector, sample_jwt):
    """Decoded sample JWT token"""
    return jwt_inspector.decode_jwt(sample_jwt)


# JWT Inspector Tests

class TestJWTInspector:
    """Tests for JWTInspector class"""
    
    def test_decode_jwt_valid(self, jwt_inspector, sample_jwt):
        """Test decoding a valid JWT"""
        token = jwt_inspector.decode_jwt(sample_jwt)
        
        assert token is not None
        assert token.raw_token == sample_jwt
        assert token.algorithm == "HS256"
        assert token.token_type == "JWT"
        assert token.payload["sub"] == "1234567890"
        assert token.payload["name"] == "John Doe"
        assert token.payload["isAdmin"] is False
    
    def test_decode_jwt_invalid(self, jwt_inspector):
        """Test decoding an invalid JWT"""
        invalid_jwt = "not.a.jwt"
        token = jwt_inspector.decode_jwt(invalid_jwt)
        
        assert token is None
    
    def test_decode_jwt_malformed(self, jwt_inspector):
        """Test decoding a malformed JWT"""
        malformed_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid_payload.signature"
        token = jwt_inspector.decode_jwt(malformed_jwt)
        
        assert token is None
    
    def test_detect_jwt_in_response_header(self, jwt_inspector, sample_jwt):
        """Test detecting JWT in response header"""
        response = Response(
            status_code=200,
            headers={"Authorization": f"Bearer {sample_jwt}"},
            body=b"",
            text="",
            elapsed_time=0.1,
            request=Mock(),
        )
        
        tokens = jwt_inspector.detect_jwt_in_response(response)
        
        assert len(tokens) == 1
        assert tokens[0].raw_token == sample_jwt
        assert tokens[0].location == "header"
        assert tokens[0].parameter_name == "Authorization"
    
    def test_detect_jwt_in_response_cookie(self, jwt_inspector, sample_jwt):
        """Test detecting JWT in Set-Cookie header"""
        response = Response(
            status_code=200,
            headers={"Set-Cookie": f"token={sample_jwt}; Path=/; HttpOnly"},
            body=b"",
            text="",
            elapsed_time=0.1,
            request=Mock(),
        )
        
        tokens = jwt_inspector.detect_jwt_in_response(response)
        
        # JWT is detected twice: once in Set-Cookie header, once as cookie
        assert len(tokens) >= 1
        # Find the cookie token
        cookie_tokens = [t for t in tokens if t.location == "cookie"]
        assert len(cookie_tokens) == 1
        assert cookie_tokens[0].raw_token == sample_jwt
        assert cookie_tokens[0].parameter_name == "token"
    
    def test_detect_jwt_in_response_body(self, jwt_inspector, sample_jwt):
        """Test detecting JWT in response body"""
        body_text = f'{{"token": "{sample_jwt}"}}'
        response = Response(
            status_code=200,
            headers={},
            body=body_text.encode(),
            text=body_text,
            elapsed_time=0.1,
            request=Mock(),
        )
        
        tokens = jwt_inspector.detect_jwt_in_response(response)
        
        assert len(tokens) == 1
        assert tokens[0].raw_token == sample_jwt
        assert tokens[0].location == "body"
    
    def test_detect_jwt_in_request_header(self, jwt_inspector, sample_jwt):
        """Test detecting JWT in request header"""
        request = Request(
            method="GET",
            url="https://example.com",
            headers={"Authorization": f"Bearer {sample_jwt}"},
        )
        
        tokens = jwt_inspector.detect_jwt_in_request(request)
        
        assert len(tokens) == 1
        assert tokens[0].raw_token == sample_jwt
        assert tokens[0].location == "header"
    
    def test_detect_jwt_in_request_cookie(self, jwt_inspector, sample_jwt):
        """Test detecting JWT in request cookie"""
        request = Request(
            method="GET",
            url="https://example.com",
            cookies={"token": sample_jwt},
        )
        
        tokens = jwt_inspector.detect_jwt_in_request(request)
        
        assert len(tokens) == 1
        assert tokens[0].raw_token == sample_jwt
        assert tokens[0].location == "cookie"
    
    def test_display_token_info(self, jwt_inspector, sample_jwt_token):
        """Test displaying token information"""
        display = jwt_inspector.display_token_info(sample_jwt_token)
        
        assert "JWT TOKEN DETECTED" in display
        assert "HEADER:" in display
        assert "PAYLOAD:" in display
        assert "SIGNATURE:" in display
        assert "HS256" in display
        assert "John Doe" in display


# JWT Tamperer Tests

class TestJWTTamperer:
    """Tests for JWTTamperer class"""
    
    def test_edit_claim_payload(self, jwt_tamperer, jwt_inspector, sample_jwt_token):
        """Test editing a payload claim"""
        modified_jwt = jwt_tamperer.edit_claim(
            sample_jwt_token,
            "isAdmin",
            True,
            "payload"
        )
        
        # Decode modified token
        modified_token = jwt_inspector.decode_jwt(modified_jwt)
        
        assert modified_token is not None
        assert modified_token.payload["isAdmin"] is True
        assert modified_token.payload["name"] == "John Doe"  # Other claims unchanged
    
    def test_edit_claim_header(self, jwt_tamperer, jwt_inspector, sample_jwt_token):
        """Test editing a header claim"""
        modified_jwt = jwt_tamperer.edit_claim(
            sample_jwt_token,
            "kid",
            "test-key-id",
            "header"
        )
        
        # Decode modified token
        modified_token = jwt_inspector.decode_jwt(modified_jwt)
        
        assert modified_token is not None
        assert modified_token.header["kid"] == "test-key-id"
        assert modified_token.algorithm == "HS256"  # Other claims unchanged
    
    def test_algorithm_confusion_none(self, jwt_tamperer, jwt_inspector, sample_jwt_token):
        """Test algorithm confusion with 'none'"""
        modified_jwt = jwt_tamperer.algorithm_confusion_none(sample_jwt_token)
        
        # Decode modified token
        modified_token = jwt_inspector.decode_jwt(modified_jwt)
        
        assert modified_token is not None
        assert modified_token.algorithm == "none"
        assert modified_token.signature == ""
    
    def test_algorithm_confusion_hs256(self, jwt_tamperer, jwt_inspector, sample_jwt_token):
        """Test algorithm confusion to HS256"""
        modified_jwt = jwt_tamperer.algorithm_confusion_hs256(sample_jwt_token)
        
        # Decode modified token
        modified_token = jwt_inspector.decode_jwt(modified_jwt)
        
        assert modified_token is not None
        assert modified_token.algorithm == "HS256"
    
    def test_modify_kid(self, jwt_tamperer, jwt_inspector, sample_jwt_token):
        """Test modifying kid parameter"""
        new_kid = "../../../dev/null"
        modified_jwt = jwt_tamperer.modify_kid(sample_jwt_token, new_kid)
        
        # Decode modified token
        modified_token = jwt_inspector.decode_jwt(modified_jwt)
        
        assert modified_token is not None
        assert modified_token.key_id == new_kid
    
    def test_inject_jwk(self, jwt_tamperer, jwt_inspector, sample_jwt_token):
        """Test injecting JWK"""
        jwk = {
            "kty": "RSA",
            "kid": "test-key",
            "use": "sig",
            "n": "test-modulus",
            "e": "AQAB"
        }
        modified_jwt = jwt_tamperer.inject_jwk(sample_jwt_token, jwk)
        
        # Decode modified token
        modified_token = jwt_inspector.decode_jwt(modified_jwt)
        
        assert modified_token is not None
        assert modified_token.jwk == jwk
    
    def test_remove_signature(self, jwt_tamperer, jwt_inspector, sample_jwt_token):
        """Test removing signature"""
        modified_jwt = jwt_tamperer.remove_signature(sample_jwt_token)
        
        # Decode modified token
        modified_token = jwt_inspector.decode_jwt(modified_jwt)
        
        assert modified_token is not None
        assert modified_token.signature == ""
    
    def test_sign_with_key_hs256(self, jwt_tamperer, jwt_inspector, sample_jwt_token):
        """Test signing with HS256"""
        key = "test-secret"
        signed_jwt = jwt_tamperer.sign_with_key(sample_jwt_token, key, "HS256")
        
        # Decode signed token
        signed_token = jwt_inspector.decode_jwt(signed_jwt)
        
        assert signed_token is not None
        assert signed_token.algorithm == "HS256"
        assert signed_token.signature != ""
        assert signed_token.signature != sample_jwt_token.signature


# JWT Replacer Tests

class TestJWTReplacer:
    """Tests for JWTReplacer class"""
    
    def test_register_replacement(self, jwt_replacer, sample_jwt):
        """Test registering a JWT replacement"""
        replacement = "eyJhbGciOiJub25lIn0.eyJpc0FkbWluIjp0cnVlfQ."
        
        jwt_replacer.register_replacement(sample_jwt, replacement)
        
        assert sample_jwt in jwt_replacer.replacement_tokens
        assert jwt_replacer.replacement_tokens[sample_jwt] == replacement
    
    def test_apply_replacements_header(self, jwt_replacer, sample_jwt):
        """Test applying replacements to request header"""
        replacement = "eyJhbGciOiJub25lIn0.eyJpc0FkbWluIjp0cnVlfQ."
        jwt_replacer.register_replacement(sample_jwt, replacement)
        
        request = Request(
            method="GET",
            url="https://example.com",
            headers={"Authorization": f"Bearer {sample_jwt}"},
        )
        
        modified_request = jwt_replacer.apply_replacements(request)
        
        assert replacement in modified_request.headers["Authorization"]
        assert sample_jwt not in modified_request.headers["Authorization"]
    
    def test_apply_replacements_cookie(self, jwt_replacer, sample_jwt):
        """Test applying replacements to request cookie"""
        replacement = "eyJhbGciOiJub25lIn0.eyJpc0FkbWluIjp0cnVlfQ."
        jwt_replacer.register_replacement(sample_jwt, replacement)
        
        request = Request(
            method="GET",
            url="https://example.com",
            cookies={"token": sample_jwt},
        )
        
        modified_request = jwt_replacer.apply_replacements(request)
        
        assert modified_request.cookies["token"] == replacement
    
    def test_apply_replacements_body(self, jwt_replacer, sample_jwt):
        """Test applying replacements to request body"""
        replacement = "eyJhbGciOiJub25lIn0.eyJpc0FkbWluIjp0cnVlfQ."
        jwt_replacer.register_replacement(sample_jwt, replacement)
        
        request = Request(
            method="POST",
            url="https://example.com",
            data=f'{{"token": "{sample_jwt}"}}',
        )
        
        modified_request = jwt_replacer.apply_replacements(request)
        
        assert replacement in modified_request.data
        assert sample_jwt not in modified_request.data
    
    def test_clear_replacements(self, jwt_replacer, sample_jwt):
        """Test clearing all replacements"""
        replacement = "eyJhbGciOiJub25lIn0.eyJpc0FkbWluIjp0cnVlfQ."
        jwt_replacer.register_replacement(sample_jwt, replacement)
        
        assert len(jwt_replacer.replacement_tokens) == 1
        
        jwt_replacer.clear_replacements()
        
        assert len(jwt_replacer.replacement_tokens) == 0


# JWT Vulnerability Scanner Tests

class TestJWTVulnerabilityScanner:
    """Tests for JWTVulnerabilityScanner class"""
    
    @pytest.mark.asyncio
    async def test_scan_token_algorithm_none(self, request_handler, sample_jwt_token):
        """Test scanning for algorithm=none vulnerability"""
        scanner = JWTVulnerabilityScanner(request_handler)
        
        # Mock successful response (vulnerability found)
        mock_response = Response(
            status_code=200,
            headers={},
            body=b"Success",
            text="Success",
            elapsed_time=0.1,
            request=Mock(),
        )
        
        with patch.object(request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response
            
            vulnerabilities = await scanner.scan_token(
                sample_jwt_token,
                "https://example.com/api/test",
                "GET",
                {"Authorization": f"Bearer {sample_jwt_token.raw_token}"}
            )
            
            # Should find algorithm=none vulnerability
            assert len(vulnerabilities) > 0
            assert any(v.vulnerability_type == "algorithm_confusion_none" for v in vulnerabilities)
    
    @pytest.mark.asyncio
    async def test_scan_token_no_vulnerabilities(self, request_handler, sample_jwt_token):
        """Test scanning when no vulnerabilities found"""
        scanner = JWTVulnerabilityScanner(request_handler)
        
        # Mock 401 response (no vulnerability)
        mock_response = Response(
            status_code=401,
            headers={},
            body=b"Unauthorized",
            text="Unauthorized",
            elapsed_time=0.1,
            request=Mock(),
        )
        
        with patch.object(request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response
            
            vulnerabilities = await scanner.scan_token(
                sample_jwt_token,
                "https://example.com/api/test",
                "GET",
                {"Authorization": f"Bearer {sample_jwt_token.raw_token}"}
            )
            
            # Should not find vulnerabilities
            assert len(vulnerabilities) == 0


# Integration Tests

class TestJWTIntegration:
    """Integration tests for JWT module"""
    
    def test_full_workflow_privilege_escalation(
        self,
        jwt_inspector,
        jwt_tamperer,
        jwt_replacer,
        sample_jwt
    ):
        """Test complete workflow: detect -> tamper -> replace"""
        # Step 1: Detect JWT
        token = jwt_inspector.decode_jwt(sample_jwt)
        assert token is not None
        assert token.payload["isAdmin"] is False
        
        # Step 2: Tamper with JWT (privilege escalation)
        tampered_jwt = jwt_tamperer.edit_claim(token, "isAdmin", True, "payload")
        tampered_token = jwt_inspector.decode_jwt(tampered_jwt)
        assert tampered_token.payload["isAdmin"] is True
        
        # Step 3: Register replacement
        jwt_replacer.register_replacement(sample_jwt, tampered_jwt)
        
        # Step 4: Apply replacement to request
        request = Request(
            method="GET",
            url="https://example.com/admin",
            headers={"Authorization": f"Bearer {sample_jwt}"},
        )
        
        modified_request = jwt_replacer.apply_replacements(request)
        
        # Verify tampered JWT is in request
        assert tampered_jwt in modified_request.headers["Authorization"]
        
        # Verify tampered JWT has isAdmin=true
        final_token = jwt_inspector.decode_jwt(tampered_jwt)
        assert final_token.payload["isAdmin"] is True
    
    def test_multiple_jwt_detection(self, jwt_inspector, sample_jwt):
        """Test detecting multiple JWTs in same response"""
        another_jwt = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoidGVzdCJ9."
        
        response = Response(
            status_code=200,
            headers={
                "Authorization": f"Bearer {sample_jwt}",
                "X-Refresh-Token": another_jwt,
            },
            body=b"",
            text="",
            elapsed_time=0.1,
            request=Mock(),
        )
        
        tokens = jwt_inspector.detect_jwt_in_response(response)
        
        # Should detect both JWTs
        assert len(tokens) == 2
        token_strings = [t.raw_token for t in tokens]
        assert sample_jwt in token_strings
        assert another_jwt in token_strings
