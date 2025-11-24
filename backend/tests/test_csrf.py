"""Tests for CSRF module"""

import pytest
from unittest.mock import Mock, AsyncMock
from app.modules.csrf import (
    CSRFTester,
    CSRFPoCGenerator,
    CSRFTestPoint,
    CSRFResult,
    CSRFTechnique,
)
from app.core.request_handler import Response


@pytest.fixture
def mock_request_handler():
    """Create mock request handler"""
    handler = Mock()
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def csrf_tester(mock_request_handler):
    """Create CSRF tester instance"""
    return CSRFTester(mock_request_handler)


@pytest.fixture
def sample_test_point():
    """Create sample CSRF test point"""
    return CSRFTestPoint(
        url="https://example.com/transfer",
        method="POST",
        parameters={
            "amount": "1000",
            "to_account": "attacker",
            "csrf_token": "abc123xyz"
        },
        csrf_token_name="csrf_token",
        csrf_token_value="abc123xyz",
        csrf_token_location="parameter"
    )


class TestCSRFTester:
    """Test CSRF tester functionality"""
    
    @pytest.mark.asyncio
    async def test_token_omission_vulnerable(
        self, csrf_tester, mock_request_handler, sample_test_point
    ):
        """Test CSRF detection with token omission"""
        # Mock baseline response (legitimate request)
        baseline_response = Mock(spec=Response)
        baseline_response.status_code = 200
        baseline_response.text = "Transfer successful"
        
        # Mock attack response (request without token also succeeds)
        attack_response = Mock(spec=Response)
        attack_response.status_code = 200
        attack_response.text = "Transfer successful"
        
        # Set up mock to return different responses
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            attack_response
        ]
        
        # Test for CSRF
        results = await csrf_tester.test_endpoint(
            sample_test_point,
            techniques=[CSRFTechnique.TOKEN_OMISSION]
        )
        
        # Verify results
        assert len(results) > 0
        result = results[0]
        assert isinstance(result, CSRFResult)
        assert result.is_vulnerable == True
        assert result.technique == CSRFTechnique.TOKEN_OMISSION
        assert result.confidence > 0.9
        assert result.poc_html is not None
        assert result.poc_javascript is not None
    
    @pytest.mark.asyncio
    async def test_token_omission_not_vulnerable(
        self, csrf_tester, mock_request_handler, sample_test_point
    ):
        """Test when token omission is properly protected"""
        # Mock baseline response
        baseline_response = Mock(spec=Response)
        baseline_response.status_code = 200
        baseline_response.text = "Transfer successful"
        
        # Mock attack response (request without token fails)
        attack_response = Mock(spec=Response)
        attack_response.status_code = 403
        attack_response.text = "CSRF token missing"
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            attack_response
        ]
        
        # Test for CSRF
        results = await csrf_tester.test_endpoint(
            sample_test_point,
            techniques=[CSRFTechnique.TOKEN_OMISSION]
        )
        
        # Verify not vulnerable
        assert len(results) > 0
        result = results[0]
        assert result.is_vulnerable == False
        assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_token_reuse_vulnerable(
        self, csrf_tester, mock_request_handler, sample_test_point
    ):
        """Test CSRF detection with token reuse"""
        # Mock responses - token can be reused
        baseline_response = Mock(spec=Response)
        baseline_response.status_code = 200
        baseline_response.text = "Transfer successful"
        
        first_use_response = Mock(spec=Response)
        first_use_response.status_code = 200
        first_use_response.text = "Transfer successful"
        
        reuse_response = Mock(spec=Response)
        reuse_response.status_code = 200
        reuse_response.text = "Transfer successful"
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            first_use_response,
            reuse_response
        ]
        
        # Test token reuse
        results = await csrf_tester.test_endpoint(
            sample_test_point,
            techniques=[CSRFTechnique.TOKEN_REUSE]
        )
        
        # Verify vulnerable
        assert len(results) > 0
        result = results[0]
        assert result.is_vulnerable == True
        assert result.technique == CSRFTechnique.TOKEN_REUSE
    
    @pytest.mark.asyncio
    async def test_method_switching_vulnerable(
        self, csrf_tester, mock_request_handler, sample_test_point
    ):
        """Test CSRF detection with method switching"""
        # Mock baseline response
        baseline_response = Mock(spec=Response)
        baseline_response.status_code = 200
        baseline_response.text = "Transfer successful"
        
        # Mock GET request response (should fail but doesn't)
        get_response = Mock(spec=Response)
        get_response.status_code = 200
        get_response.text = "Transfer successful"
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            get_response
        ]
        
        # Test method switching
        results = await csrf_tester.test_endpoint(
            sample_test_point,
            techniques=[CSRFTechnique.METHOD_SWITCHING]
        )
        
        # Verify vulnerable
        assert len(results) > 0
        result = results[0]
        assert result.is_vulnerable == True
        assert result.technique == CSRFTechnique.METHOD_SWITCHING
        assert "attack_url" in result.metadata
    
    @pytest.mark.asyncio
    async def test_method_switching_not_post(
        self, csrf_tester, mock_request_handler
    ):
        """Test method switching on non-POST request"""
        # Create GET test point
        test_point = CSRFTestPoint(
            url="https://example.com/view",
            method="GET",
            parameters={"id": "123"}
        )
        
        # Test method switching (should skip)
        results = await csrf_tester.test_endpoint(
            test_point,
            techniques=[CSRFTechnique.METHOD_SWITCHING]
        )
        
        # Verify skipped
        assert len(results) > 0
        result = results[0]
        assert result.is_vulnerable == False
        assert "only applies to POST" in result.evidence[0]
    
    @pytest.mark.asyncio
    async def test_referer_bypass_vulnerable(
        self, csrf_tester, mock_request_handler, sample_test_point
    ):
        """Test CSRF with referer bypass"""
        # Mock responses
        baseline_response = Mock(spec=Response)
        baseline_response.status_code = 200
        baseline_response.text = "Success"
        
        attack_response = Mock(spec=Response)
        attack_response.status_code = 200
        attack_response.text = "Success"
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            attack_response
        ]
        
        # Test referer bypass
        results = await csrf_tester.test_endpoint(
            sample_test_point,
            techniques=[CSRFTechnique.REFERER_BYPASS]
        )
        
        # Verify vulnerable
        assert len(results) > 0
        result = results[0]
        assert result.is_vulnerable == True
        assert result.technique == CSRFTechnique.REFERER_BYPASS
    
    @pytest.mark.asyncio
    async def test_origin_bypass_vulnerable(
        self, csrf_tester, mock_request_handler, sample_test_point
    ):
        """Test CSRF with origin bypass"""
        # Mock responses
        baseline_response = Mock(spec=Response)
        baseline_response.status_code = 200
        baseline_response.text = "Success"
        
        attack_response = Mock(spec=Response)
        attack_response.status_code = 200
        attack_response.text = "Success"
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            attack_response
        ]
        
        # Test origin bypass
        results = await csrf_tester.test_endpoint(
            sample_test_point,
            techniques=[CSRFTechnique.ORIGIN_BYPASS]
        )
        
        # Verify vulnerable
        assert len(results) > 0
        result = results[0]
        assert result.is_vulnerable == True
        assert result.technique == CSRFTechnique.ORIGIN_BYPASS
    
    @pytest.mark.asyncio
    async def test_csrf_token_detection_parameter(self, csrf_tester):
        """Test CSRF token detection in parameters"""
        test_point = CSRFTestPoint(
            url="https://example.com/action",
            method="POST",
            parameters={
                "action": "delete",
                "_csrf": "token123"
            }
        )
        
        # Detect token
        await csrf_tester._detect_csrf_token(test_point)
        
        # Verify detection
        assert test_point.csrf_token_name == "_csrf"
        assert test_point.csrf_token_value == "token123"
        assert test_point.csrf_token_location == "parameter"
    
    @pytest.mark.asyncio
    async def test_csrf_token_detection_header(self, csrf_tester):
        """Test CSRF token detection in headers"""
        test_point = CSRFTestPoint(
            url="https://example.com/action",
            method="POST",
            parameters={"action": "delete"},
            headers={"X-CSRF-Token": "header_token"}
        )
        
        # Detect token
        await csrf_tester._detect_csrf_token(test_point)
        
        # Verify detection
        assert test_point.csrf_token_name == "X-CSRF-Token"
        assert test_point.csrf_token_value == "header_token"
        assert test_point.csrf_token_location == "header"
    
    @pytest.mark.asyncio
    async def test_csrf_token_detection_cookie(self, csrf_tester):
        """Test CSRF token detection in cookies"""
        test_point = CSRFTestPoint(
            url="https://example.com/action",
            method="POST",
            parameters={"action": "delete"},
            cookies={"csrftoken": "cookie_token"}
        )
        
        # Detect token
        await csrf_tester._detect_csrf_token(test_point)
        
        # Verify detection
        assert test_point.csrf_token_name == "csrftoken"
        assert test_point.csrf_token_value == "cookie_token"
        assert test_point.csrf_token_location == "cookie"
    
    def test_is_request_successful_same_status(self, csrf_tester):
        """Test success detection with same status codes"""
        baseline = Mock(spec=Response)
        baseline.status_code = 200
        baseline.text = "Success"
        
        attack = Mock(spec=Response)
        attack.status_code = 200
        attack.text = "Success"
        
        is_successful = csrf_tester._is_request_successful(baseline, attack)
        assert is_successful == True
    
    def test_is_request_successful_with_error_text(self, csrf_tester):
        """Test success detection with error indicators"""
        baseline = Mock(spec=Response)
        baseline.status_code = 200
        baseline.text = "Success"
        
        attack = Mock(spec=Response)
        attack.status_code = 200
        attack.text = "Error: CSRF token invalid"
        
        is_successful = csrf_tester._is_request_successful(baseline, attack)
        assert is_successful == False
    
    def test_is_request_successful_failed_status(self, csrf_tester):
        """Test success detection with failed status"""
        baseline = Mock(spec=Response)
        baseline.status_code = 200
        baseline.text = "Success"
        
        attack = Mock(spec=Response)
        attack.status_code = 403
        attack.text = "Forbidden"
        
        is_successful = csrf_tester._is_request_successful(baseline, attack)
        assert is_successful == False
    
    def test_generate_invalid_token(self, csrf_tester):
        """Test invalid token generation"""
        original = "abc123xyz"
        invalid = csrf_tester._generate_invalid_token(original)
        
        # Should be different from original
        assert invalid != original
        assert len(invalid) > 0
    
    def test_generate_invalid_token_empty(self, csrf_tester):
        """Test invalid token generation with empty input"""
        invalid = csrf_tester._generate_invalid_token("")
        
        # Should return a default invalid token
        assert invalid == "invalid_token_12345"


class TestCSRFPoCGenerator:
    """Test CSRF PoC generator"""
    
    def test_html_poc_generation_post(self):
        """Test HTML PoC generation for POST request"""
        test_point = CSRFTestPoint(
            url="https://example.com/transfer",
            method="POST",
            parameters={
                "amount": "1000",
                "to_account": "attacker",
                "csrf_token": "abc123"
            },
            csrf_token_name="csrf_token"
        )
        
        poc_generator = CSRFPoCGenerator()
        poc_html = poc_generator.generate_html_poc(
            test_point,
            CSRFTechnique.TOKEN_OMISSION
        )
        
        # Verify PoC contains key elements
        assert "<!DOCTYPE html>" in poc_html
        assert "CSRF Proof of Concept" in poc_html
        assert test_point.url in poc_html
        assert "amount" in poc_html
        assert "to_account" in poc_html
        assert "csrf_token" not in poc_html  # Token should be omitted
        assert "Safe Demonstration Instructions" in poc_html
    
    def test_html_poc_generation_method_switching(self):
        """Test HTML PoC generation for method switching"""
        test_point = CSRFTestPoint(
            url="https://example.com/delete",
            method="POST",
            parameters={
                "id": "123",
                "csrf_token": "abc123"
            },
            csrf_token_name="csrf_token"
        )
        
        poc_generator = CSRFPoCGenerator()
        poc_html = poc_generator.generate_html_poc(
            test_point,
            CSRFTechnique.METHOD_SWITCHING
        )
        
        # Verify PoC contains GET-based attack
        assert "<!DOCTYPE html>" in poc_html
        assert "Method Switching" in poc_html
        assert "id=123" in poc_html
        assert "csrf_token" not in poc_html
    
    def test_javascript_poc_generation_post(self):
        """Test JavaScript PoC generation for POST request"""
        test_point = CSRFTestPoint(
            url="https://example.com/transfer",
            method="POST",
            parameters={
                "amount": "1000",
                "to_account": "attacker",
                "csrf_token": "abc123"
            },
            csrf_token_name="csrf_token"
        )
        
        poc_generator = CSRFPoCGenerator()
        poc_js = poc_generator.generate_javascript_poc(
            test_point,
            CSRFTechnique.TOKEN_OMISSION
        )
        
        # Verify JavaScript contains key functions
        assert "csrfAttackForm" in poc_js
        assert "csrfAttackFetch" in poc_js
        assert "csrfAttackXHR" in poc_js
        assert test_point.url in poc_js
        assert "amount" in poc_js
        assert "to_account" in poc_js
        assert "Safe demonstration instructions" in poc_js
    
    def test_javascript_poc_generation_method_switching(self):
        """Test JavaScript PoC generation for method switching"""
        test_point = CSRFTestPoint(
            url="https://example.com/delete",
            method="POST",
            parameters={
                "id": "123",
                "csrf_token": "abc123"
            },
            csrf_token_name="csrf_token"
        )
        
        poc_generator = CSRFPoCGenerator()
        poc_js = poc_generator.generate_javascript_poc(
            test_point,
            CSRFTechnique.METHOD_SWITCHING
        )
        
        # Verify JavaScript contains GET-based attacks
        assert "csrfAttackImage" in poc_js
        assert "csrfAttackFetch" in poc_js
        assert "csrfAttackXHR" in poc_js
        assert test_point.url in poc_js
        assert "Method Switching" in poc_js


class TestCSRFTestPoint:
    """Test CSRFTestPoint dataclass"""
    
    def test_test_point_creation(self):
        """Test creating CSRF test point"""
        test_point = CSRFTestPoint(
            url="https://example.com/action",
            method="POST",
            parameters={"key": "value"},
            csrf_token_name="csrf_token",
            csrf_token_value="abc123",
            csrf_token_location="parameter"
        )
        
        assert test_point.url == "https://example.com/action"
        assert test_point.method == "POST"
        assert test_point.parameters == {"key": "value"}
        assert test_point.csrf_token_name == "csrf_token"
        assert test_point.csrf_token_value == "abc123"
        assert test_point.csrf_token_location == "parameter"
    
    def test_test_point_defaults(self):
        """Test CSRF test point with defaults"""
        test_point = CSRFTestPoint(
            url="https://example.com/action"
        )
        
        assert test_point.url == "https://example.com/action"
        assert test_point.method == "POST"
        assert test_point.parameters == {}
        assert test_point.headers == {}
        assert test_point.cookies == {}
        assert test_point.csrf_token_name is None


class TestCSRFResult:
    """Test CSRFResult dataclass"""
    
    def test_result_creation(self):
        """Test creating CSRF result"""
        test_point = CSRFTestPoint(
            url="https://example.com/action",
            method="POST"
        )
        
        result = CSRFResult(
            test_point=test_point,
            is_vulnerable=True,
            technique=CSRFTechnique.TOKEN_OMISSION,
            confidence=0.95
        )
        
        assert result.is_vulnerable == True
        assert result.technique == CSRFTechnique.TOKEN_OMISSION
        assert result.confidence == 0.95
        assert result.test_point == test_point
    
    def test_result_with_evidence(self):
        """Test CSRF result with evidence"""
        test_point = CSRFTestPoint(
            url="https://example.com/action",
            method="POST"
        )
        
        evidence = [
            "CSRF vulnerability detected",
            "Token omission successful",
            "Confidence: 95%"
        ]
        
        result = CSRFResult(
            test_point=test_point,
            is_vulnerable=True,
            evidence=evidence
        )
        
        assert len(result.evidence) == 3
        assert "CSRF vulnerability detected" in result.evidence


class TestCSRFTechniques:
    """Test CSRF techniques enum"""
    
    def test_all_techniques_available(self):
        """Test that all techniques are defined"""
        techniques = list(CSRFTechnique)
        
        assert CSRFTechnique.TOKEN_OMISSION in techniques
        assert CSRFTechnique.TOKEN_REUSE in techniques
        assert CSRFTechnique.TOKEN_EXPIRATION in techniques
        assert CSRFTechnique.METHOD_SWITCHING in techniques
        assert CSRFTechnique.REFERER_BYPASS in techniques
        assert CSRFTechnique.ORIGIN_BYPASS in techniques
    
    def test_technique_values(self):
        """Test technique enum values"""
        assert CSRFTechnique.TOKEN_OMISSION.value == "token_omission"
        assert CSRFTechnique.TOKEN_REUSE.value == "token_reuse"
        assert CSRFTechnique.METHOD_SWITCHING.value == "method_switching"
