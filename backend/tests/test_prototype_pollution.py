"""Tests for Prototype Pollution module"""

import pytest
import json
from unittest.mock import Mock, AsyncMock
from app.modules.prototype_pollution import (
    PrototypePollutionTester,
    InjectionPoint,
    InjectionLocation,
    PrototypePollutionResult,
    PollutionTechnique,
    create_injection_points_from_request,
)
from app.core.request_handler import Response


@pytest.fixture
def mock_request_handler():
    """Create mock request handler"""
    handler = Mock()
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def pollution_tester(mock_request_handler):
    """Create prototype pollution tester instance"""
    return PrototypePollutionTester(mock_request_handler)


@pytest.fixture
def sample_json_injection_point():
    """Create sample JSON injection point"""
    return InjectionPoint(
        parameter="user_data",
        location=InjectionLocation.JSON_BODY,
        original_value='{"name": "test"}',
        url="https://example.com/api/user",
        method="POST",
        headers={"Content-Type": "application/json"},
        json_data={"name": "test"},
    )


@pytest.fixture
def sample_query_injection_point():
    """Create sample query parameter injection point"""
    return InjectionPoint(
        parameter="config",
        location=InjectionLocation.QUERY,
        original_value="default",
        url="https://example.com/api/config?config=default",
        method="GET",
    )


class TestPrototypePollutionTester:
    """Test prototype pollution tester functionality"""
    
    @pytest.mark.asyncio
    async def test_proto_property_detection(
        self, pollution_tester, mock_request_handler, sample_json_injection_point
    ):
        """Test __proto__ property pollution detection"""
        # Mock baseline response
        baseline_response = Mock(spec=Response)
        baseline_response.text = '{"status": "ok", "user": {"name": "test"}}'
        baseline_response.status_code = 200
        
        # Mock vulnerable response with polluted property
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = '{"status": "ok", "user": {"name": "test"}, "polluted": "yes"}'
        vulnerable_response.status_code = 200
        
        # Set up mock to return different responses
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            vulnerable_response,
        ]
        
        # Test for prototype pollution
        results = await pollution_tester.test_injection_point(
            sample_json_injection_point,
            techniques=[PollutionTechnique.PROTO_PROPERTY],
        )
        
        # Verify results
        assert len(results) > 0
        
        # Find vulnerable result
        vulnerable_results = [r for r in results if r.is_vulnerable]
        assert len(vulnerable_results) > 0
        
        result = vulnerable_results[0]
        assert isinstance(result, PrototypePollutionResult)
        assert result.is_vulnerable is True
        assert result.technique == PollutionTechnique.PROTO_PROPERTY
        assert result.polluted_property == "polluted"
        assert result.confidence > 0.8
    
    @pytest.mark.asyncio
    async def test_constructor_prototype_detection(
        self, pollution_tester, mock_request_handler, sample_json_injection_point
    ):
        """Test constructor.prototype pollution detection"""
        # Mock baseline response
        baseline_response = Mock(spec=Response)
        baseline_response.text = '{"status": "ok"}'
        baseline_response.status_code = 200
        
        # Mock vulnerable response
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = '{"status": "ok", "isAdmin": true}'
        vulnerable_response.status_code = 200
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            vulnerable_response,
        ]
        
        # Test for constructor.prototype pollution
        results = await pollution_tester.test_injection_point(
            sample_json_injection_point,
            techniques=[PollutionTechnique.CONSTRUCTOR_PROTOTYPE],
        )
        
        # Verify results
        vulnerable_results = [r for r in results if r.is_vulnerable]
        assert len(vulnerable_results) > 0
        
        result = vulnerable_results[0]
        assert result.is_vulnerable is True
        assert result.technique == PollutionTechnique.CONSTRUCTOR_PROTOTYPE
        assert result.polluted_property == "isAdmin"
    
    @pytest.mark.asyncio
    async def test_no_vulnerability(
        self, pollution_tester, mock_request_handler, sample_json_injection_point
    ):
        """Test when no prototype pollution vulnerability exists"""
        # Mock safe response (no pollution)
        safe_response = Mock(spec=Response)
        safe_response.text = '{"status": "ok", "user": {"name": "test"}}'
        safe_response.status_code = 200
        
        # All responses are safe
        mock_request_handler.send_request.return_value = safe_response
        
        # Test for prototype pollution
        results = await pollution_tester.test_injection_point(
            sample_json_injection_point,
        )
        
        # Verify no vulnerabilities found
        vulnerable_results = [r for r in results if r.is_vulnerable]
        assert len(vulnerable_results) == 0
    
    @pytest.mark.asyncio
    async def test_query_parameter_injection(
        self, pollution_tester, mock_request_handler, sample_query_injection_point
    ):
        """Test prototype pollution via query parameters"""
        # Mock baseline response
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Config: default"
        baseline_response.status_code = 200
        
        # Mock safe response (no pollution detected)
        safe_response = Mock(spec=Response)
        safe_response.text = "Config: default"
        safe_response.status_code = 200
        
        # Return baseline first, then safe responses for all payloads
        mock_request_handler.send_request.return_value = safe_response
        
        # Test query parameter injection
        results = await pollution_tester.test_injection_point(
            sample_query_injection_point,
        )
        
        # Verify results were generated
        assert len(results) > 0
        
        # Check that injection point location is correct
        for result in results:
            assert result.injection_point.location == InjectionLocation.QUERY
    
    @pytest.mark.asyncio
    async def test_escalation_guidance_generation(
        self, pollution_tester, sample_json_injection_point
    ):
        """Test escalation guidance generation"""
        # Generate escalation guidance
        guidance = pollution_tester._generate_escalation_guidance(
            sample_json_injection_point,
            "isAdmin",
        )
        
        # Verify guidance is generated
        assert len(guidance) > 0
        assert isinstance(guidance, list)
        
        # Check for key sections
        guidance_text = "\n".join(guidance)
        assert "RCE" in guidance_text or "Remote Code Execution" in guidance_text
        assert "Authentication Bypass" in guidance_text
        assert "isAdmin" in guidance_text
    
    def test_merge_payloads(self, pollution_tester):
        """Test payload merging"""
        base = {"user": {"name": "test", "email": "test@example.com"}}
        pollution = {"__proto__": {"isAdmin": True}}
        
        merged = pollution_tester._merge_payloads(base, pollution)
        
        assert "user" in merged
        assert "__proto__" in merged
        assert merged["user"]["name"] == "test"
        assert merged["__proto__"]["isAdmin"] is True
    
    def test_flatten_payload(self, pollution_tester):
        """Test payload flattening for query/POST parameters"""
        nested = {
            "__proto__": {
                "isAdmin": True,
                "role": "admin",
            }
        }
        
        flattened = pollution_tester._flatten_payload(nested)
        
        assert "__proto__.isAdmin" in flattened
        assert "__proto__.role" in flattened
        assert flattened["__proto__.isAdmin"] == "true"
        assert flattened["__proto__.role"] == "admin"
    
    def test_extract_polluted_properties(self, pollution_tester):
        """Test extraction of polluted properties from payload"""
        payload = {
            "__proto__": {
                "polluted": "yes",
                "isAdmin": True,
            }
        }
        
        properties = pollution_tester._extract_polluted_properties(payload)
        
        assert "polluted" in properties
        assert "isAdmin" in properties
        assert properties["polluted"] == "yes"
        assert properties["isAdmin"] == "True"
    
    def test_detect_pollution_json_format(self, pollution_tester):
        """Test pollution detection in JSON format"""
        payload = {"__proto__": {"polluted": "yes"}}
        response_text = '{"status": "ok", "polluted": "yes"}'
        baseline_text = '{"status": "ok"}'
        
        is_polluted, property_name = pollution_tester._detect_pollution(
            payload,
            response_text,
            baseline_text,
        )
        
        assert is_polluted is True
        assert property_name == "polluted"
    
    def test_detect_pollution_javascript_format(self, pollution_tester):
        """Test pollution detection in JavaScript object format"""
        payload = {"__proto__": {"isAdmin": True}}
        response_text = "var user = {name: 'test', isAdmin: true};"
        baseline_text = "var user = {name: 'test'};"
        
        is_polluted, property_name = pollution_tester._detect_pollution(
            payload,
            response_text,
            baseline_text,
        )
        
        assert is_polluted is True
        assert property_name == "isAdmin"
    
    def test_detect_no_pollution(self, pollution_tester):
        """Test when no pollution is detected"""
        payload = {"__proto__": {"polluted": "yes"}}
        response_text = '{"status": "ok", "user": {"name": "test"}}'
        baseline_text = '{"status": "ok", "user": {"name": "test"}}'
        
        is_polluted, property_name = pollution_tester._detect_pollution(
            payload,
            response_text,
            baseline_text,
        )
        
        assert is_polluted is False
        assert property_name is None


class TestInjectionPointCreation:
    """Test injection point creation helpers"""
    
    def test_create_query_injection_points(self):
        """Test creating injection points from query parameters"""
        injection_points = create_injection_points_from_request(
            url="https://example.com/api/test",
            method="GET",
            query_params={"id": "123", "action": "update"},
        )
        
        assert len(injection_points) == 2
        assert all(ip.location == InjectionLocation.QUERY for ip in injection_points)
        
        # Check parameters
        params = [ip.parameter for ip in injection_points]
        assert "id" in params
        assert "action" in params
    
    def test_create_post_injection_points(self):
        """Test creating injection points from POST data"""
        injection_points = create_injection_points_from_request(
            url="https://example.com/api/user",
            method="POST",
            post_data={"name": "test", "email": "test@example.com"},
        )
        
        assert len(injection_points) == 2
        assert all(ip.location == InjectionLocation.POST for ip in injection_points)
    
    def test_create_json_injection_point(self):
        """Test creating injection point from JSON body"""
        injection_points = create_injection_points_from_request(
            url="https://example.com/api/config",
            method="POST",
            json_data={"settings": {"theme": "dark"}},
        )
        
        assert len(injection_points) == 1
        assert injection_points[0].location == InjectionLocation.JSON_BODY
        assert injection_points[0].parameter == "json_body"
    
    def test_create_multiple_injection_points(self):
        """Test creating multiple injection points from mixed request"""
        injection_points = create_injection_points_from_request(
            url="https://example.com/api/update",
            method="POST",
            query_params={"id": "123"},
            json_data={"user": {"name": "test"}},
        )
        
        assert len(injection_points) == 2
        
        # Check we have both query and JSON injection points
        locations = [ip.location for ip in injection_points]
        assert InjectionLocation.QUERY in locations
        assert InjectionLocation.JSON_BODY in locations


class TestPollutionPayloads:
    """Test pollution payload structures"""
    
    def test_proto_property_payloads(self, pollution_tester):
        """Test __proto__ property payloads"""
        payloads = pollution_tester.POLLUTION_PAYLOADS[PollutionTechnique.PROTO_PROPERTY]
        
        assert len(payloads) > 0
        
        # Check payload structure
        for payload in payloads:
            assert isinstance(payload, dict)
            # Should contain __proto__ or nested __proto__
            assert "__proto__" in json.dumps(payload)
    
    def test_constructor_prototype_payloads(self, pollution_tester):
        """Test constructor.prototype payloads"""
        payloads = pollution_tester.POLLUTION_PAYLOADS[PollutionTechnique.CONSTRUCTOR_PROTOTYPE]
        
        assert len(payloads) > 0
        
        # Check payload structure
        for payload in payloads:
            assert isinstance(payload, dict)
            assert "constructor" in payload
            assert "prototype" in payload["constructor"]
    
    def test_escalation_paths_exist(self, pollution_tester):
        """Test that escalation paths are defined"""
        assert "rce" in pollution_tester.ESCALATION_PATHS
        assert "auth_bypass" in pollution_tester.ESCALATION_PATHS
        assert "dos" in pollution_tester.ESCALATION_PATHS
        assert "xss" in pollution_tester.ESCALATION_PATHS
        
        # Check each path has guidance
        for path_type, paths in pollution_tester.ESCALATION_PATHS.items():
            assert len(paths) > 0
            assert all(isinstance(p, str) for p in paths)
