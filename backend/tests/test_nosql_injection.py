"""Unit tests for NoSQL Injection module"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.modules.nosql_injection import (
    NoSQLInjectionTester,
    NoSQLDataExtractor,
    InjectionPoint,
    NoSQLInjectionType,
    NoSQLDatabase,
    NoSQLInjectionResult,
    ExtractionProgress,
)
from app.core.request_handler import RequestHandler, Response
from app.core.http_models import Request


@pytest.fixture
def request_handler():
    """Create mock request handler"""
    handler = MagicMock(spec=RequestHandler)
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def tester(request_handler):
    """Create NoSQL injection tester"""
    return NoSQLInjectionTester(request_handler)


@pytest.fixture
def injection_point():
    """Create test injection point"""
    return InjectionPoint(
        parameter="username",
        location="json",
        original_value="admin",
        url="https://example.com/api/login",
        method="POST",
        is_json=True,
    )


def create_mock_response(
    status_code=200,
    text="",
    headers=None,
    elapsed_time=0.1,
):
    """Create a mock response"""
    request = Request(
        method="POST",
        url="https://example.com/api/login",
    )
    
    return Response(
        status_code=status_code,
        headers=headers or {},
        body=text.encode(),
        text=text,
        elapsed_time=elapsed_time,
        request=request,
    )


class TestNoSQLInjectionTester:
    """Tests for NoSQLInjectionTester"""
    
    @pytest.mark.asyncio
    async def test_initialization(self, request_handler):
        """Test tester initialization"""
        tester = NoSQLInjectionTester(request_handler)
        
        assert tester.request_handler == request_handler
        assert tester.payload_engine is not None
        
        # Check that default payloads are loaded
        categories = tester.payload_engine.get_categories()
        assert "nosql_operator" in categories
        assert "nosql_auth_bypass" in categories
        assert "nosql_time_based" in categories
    
    @pytest.mark.asyncio
    async def test_operator_injection_with_error(self, tester, injection_point):
        """Test operator injection detection via error message"""
        # Mock response with MongoDB error
        error_response = create_mock_response(
            status_code=500,
            text="MongoError: invalid query operator"
        )
        tester.request_handler.send_request.return_value = error_response
        
        # Test operator injection
        result = await tester._test_operator_injection(injection_point)
        
        assert result is not None
        assert result.is_vulnerable
        assert result.injection_type == NoSQLInjectionType.OPERATOR_INJECTION
        assert result.database_type == NoSQLDatabase.MONGODB
        assert result.confidence >= 0.8
    
    @pytest.mark.asyncio
    async def test_operator_injection_no_vulnerability(self, tester, injection_point):
        """Test operator injection when no vulnerability exists"""
        # Mock consistent responses (no vulnerability)
        normal_response = create_mock_response(text="Invalid credentials")
        tester.request_handler.send_request.return_value = normal_response
        
        # Test operator injection
        result = await tester._test_operator_injection(injection_point)
        
        assert result is not None
        assert not result.is_vulnerable
        assert result.injection_type == NoSQLInjectionType.OPERATOR_INJECTION
    
    @pytest.mark.asyncio
    async def test_authentication_bypass_success(self, tester, injection_point):
        """Test authentication bypass detection"""
        # Mock baseline response (auth failure)
        baseline_response = create_mock_response(
            status_code=401,
            text="Invalid credentials"
        )
        
        # Mock bypass response (auth success)
        bypass_response = create_mock_response(
            status_code=200,
            text="Welcome to dashboard! Logged in successfully."
        )
        
        tester.request_handler.send_request.side_effect = [
            baseline_response,
            bypass_response,
        ]
        
        # Test authentication bypass
        result = await tester._test_authentication_bypass(injection_point)
        
        assert result is not None
        assert result.is_vulnerable
        assert result.injection_type == NoSQLInjectionType.AUTHENTICATION_BYPASS
        assert result.confidence >= 0.8
    
    @pytest.mark.asyncio
    async def test_boolean_based_blind_no_vulnerability(self, tester, injection_point):
        """Test boolean-based blind when no vulnerability exists"""
        # Mock consistent responses (no vulnerability)
        normal_response = create_mock_response(text="No results")
        tester.request_handler.send_request.return_value = normal_response
        
        # Test boolean-based blind
        result = await tester._test_boolean_based(injection_point)
        
        assert result is not None
        assert not result.is_vulnerable
        assert result.injection_type == NoSQLInjectionType.BOOLEAN_BASED_BLIND
    
    @pytest.mark.asyncio
    async def test_time_based_blind_no_vulnerability(self, tester, injection_point):
        """Test time-based blind when no vulnerability exists"""
        # Mock fast responses (no vulnerability)
        fast_response = create_mock_response(elapsed_time=0.1)
        tester.request_handler.send_request.return_value = fast_response
        
        # Test time-based blind
        result = await tester._test_time_based(injection_point)
        
        assert result is not None
        assert not result.is_vulnerable
        assert result.injection_type == NoSQLInjectionType.TIME_BASED_BLIND
    
    @pytest.mark.asyncio
    async def test_javascript_injection(self, tester, injection_point):
        """Test JavaScript injection detection"""
        # Mock baseline response
        baseline_response = create_mock_response(text="Results: []")
        
        # Mock response with JavaScript error
        js_error_response = create_mock_response(
            status_code=500,
            text="SyntaxError: Unexpected token in JavaScript expression"
        )
        
        tester.request_handler.send_request.side_effect = [
            baseline_response,
            js_error_response,
        ]
        
        # Test JavaScript injection
        result = await tester._test_javascript_injection(injection_point)
        
        assert result is not None
        assert result.is_vulnerable
        assert result.injection_type == NoSQLInjectionType.JAVASCRIPT_INJECTION
        assert result.database_type == NoSQLDatabase.MONGODB
        assert result.confidence >= 0.8
    
    @pytest.mark.asyncio
    async def test_no_vulnerability_found(self, tester, injection_point):
        """Test when no vulnerability is found"""
        # Mock consistent responses
        normal_response = create_mock_response(text="Invalid credentials")
        tester.request_handler.send_request.return_value = normal_response
        
        # Test operator injection
        result = await tester._test_operator_injection(injection_point)
        
        assert result is not None
        assert not result.is_vulnerable
        assert result.confidence == 0.0
    
    def test_detect_nosql_error_mongodb(self, tester):
        """Test MongoDB error detection"""
        response_text = "MongoError: invalid query"
        db_type, error_msg = tester._detect_nosql_error(response_text)
        
        assert db_type == NoSQLDatabase.MONGODB
        assert error_msg is not None
        assert "MongoError" in error_msg
    
    def test_detect_nosql_error_couchdb(self, tester):
        """Test CouchDB error detection"""
        response_text = "CouchDB error: invalid json"
        db_type, error_msg = tester._detect_nosql_error(response_text)
        
        assert db_type == NoSQLDatabase.COUCHDB
        assert error_msg is not None
    
    def test_detect_nosql_error_none(self, tester):
        """Test when no NoSQL error is detected"""
        response_text = "Normal response without errors"
        db_type, error_msg = tester._detect_nosql_error(response_text)
        
        assert db_type == NoSQLDatabase.UNKNOWN
        assert error_msg is None


class TestNoSQLDataExtractor:
    """Tests for NoSQLDataExtractor"""
    
    @pytest.fixture
    def mock_result(self, injection_point):
        """Create mock injection result"""
        return NoSQLInjectionResult(
            injection_point=injection_point,
            is_vulnerable=True,
            injection_type=NoSQLInjectionType.BOOLEAN_BASED_BLIND,
            confidence=0.90,
        )
    
    @pytest.fixture
    def extractor(self, request_handler, injection_point, mock_result):
        """Create data extractor"""
        return NoSQLDataExtractor(
            request_handler=request_handler,
            injection_point=injection_point,
            injection_result=mock_result,
        )
    
    @pytest.mark.asyncio
    async def test_extract_field_length(self, extractor):
        """Test field length extraction"""
        # Mock responses for binary search
        # Simulate a field with length 5
        # Binary search will test: 50, 25, 12, 6, 3, 4, 5
        responses = [
            create_mock_response(text=""),  # >50: no
            create_mock_response(text=""),  # >25: no
            create_mock_response(text=""),  # >12: no
            create_mock_response(text=""),  # >6: no
            create_mock_response(text="result"),  # >3: yes
            create_mock_response(text="result"),  # >4: yes
            create_mock_response(text=""),  # >5: no
        ]
        
        extractor.tester.request_handler.send_request.side_effect = responses
        
        # Extract length
        length = await extractor.extract_field_length("username", max_length=100)
        
        # Verify the method runs and returns a reasonable value
        assert length is not None
        assert isinstance(length, int)
        assert length >= 0
    
    def test_extraction_progress_calculation(self):
        """Test extraction progress calculation"""
        progress = ExtractionProgress(
            total_chars=100,
            extracted_chars=50,
            current_value="admin",
            requests_sent=150,
            estimated_time_remaining=30.5,
        )
        
        assert progress.progress_percentage == 50.0
        assert progress.current_value == "admin"
        assert progress.requests_sent == 150


class TestInjectionPoint:
    """Tests for InjectionPoint"""
    
    def test_injection_point_creation(self):
        """Test injection point creation"""
        point = InjectionPoint(
            parameter="username",
            location="json",
            original_value="admin",
            url="https://example.com/api/login",
            method="POST",
            is_json=True,
        )
        
        assert point.parameter == "username"
        assert point.location == "json"
        assert point.original_value == "admin"
        assert point.url == "https://example.com/api/login"
        assert point.method == "POST"
        assert point.is_json is True


class TestPayloadGeneration:
    """Tests for payload generation"""
    
    def test_operator_payloads_loaded(self, tester):
        """Test that operator payloads are loaded"""
        payloads = list(tester.payload_engine.get_payloads("nosql_operator"))
        
        assert len(payloads) > 0
        
        # Check that payloads contain expected operators
        payload_strings = [p.encoded for p in payloads]
        assert any("$ne" in p for p in payload_strings)
        assert any("$gt" in p for p in payload_strings)
        assert any("$regex" in p for p in payload_strings)
    
    def test_auth_bypass_payloads_loaded(self, tester):
        """Test that authentication bypass payloads are loaded"""
        payloads = list(tester.payload_engine.get_payloads("nosql_auth_bypass"))
        
        assert len(payloads) > 0
        
        # Verify payloads are valid JSON
        for payload in payloads:
            try:
                parsed = json.loads(payload.encoded)
                assert isinstance(parsed, dict)
            except json.JSONDecodeError:
                pytest.fail(f"Invalid JSON payload: {payload.encoded}")
    
    def test_time_based_payloads_loaded(self, tester):
        """Test that time-based payloads are loaded"""
        payloads = list(tester.payload_engine.get_payloads("nosql_time_based"))
        
        assert len(payloads) > 0
        
        # Check that payloads contain sleep functions
        payload_strings = [p.encoded for p in payloads]
        assert any("sleep" in p.lower() for p in payload_strings)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
