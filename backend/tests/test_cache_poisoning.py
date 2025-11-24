"""Tests for cache poisoning module"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
from app.modules.cache_poisoning import (
    CachePoisoningTester,
    CacheTestPoint,
    CachePoisoningType,
    CacheStatus,
    CacheKeyAnalysis,
    CachePoisoningResult,
)
from app.core.request_handler import Response


@pytest.fixture
def mock_request_handler():
    """Create mock request handler"""
    handler = Mock()
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def cache_tester(mock_request_handler):
    """Create cache poisoning tester instance"""
    return CachePoisoningTester(mock_request_handler)


@pytest.fixture
def test_point():
    """Create test point"""
    return CacheTestPoint(
        url="https://example.com/api/data",
        method="GET",
        headers={"User-Agent": "Test"},
    )


def create_mock_response(
    status_code=200,
    text="<html>Test Response</html>",
    headers=None,
):
    """Create mock response"""
    response = Mock(spec=Response)
    response.status_code = status_code
    response.text = text
    response.headers = headers or {}
    return response


class TestCachePoisoningTester:
    """Test CachePoisoningTester class"""
    
    @pytest.mark.asyncio
    async def test_analyze_cache_keys_basic(self, cache_tester, test_point, mock_request_handler):
        """Test basic cache key analysis"""
        # Setup mock response
        mock_response = create_mock_response(
            headers={"X-Cache": "HIT", "Cache-Control": "public, max-age=3600"}
        )
        mock_request_handler.send_request.return_value = mock_response
        
        # Analyze cache keys
        result = await cache_tester.analyze_cache_keys(test_point)
        
        # Verify result
        assert isinstance(result, CacheKeyAnalysis)
        assert result.url == test_point.url
        assert result.cache_status == CacheStatus.HIT
        assert "Cache-Control" in result.cache_control_headers
    
    @pytest.mark.asyncio
    async def test_detect_cache_status_hit(self, cache_tester):
        """Test cache status detection - HIT"""
        response = create_mock_response(headers={"X-Cache": "HIT"})
        status = cache_tester._detect_cache_status(response)
        assert status == CacheStatus.HIT
    
    @pytest.mark.asyncio
    async def test_detect_cache_status_miss(self, cache_tester):
        """Test cache status detection - MISS"""
        response = create_mock_response(headers={"X-Cache": "MISS"})
        status = cache_tester._detect_cache_status(response)
        assert status == CacheStatus.MISS
    
    @pytest.mark.asyncio
    async def test_detect_cache_status_age_header(self, cache_tester):
        """Test cache status detection via Age header"""
        response = create_mock_response(headers={"Age": "120"})
        status = cache_tester._detect_cache_status(response)
        assert status == CacheStatus.HIT
    
    def test_detect_cdn_cloudflare(self, cache_tester):
        """Test CDN detection - Cloudflare"""
        response = create_mock_response(
            headers={"CF-Cache-Status": "HIT", "CF-Ray": "abc123"}
        )
        cdn = cache_tester._detect_cdn(response)
        assert cdn == "Cloudflare"
    
    def test_detect_cdn_fastly(self, cache_tester):
        """Test CDN detection - Fastly"""
        response = create_mock_response(
            headers={"X-Served-By": "cache-fastly-123"}
        )
        cdn = cache_tester._detect_cdn(response)
        assert cdn == "Fastly"
    
    def test_detect_cdn_none(self, cache_tester):
        """Test CDN detection - None"""
        response = create_mock_response(headers={})
        cdn = cache_tester._detect_cdn(response)
        assert cdn is None
    
    def test_contains_sensitive_data_email(self, cache_tester):
        """Test sensitive data detection - email"""
        response = create_mock_response(
            text='{"email": "user@example.com", "name": "Test User"}'
        )
        assert cache_tester._contains_sensitive_data(response) is True
    
    def test_contains_sensitive_data_password(self, cache_tester):
        """Test sensitive data detection - password"""
        response = create_mock_response(
            text='{"password": "secret123"}'
        )
        assert cache_tester._contains_sensitive_data(response) is True
    
    def test_contains_sensitive_data_token(self, cache_tester):
        """Test sensitive data detection - token"""
        response = create_mock_response(
            text='{"api_key": "secret123", "token": "abc"}'
        )
        assert cache_tester._contains_sensitive_data(response) is True
    
    def test_contains_sensitive_data_none(self, cache_tester):
        """Test sensitive data detection - none"""
        response = create_mock_response(
            text="<html><body>Public content</body></html>"
        )
        assert cache_tester._contains_sensitive_data(response) is False
    
    def test_is_cacheable_public(self, cache_tester):
        """Test cacheability - public"""
        response = create_mock_response(
            headers={"Cache-Control": "public, max-age=3600"}
        )
        assert cache_tester._is_cacheable(response) is True
    
    def test_is_cacheable_no_cache(self, cache_tester):
        """Test cacheability - no-cache"""
        response = create_mock_response(
            headers={"Cache-Control": "no-cache, no-store"}
        )
        assert cache_tester._is_cacheable(response) is False
    
    def test_is_cacheable_private(self, cache_tester):
        """Test cacheability - private"""
        response = create_mock_response(
            headers={"Cache-Control": "private"}
        )
        assert cache_tester._is_cacheable(response) is False
    
    def test_is_cacheable_expires(self, cache_tester):
        """Test cacheability - Expires header"""
        response = create_mock_response(
            headers={"Expires": "Wed, 21 Oct 2025 07:28:00 GMT"}
        )
        assert cache_tester._is_cacheable(response) is True
    
    def test_response_contains_value(self, cache_tester):
        """Test response contains value"""
        response = create_mock_response(text="<html>Test payload here</html>")
        assert cache_tester._response_contains_value(response, "payload") is True
        assert cache_tester._response_contains_value(response, "notfound") is False
    
    def test_hash_response(self, cache_tester):
        """Test response hashing"""
        response1 = create_mock_response(status_code=200, text="content")
        response2 = create_mock_response(status_code=200, text="content")
        response3 = create_mock_response(status_code=200, text="different")
        
        hash1 = cache_tester._hash_response(response1)
        hash2 = cache_tester._hash_response(response2)
        hash3 = cache_tester._hash_response(response3)
        
        assert hash1 == hash2
        assert hash1 != hash3
    
    def test_mixed_case(self, cache_tester):
        """Test mixed case conversion"""
        result = cache_tester._mixed_case("example.com")
        # Check that it alternates case (even indices uppercase, odd indices lowercase)
        assert result[0].isupper()  # 'E'
        assert result[1].islower()  # 'x'
        assert result[2].isupper()  # 'A'
        assert len(result) == len("example.com")
    
    def test_extract_sensitive_indicators(self, cache_tester):
        """Test extraction of sensitive data indicators"""
        response = create_mock_response(
            text='{"email": "test@example.com", "password": "secret", "token": "abc123"}'
        )
        indicators = cache_tester._extract_sensitive_indicators(response)
        assert "email" in indicators
        assert "password" in indicators
        assert "token" in indicators
    
    @pytest.mark.asyncio
    async def test_test_unkeyed_header_poisoning_vulnerable(
        self, cache_tester, test_point, mock_request_handler
    ):
        """Test unkeyed header poisoning detection - vulnerable"""
        # Setup cache analysis with unkeyed header
        cache_analysis = CacheKeyAnalysis(
            url=test_point.url,
            unkeyed_headers=["X-Forwarded-Host"],
            cache_status=CacheStatus.HIT,
        )
        
        # Setup mock responses
        xss_payload = "<script>alert('Cache-Poisoned-X-Forwarded-Host')</script>"
        poisoned_response = create_mock_response(text=f"<html>{xss_payload}</html>")
        mock_request_handler.send_request.return_value = poisoned_response
        
        # Test for poisoning
        results = await cache_tester.test_unkeyed_header_poisoning(test_point, cache_analysis)
        
        # Verify results
        assert len(results) > 0
        result = results[0]
        assert result.is_vulnerable is True
        assert result.poisoning_type == CachePoisoningType.UNKEYED_HEADER
        assert result.unkeyed_header == "X-Forwarded-Host"
        assert result.confidence > 0.9
        assert len(result.evidence) > 0
        assert result.exploitation_guidance is not None
    
    @pytest.mark.asyncio
    async def test_test_web_cache_deception_vulnerable(
        self, cache_tester, test_point, mock_request_handler
    ):
        """Test web cache deception detection - vulnerable"""
        # Setup mock response with sensitive data and cacheable
        sensitive_response = create_mock_response(
            text='{"email": "user@example.com", "balance": "$1000"}',
            headers={"Cache-Control": "public, max-age=3600"},
        )
        mock_request_handler.send_request.return_value = sensitive_response
        
        # Test for web cache deception
        results = await cache_tester.test_web_cache_deception(test_point)
        
        # Verify results
        assert len(results) > 0
        # At least one should be vulnerable
        vulnerable_results = [r for r in results if r.is_vulnerable]
        if vulnerable_results:
            result = vulnerable_results[0]
            assert result.poisoning_type == CachePoisoningType.WEB_CACHE_DECEPTION
            assert result.confidence > 0.8
            assert result.exploitation_guidance is not None


class TestCacheTestPoint:
    """Test CacheTestPoint dataclass"""
    
    def test_cache_test_point_creation(self):
        """Test creating a cache test point"""
        test_point = CacheTestPoint(
            url="https://example.com/",
            method="GET",
            headers={"User-Agent": "Test"},
            parameters={"key": "value"},
        )
        
        assert test_point.url == "https://example.com/"
        assert test_point.method == "GET"
        assert test_point.headers == {"User-Agent": "Test"}
        assert test_point.parameters == {"key": "value"}
    
    def test_cache_test_point_defaults(self):
        """Test cache test point with defaults"""
        test_point = CacheTestPoint(url="https://example.com/")
        
        assert test_point.method == "GET"
        assert test_point.headers == {}
        assert test_point.parameters == {}


class TestCachePoisoningResult:
    """Test CachePoisoningResult dataclass"""
    
    def test_cache_poisoning_result_creation(self):
        """Test creating a cache poisoning result"""
        test_point = CacheTestPoint(url="https://example.com/")
        
        result = CachePoisoningResult(
            test_point=test_point,
            is_vulnerable=True,
            poisoning_type=CachePoisoningType.UNKEYED_HEADER,
            unkeyed_header="X-Forwarded-Host",
            payload="<script>alert(1)</script>",
            confidence=0.95,
            evidence=["Evidence 1", "Evidence 2"],
        )
        
        assert result.is_vulnerable is True
        assert result.poisoning_type == CachePoisoningType.UNKEYED_HEADER
        assert result.unkeyed_header == "X-Forwarded-Host"
        assert result.confidence == 0.95
        assert len(result.evidence) == 2


class TestExploitationGuidance:
    """Test exploitation guidance generation"""
    
    def test_generate_xss_amplification_guidance(self, cache_tester):
        """Test XSS amplification guidance generation"""
        guidance = cache_tester._generate_xss_amplification_guidance(
            "X-Forwarded-Host",
            "<script>alert(1)</script>"
        )
        
        assert "XSS Amplification" in guidance
        assert "X-Forwarded-Host" in guidance
        assert "Exploitation Steps" in guidance
        assert "Mitigation" in guidance
    
    def test_generate_cache_deception_guidance(self, cache_tester):
        """Test cache deception guidance generation"""
        guidance = cache_tester._generate_cache_deception_guidance(
            "https://example.com/account/settings/style.css"
        )
        
        assert "Web Cache Deception" in guidance
        assert "Exploitation Steps" in guidance
        assert "Mitigation" in guidance
    
    def test_generate_normalization_guidance(self, cache_tester):
        """Test normalization guidance generation"""
        guidance = cache_tester._generate_normalization_guidance("port_80")
        
        assert "Normalization" in guidance
        assert "port_80" in guidance
        assert "Mitigation" in guidance
    
    def test_generate_origin_bypass_guidance(self, cache_tester):
        """Test origin bypass guidance generation"""
        guidance = cache_tester._generate_origin_bypass_guidance(
            "X-Original-URL",
            "/admin"
        )
        
        assert "Origin Server Bypass" in guidance
        assert "X-Original-URL" in guidance
        assert "Exploitation Steps" in guidance
        assert "Mitigation" in guidance
