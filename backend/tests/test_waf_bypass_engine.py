"""Tests for WAF Bypass Engine"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from app.core.waf_bypass_engine import (
    WAFBypassEngine,
    WAFInfo,
    BypassTechnique,
    BypassResult,
)
from app.core.http_models import Response, Request


@pytest.fixture
def waf_engine():
    """Create WAF bypass engine instance"""
    return WAFBypassEngine()


@pytest.fixture
def mock_request_handler():
    """Create mock request handler"""
    handler = Mock()
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def sample_technique():
    """Create sample bypass technique"""
    return BypassTechnique(
        name="URL Encoding",
        description="Apply URL encoding",
        category="encoding",
        apply_function="apply_url_encoding",
        effectiveness="medium",
    )


class TestWAFDetection:
    """Test WAF detection functionality"""
    
    @pytest.mark.asyncio
    async def test_detect_cloudflare(self, mock_request_handler):
        """Test Cloudflare WAF detection"""
        # Mock responses
        benign_response = Response(
            status_code=200,
            headers={"cf-ray": "12345"},
            body=b"OK",
            text="OK",
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        
        malicious_response = Response(
            status_code=403,
            headers={"cf-ray": "12346"},
            body=b"Attention Required! Cloudflare",
            text="Attention Required! Cloudflare",
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        
        mock_request_handler.send_request.side_effect = [
            benign_response,
            malicious_response,
        ]
        
        # Test detection
        engine = WAFBypassEngine(mock_request_handler)
        waf_info = await engine.detect_waf("https://example.com")
        
        assert waf_info is not None
        assert waf_info.vendor == "Cloudflare"
        assert waf_info.confidence > 0.5
        assert len(waf_info.detected_from) > 0
    
    @pytest.mark.asyncio
    async def test_detect_no_waf(self, mock_request_handler):
        """Test when no WAF is present"""
        # Mock responses - both succeed
        response = Response(
            status_code=200,
            headers={},
            body=b"OK",
            text="OK",
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        
        mock_request_handler.send_request.return_value = response
        
        # Test detection
        engine = WAFBypassEngine(mock_request_handler)
        waf_info = await engine.detect_waf("https://example.com")
        
        assert waf_info is None
    
    @pytest.mark.asyncio
    async def test_detect_generic_waf(self, mock_request_handler):
        """Test generic WAF detection"""
        # Mock responses - use 503 to avoid matching specific WAF signatures
        benign_response = Response(
            status_code=200,
            headers={},
            body=b"OK",
            text="OK",
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        
        malicious_response = Response(
            status_code=503,
            headers={},
            body=b"Service Unavailable",
            text="Service Unavailable",
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        
        mock_request_handler.send_request.side_effect = [
            benign_response,
            malicious_response,
        ]
        
        # Test detection
        engine = WAFBypassEngine(mock_request_handler)
        waf_info = await engine.detect_waf("https://example.com")
        
        assert waf_info is not None
        assert waf_info.vendor == "Generic/Unknown"
        assert waf_info.confidence >= 0.6


class TestBypassTechniques:
    """Test bypass technique functionality"""
    
    def test_get_all_techniques(self, waf_engine):
        """Test getting all bypass techniques"""
        techniques = waf_engine.get_bypass_techniques()
        
        assert len(techniques) > 0
        assert all(isinstance(t, BypassTechnique) for t in techniques)
        
        # Check categories are present
        categories = {t.category for t in techniques}
        assert "encoding" in categories
        assert "obfuscation" in categories
        assert "protocol" in categories
        assert "header" in categories
    
    def test_get_vendor_specific_techniques(self, waf_engine):
        """Test getting vendor-specific techniques"""
        techniques = waf_engine.get_bypass_techniques("Cloudflare")
        
        assert len(techniques) > 0
        # Cloudflare-specific techniques should be prioritized
        # (at the beginning of the list)
    
    def test_apply_url_encoding(self, waf_engine):
        """Test URL encoding bypass"""
        payload = "' OR '1'='1"
        result = waf_engine.apply_url_encoding(payload)
        
        assert result != payload
        assert "'" not in result
        assert "%27" in result
    
    def test_apply_double_url_encoding(self, waf_engine):
        """Test double URL encoding bypass"""
        payload = "' OR '1'='1"
        result = waf_engine.apply_double_url_encoding(payload)
        
        assert result != payload
        assert "%2527" in result  # Double encoded '
    
    def test_apply_case_variation(self, waf_engine):
        """Test case variation bypass"""
        payload = "SELECT * FROM users"
        result = waf_engine.apply_case_variation(payload)
        
        assert result != payload
        # Should have mixed case
        assert result != payload.upper()
        assert result != payload.lower()
    
    def test_apply_comment_injection(self, waf_engine):
        """Test comment injection bypass"""
        payload = "SELECT * FROM users WHERE id=1"
        result = waf_engine.apply_comment_injection(payload)
        
        assert result != payload
        assert "/**/" in result
    
    def test_apply_whitespace_manipulation(self, waf_engine):
        """Test whitespace manipulation bypass"""
        payload = "SELECT * FROM users"
        result = waf_engine.apply_whitespace_manipulation(payload)
        
        assert result != payload
        assert "\t" in result
    
    def test_apply_bypass_with_technique(self, waf_engine, sample_technique):
        """Test applying bypass with technique object"""
        payload = "' OR '1'='1"
        result = waf_engine.apply_bypass(payload, sample_technique)
        
        assert result != payload
        assert "%27" in result


class TestBypassPersistence:
    """Test bypass persistence functionality"""
    
    def test_save_successful_bypass(self, waf_engine, sample_technique):
        """Test saving successful bypass"""
        waf_engine.save_successful_bypass(
            url="https://example.com",
            waf_vendor="Cloudflare",
            technique=sample_technique,
            payload="' OR '1'='1",
            bypassed_payload="%27%20OR%20%271%27%3D%271",
        )
        
        # Check cache
        cached = waf_engine.get_cached_bypasses("Cloudflare")
        assert len(cached) > 0
        assert sample_technique in cached
        
        # Check URL-specific bypass
        bypass_info = waf_engine.get_bypass_for_url("https://example.com")
        assert bypass_info is not None
        assert bypass_info["waf_vendor"] == "Cloudflare"
        assert bypass_info["technique"] == sample_technique
    
    def test_get_cached_bypasses_empty(self, waf_engine):
        """Test getting cached bypasses when none exist"""
        cached = waf_engine.get_cached_bypasses("NonExistent")
        assert cached == []
    
    def test_clear_bypass_cache_specific(self, waf_engine, sample_technique):
        """Test clearing specific vendor cache"""
        # Save bypasses for two vendors
        waf_engine.save_successful_bypass(
            "https://example.com", "Cloudflare", sample_technique, "test", "test"
        )
        waf_engine.save_successful_bypass(
            "https://example2.com", "AWS WAF", sample_technique, "test", "test"
        )
        
        # Clear Cloudflare only
        waf_engine.clear_bypass_cache("Cloudflare")
        
        assert len(waf_engine.get_cached_bypasses("Cloudflare")) == 0
        assert len(waf_engine.get_cached_bypasses("AWS WAF")) > 0
    
    def test_clear_bypass_cache_all(self, waf_engine, sample_technique):
        """Test clearing all cache"""
        # Save bypasses
        waf_engine.save_successful_bypass(
            "https://example.com", "Cloudflare", sample_technique, "test", "test"
        )
        
        # Clear all
        waf_engine.clear_bypass_cache()
        
        assert len(waf_engine.get_cached_bypasses("Cloudflare")) == 0
        assert waf_engine.get_bypass_for_url("https://example.com") is None
    
    def test_export_import_bypass_patterns(self, waf_engine, sample_technique):
        """Test exporting and importing bypass patterns"""
        # Save some bypasses
        waf_engine.save_successful_bypass(
            "https://example.com", "Cloudflare", sample_technique, "test", "test"
        )
        
        # Export
        patterns = waf_engine.export_bypass_patterns()
        
        assert "bypass_cache" in patterns
        assert "successful_bypasses" in patterns
        assert "Cloudflare" in patterns["bypass_cache"]
        
        # Import to new engine
        new_engine = WAFBypassEngine()
        new_engine.import_bypass_patterns(patterns)
        
        # Verify import
        cached = new_engine.get_cached_bypasses("Cloudflare")
        assert len(cached) > 0
        assert cached[0].name == sample_technique.name


class TestBypassHeaders:
    """Test bypass header functionality"""
    
    def test_get_generic_bypass_headers(self, waf_engine):
        """Test getting generic bypass headers"""
        headers = waf_engine.get_bypass_headers()
        
        assert "X-Forwarded-For" in headers
        assert "X-Real-IP" in headers
        assert headers["X-Forwarded-For"] == "127.0.0.1"
    
    def test_get_cloudflare_bypass_headers(self, waf_engine):
        """Test getting Cloudflare-specific headers"""
        headers = waf_engine.get_bypass_headers("Cloudflare")
        
        assert "CF-Connecting-IP" in headers
        assert "X-Forwarded-For" in headers
        assert "X-Original-URL" in headers
    
    def test_get_unknown_vendor_headers(self, waf_engine):
        """Test getting headers for unknown vendor"""
        headers = waf_engine.get_bypass_headers("UnknownVendor")
        
        # Should return generic headers
        assert "X-Forwarded-For" in headers
        assert "X-Real-IP" in headers


class TestMultipleBypasses:
    """Test applying multiple bypass techniques"""
    
    def test_apply_multiple_bypasses(self, waf_engine):
        """Test applying multiple techniques in sequence"""
        payload = "SELECT * FROM users"
        
        techniques = [
            BypassTechnique(
                "Case Variation", "", "obfuscation", "apply_case_variation"
            ),
            BypassTechnique(
                "Comment Injection", "", "obfuscation", "apply_comment_injection"
            ),
        ]
        
        result = waf_engine.apply_multiple_bypasses(payload, techniques)
        
        assert result != payload
        # Should have both case variation and comments
        assert "/**/" in result
    
    def test_apply_multiple_bypasses_empty(self, waf_engine):
        """Test applying empty technique list"""
        payload = "SELECT * FROM users"
        result = waf_engine.apply_multiple_bypasses(payload, [])
        
        assert result == payload


class TestBypassTesting:
    """Test bypass testing functionality"""
    
    @pytest.mark.asyncio
    async def test_test_bypass_success(self, mock_request_handler, sample_technique):
        """Test successful bypass"""
        # Original blocked, bypassed not blocked
        original_response = Response(
            status_code=403,
            headers={},
            body=b"Blocked",
            text="Blocked",
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        
        bypassed_response = Response(
            status_code=200,
            headers={},
            body=b"OK",
            text="OK",
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        
        mock_request_handler.send_request.side_effect = [
            original_response,
            bypassed_response,
        ]
        
        engine = WAFBypassEngine(mock_request_handler)
        result = await engine.test_bypass(
            "https://example.com", "' OR '1'='1", sample_technique
        )
        
        assert result.success is True
        assert result.original_blocked is True
        assert result.bypassed_blocked is False
    
    @pytest.mark.asyncio
    async def test_test_bypass_failure(self, mock_request_handler, sample_technique):
        """Test failed bypass"""
        # Both blocked
        blocked_response = Response(
            status_code=403,
            headers={},
            body=b"Blocked",
            text="Blocked",
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        
        mock_request_handler.send_request.return_value = blocked_response
        
        engine = WAFBypassEngine(mock_request_handler)
        result = await engine.test_bypass(
            "https://example.com", "' OR '1'='1", sample_technique
        )
        
        assert result.success is False
        assert result.original_blocked is True
        assert result.bypassed_blocked is True
    
    @pytest.mark.asyncio
    async def test_find_working_bypass(self, mock_request_handler):
        """Test finding a working bypass"""
        # First technique fails, second succeeds
        responses = [
            # First technique - both blocked
            Response(403, {}, b"", "", 0.1, Mock(), []),
            Response(403, {}, b"", "", 0.1, Mock(), []),
            # Second technique - original blocked, bypass works
            Response(403, {}, b"", "", 0.1, Mock(), []),
            Response(200, {}, b"OK", "OK", 0.1, Mock(), []),
        ]
        
        mock_request_handler.send_request.side_effect = responses
        
        engine = WAFBypassEngine(mock_request_handler)
        result = await engine.find_working_bypass(
            url="https://example.com",
            payload="' OR '1'='1",
            max_attempts=3,
            use_cache=False,
        )
        
        assert result is not None
        assert result.success is True
    
    @pytest.mark.asyncio
    async def test_find_working_bypass_with_cache(self, mock_request_handler, sample_technique):
        """Test finding bypass using cache"""
        # Setup cache
        engine = WAFBypassEngine(mock_request_handler)
        engine.save_successful_bypass(
            "https://example.com", "Cloudflare", sample_technique, "test", "test"
        )
        
        # Mock successful response
        responses = [
            Response(403, {}, b"", "", 0.1, Mock(), []),
            Response(200, {}, b"OK", "OK", 0.1, Mock(), []),
        ]
        mock_request_handler.send_request.side_effect = responses
        
        result = await engine.find_working_bypass(
            url="https://example.com",
            payload="' OR '1'='1",
            waf_vendor="Cloudflare",
            use_cache=True,
        )
        
        assert result is not None
        assert result.success is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
