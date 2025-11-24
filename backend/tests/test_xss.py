"""Tests for XSS module"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from app.modules.xss import (
    XSSTester,
    XSSPoCGenerator,
    InjectionPoint,
    XSSResult,
    XSSType,
    XSSTechnique,
)
from app.core.request_handler import Response


@pytest.fixture
def mock_request_handler():
    """Create mock request handler"""
    handler = Mock()
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def xss_tester(mock_request_handler):
    """Create XSS tester instance"""
    return XSSTester(mock_request_handler)


@pytest.fixture
def sample_injection_point():
    """Create sample injection point"""
    return InjectionPoint(
        parameter="search",
        location="query",
        original_value="test",
        url="https://example.com/search?q=test",
        method="GET"
    )


class TestXSSTester:
    """Test XSS tester functionality"""
    
    @pytest.mark.asyncio
    async def test_basic_xss_detection(self, xss_tester, mock_request_handler, sample_injection_point):
        """Test basic XSS detection"""
        # Mock baseline response
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Search results for: test"
        
        # Mock vulnerable response with reflected payload
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = "Search results for: <script>alert(1)</script>"
        
        # Set up mock to return different responses
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            vulnerable_response
        ]
        
        # Test for XSS
        results = await xss_tester.test_injection_point(
            sample_injection_point,
            techniques=[XSSTechnique.BASIC]
        )
        
        # Verify results
        assert len(results) > 0
        result = results[0]
        assert isinstance(result, XSSResult)
        assert result.injection_point == sample_injection_point
    
    @pytest.mark.asyncio
    async def test_encoded_xss_detection(self, xss_tester, mock_request_handler, sample_injection_point):
        """Test encoded XSS detection"""
        # Mock baseline response
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Search results"
        
        # Mock vulnerable response with encoded payload
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = "Results: &#60;script&#62;alert(1)&#60;/script&#62;"
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            vulnerable_response
        ]
        
        # Test for encoded XSS
        results = await xss_tester.test_injection_point(
            sample_injection_point,
            techniques=[XSSTechnique.ENCODED]
        )
        
        assert len(results) > 0
    
    @pytest.mark.asyncio
    async def test_filter_bypass_detection(self, xss_tester, mock_request_handler, sample_injection_point):
        """Test filter bypass XSS detection"""
        # Mock responses
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Normal content"
        
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = "Content: <svg/onload=alert(1)>"
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            vulnerable_response
        ]
        
        # Test filter bypass
        results = await xss_tester.test_injection_point(
            sample_injection_point,
            techniques=[XSSTechnique.FILTER_BYPASS]
        )
        
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_event_handler_detection(self, xss_tester, mock_request_handler, sample_injection_point):
        """Test event handler XSS detection"""
        # Mock responses
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Page content"
        
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = "Content: <marquee onstart=alert(1)>"
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            vulnerable_response
        ]
        
        # Test event handlers
        results = await xss_tester.test_injection_point(
            sample_injection_point,
            techniques=[XSSTechnique.EVENT_HANDLER]
        )
        
        assert len(results) > 0
    
    @pytest.mark.asyncio
    async def test_no_vulnerability(self, xss_tester, mock_request_handler, sample_injection_point):
        """Test when no XSS vulnerability exists"""
        # Mock safe response (payload is escaped)
        safe_response = Mock(spec=Response)
        safe_response.text = "Search results for: &lt;script&gt;alert(1)&lt;/script&gt;"
        
        mock_request_handler.send_request.return_value = safe_response
        
        # Test for XSS
        results = await xss_tester.test_injection_point(
            sample_injection_point,
            techniques=[XSSTechnique.BASIC]
        )
        
        # Verify no vulnerability found
        assert len(results) > 0
        result = results[0]
        assert result.is_vulnerable == False
    
    @pytest.mark.asyncio
    async def test_post_parameter_injection(self, xss_tester, mock_request_handler):
        """Test XSS in POST parameter"""
        # Create POST injection point
        injection_point = InjectionPoint(
            parameter="comment",
            location="post",
            original_value="",
            url="https://example.com/comment",
            method="POST",
            data={"comment": "", "user": "test"}
        )
        
        # Mock responses
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Comment posted"
        
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = "Comment: <script>alert(1)</script>"
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            vulnerable_response
        ]
        
        # Test for XSS
        results = await xss_tester.test_injection_point(
            injection_point,
            techniques=[XSSTechnique.BASIC]
        )
        
        assert len(results) > 0
    
    @pytest.mark.asyncio
    async def test_tag_attribute_injection(self, xss_tester, mock_request_handler, sample_injection_point):
        """Test XSS in tag attribute context"""
        # Mock responses
        baseline_response = Mock(spec=Response)
        baseline_response.text = '<input value="test">'
        
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = '<input value="" onload=alert(1) x="">'
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            vulnerable_response
        ]
        
        # Test tag attribute XSS
        results = await xss_tester.test_injection_point(
            sample_injection_point,
            techniques=[XSSTechnique.TAG_ATTRIBUTE]
        )
        
        assert len(results) > 0
    
    def test_payload_reflection_detection(self, xss_tester):
        """Test payload reflection detection"""
        payload = "<script>alert(1)</script>"
        response_text = "Results: <script>alert(1)</script>"
        baseline_text = "Results: "
        
        is_reflected = xss_tester._is_payload_reflected(
            payload,
            response_text,
            baseline_text
        )
        
        assert is_reflected == True
    
    def test_payload_not_reflected(self, xss_tester):
        """Test when payload is not reflected"""
        payload = "<script>alert(1)</script>"
        response_text = "Results: safe content"
        baseline_text = "Results: "
        
        is_reflected = xss_tester._is_payload_reflected(
            payload,
            response_text,
            baseline_text
        )
        
        assert is_reflected == False
    
    def test_payload_escaped(self, xss_tester):
        """Test when payload is HTML-escaped"""
        payload = "<script>alert(1)</script>"
        response_text = "Results: &lt;script&gt;alert(1)&lt;/script&gt;"
        baseline_text = "Results: "
        
        is_reflected = xss_tester._is_payload_reflected(
            payload,
            response_text,
            baseline_text
        )
        
        # Should return False because payload is escaped
        assert is_reflected == False
    
    def test_dangerous_context_detection(self, xss_tester):
        """Test dangerous context detection"""
        payload = "alert(1)"
        response_text = '<script>var x = "alert(1)";</script>'
        
        is_dangerous = xss_tester._is_dangerous_context(payload, response_text)
        
        assert is_dangerous == True
    
    def test_safe_context_detection(self, xss_tester):
        """Test safe context detection"""
        payload = "alert(1)"
        response_text = '<div>alert(1)</div>'
        
        is_dangerous = xss_tester._is_dangerous_context(payload, response_text)
        
        # Should be False because it's just in text content
        assert is_dangerous == False
    
    def test_xss_type_determination(self, xss_tester, sample_injection_point):
        """Test XSS type determination"""
        payload = "<script>alert(1)</script>"
        response_text = "Normal response"
        
        xss_type = xss_tester._determine_xss_type(
            payload,
            response_text,
            sample_injection_point
        )
        
        # Should default to reflected for GET requests
        assert xss_type == XSSType.REFLECTED
    
    def test_dom_xss_type_determination(self, xss_tester, sample_injection_point):
        """Test DOM-based XSS type determination"""
        payload = "<script>alert(1)</script>"
        response_text = "document.location.hash"
        
        xss_type = xss_tester._determine_xss_type(
            payload,
            response_text,
            sample_injection_point
        )
        
        # Should detect DOM-based XSS
        assert xss_type == XSSType.DOM_BASED


class TestXSSPoCGenerator:
    """Test XSS PoC generator"""
    
    def test_poc_generation_query_param(self):
        """Test PoC generation for query parameter"""
        injection_point = InjectionPoint(
            parameter="search",
            location="query",
            original_value="test",
            url="https://example.com/search?q=test",
            method="GET"
        )
        
        payload = "<script>alert(1)</script>"
        xss_type = XSSType.REFLECTED
        
        poc_generator = XSSPoCGenerator()
        poc_html = poc_generator.generate_poc(
            injection_point,
            payload,
            xss_type
        )
        
        # Verify PoC contains key elements
        assert "<!DOCTYPE html>" in poc_html
        assert injection_point.parameter in poc_html
        assert "XSS" in poc_html
        assert "Proof of Concept" in poc_html
    
    def test_poc_generation_post_param(self):
        """Test PoC generation for POST parameter"""
        injection_point = InjectionPoint(
            parameter="comment",
            location="post",
            original_value="",
            url="https://example.com/comment",
            method="POST",
            data={"comment": "", "user": "test"}
        )
        
        payload = "<script>alert(1)</script>"
        xss_type = XSSType.REFLECTED
        
        poc_generator = XSSPoCGenerator()
        poc_html = poc_generator.generate_poc(
            injection_point,
            payload,
            xss_type
        )
        
        # Verify PoC contains form elements
        assert "<form" in poc_html
        assert "method=\"POST\"" in poc_html
        assert injection_point.parameter in poc_html
    
    def test_exploit_script_generation(self):
        """Test exploit script generation"""
        injection_point = InjectionPoint(
            parameter="search",
            location="query",
            original_value="test",
            url="https://example.com/search?q=test",
            method="GET"
        )
        
        payload = "<script>alert(1)</script>"
        xss_type = XSSType.REFLECTED
        
        poc_generator = XSSPoCGenerator()
        exploit_js = poc_generator.generate_exploit_script(
            injection_point,
            payload,
            xss_type
        )
        
        # Verify exploit script contains key functions
        assert "stealCookies" in exploit_js
        assert "hijackSession" in exploit_js
        assert "startKeylogger" in exploit_js
        assert "showPhishingOverlay" in exploit_js
        assert "document.cookie" in exploit_js


class TestInjectionPoint:
    """Test InjectionPoint dataclass"""
    
    def test_injection_point_creation(self):
        """Test creating injection point"""
        injection_point = InjectionPoint(
            parameter="test",
            location="query",
            original_value="value",
            url="https://example.com",
            method="GET"
        )
        
        assert injection_point.parameter == "test"
        assert injection_point.location == "query"
        assert injection_point.original_value == "value"
        assert injection_point.url == "https://example.com"
        assert injection_point.method == "GET"
    
    def test_injection_point_with_data(self):
        """Test injection point with POST data"""
        injection_point = InjectionPoint(
            parameter="comment",
            location="post",
            original_value="",
            url="https://example.com/comment",
            method="POST",
            data={"comment": "", "user": "test"}
        )
        
        assert injection_point.data is not None
        assert "comment" in injection_point.data
        assert "user" in injection_point.data


class TestXSSResult:
    """Test XSSResult dataclass"""
    
    def test_xss_result_creation(self):
        """Test creating XSS result"""
        injection_point = InjectionPoint(
            parameter="test",
            location="query",
            original_value="value",
            url="https://example.com",
            method="GET"
        )
        
        result = XSSResult(
            injection_point=injection_point,
            is_vulnerable=True,
            xss_type=XSSType.REFLECTED,
            technique=XSSTechnique.BASIC,
            payload="<script>alert(1)</script>",
            confidence=0.95
        )
        
        assert result.is_vulnerable == True
        assert result.xss_type == XSSType.REFLECTED
        assert result.technique == XSSTechnique.BASIC
        assert result.confidence == 0.95
    
    def test_xss_result_with_evidence(self):
        """Test XSS result with evidence"""
        injection_point = InjectionPoint(
            parameter="test",
            location="query",
            original_value="value",
            url="https://example.com",
            method="GET"
        )
        
        evidence = [
            "XSS vulnerability detected",
            "Payload reflected unescaped",
            "Confidence: 95%"
        ]
        
        result = XSSResult(
            injection_point=injection_point,
            is_vulnerable=True,
            evidence=evidence
        )
        
        assert len(result.evidence) == 3
        assert "XSS vulnerability detected" in result.evidence


class TestPayloadCategories:
    """Test payload categories"""
    
    def test_basic_payloads_loaded(self, xss_tester):
        """Test that basic payloads are loaded"""
        assert len(xss_tester.BASIC_PAYLOADS) > 0
        assert any("<script>" in p for p in xss_tester.BASIC_PAYLOADS)
    
    def test_encoded_payloads_loaded(self, xss_tester):
        """Test that encoded payloads are loaded"""
        assert len(xss_tester.ENCODED_PAYLOADS) > 0
        assert any("&#" in p for p in xss_tester.ENCODED_PAYLOADS)
    
    def test_filter_bypass_payloads_loaded(self, xss_tester):
        """Test that filter bypass payloads are loaded"""
        assert len(xss_tester.FILTER_BYPASS_PAYLOADS) > 0
    
    def test_nonstandard_tags_loaded(self, xss_tester):
        """Test that non-standard tags are loaded"""
        assert len(xss_tester.NON_STANDARD_TAGS) > 0
        assert any("marquee" in p.lower() for p in xss_tester.NON_STANDARD_TAGS)
    
    def test_event_handlers_loaded(self, xss_tester):
        """Test that event handlers are loaded"""
        assert len(xss_tester.EVENT_HANDLERS) > 0
        assert "onload" in xss_tester.EVENT_HANDLERS
        assert "onerror" in xss_tester.EVENT_HANDLERS
