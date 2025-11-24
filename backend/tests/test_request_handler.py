"""Unit tests for Request Handler"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from app.core.request_handler import RequestHandler
from app.core.http_models import Request, Response


class TestRequestHandler:
    """Test suite for RequestHandler"""

    @pytest.fixture
    def handler(self):
        """Create a RequestHandler instance"""
        return RequestHandler()

    @pytest.fixture
    def sample_request(self):
        """Create a sample request"""
        return Request(
            method="GET",
            url="https://example.com",
            headers={"User-Agent": "VulnChain"},
            cookies={},
            timeout=30.0,
            follow_redirects=True,
            http2=False,
        )

    def test_handler_initialization(self):
        """Test RequestHandler initialization with default config"""
        handler = RequestHandler()
        assert handler.default_timeout == 30.0
        assert handler.max_retries == 3
        assert handler.retry_backoff_factor == 2.0
        assert handler.waf_bypass_profile is None

    def test_handler_initialization_with_config(self):
        """Test RequestHandler initialization with custom config"""
        config = {
            "timeout": 60.0,
            "max_retries": 5,
            "retry_backoff_factor": 1.5,
        }
        handler = RequestHandler(config)
        assert handler.default_timeout == 60.0
        assert handler.max_retries == 5
        assert handler.retry_backoff_factor == 1.5

    def test_waf_bypass_profile_application(self, handler):
        """Test applying WAF bypass profile"""
        handler.apply_waf_bypass_profile("cloudflare")
        assert handler.waf_bypass_profile == "cloudflare"

    def test_get_waf_bypass_headers_cloudflare(self, handler):
        """Test getting Cloudflare WAF bypass headers"""
        headers = handler._get_waf_bypass_headers("cloudflare")
        assert "CF-Connecting-IP" in headers
        assert "X-Forwarded-For" in headers
        assert headers["CF-Connecting-IP"] == "127.0.0.1"

    def test_get_waf_bypass_headers_generic(self, handler):
        """Test getting generic WAF bypass headers"""
        headers = handler._get_waf_bypass_headers("unknown_profile")
        assert "X-Forwarded-For" in headers
        assert "X-Real-IP" in headers
        assert "X-Client-IP" in headers

    @pytest.mark.asyncio
    async def test_send_request_basic(self, handler):
        """Test basic request sending with mocked aiohttp"""
        with patch("app.core.request_handler.aiohttp.ClientSession") as mock_session:
            # Mock response
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.headers = {"Content-Type": "text/html"}
            mock_resp.read = AsyncMock(return_value=b"<html>Test</html>")

            # Mock request context manager
            mock_request_ctx = AsyncMock()
            mock_request_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_request_ctx.__aexit__ = AsyncMock(return_value=None)

            # Mock session context manager
            mock_session_instance = AsyncMock()
            mock_session_instance.request = MagicMock(return_value=mock_request_ctx)
            
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session_ctx.__aexit__ = AsyncMock(return_value=None)
            
            mock_session.return_value = mock_session_ctx

            response = await handler.send_request(
                method="GET", url="https://example.com"
            )

            assert response.status_code == 200
            assert response.text == "<html>Test</html>"
            assert "Content-Type" in response.headers

    @pytest.mark.asyncio
    async def test_send_request_with_custom_headers(self, handler):
        """Test request with custom headers"""
        custom_headers = {"X-Custom-Header": "test-value", "User-Agent": "VulnChain"}

        with patch("app.core.request_handler.aiohttp.ClientSession") as mock_session:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.headers = {}
            mock_resp.read = AsyncMock(return_value=b"OK")

            # Mock request context manager
            mock_request_ctx = AsyncMock()
            mock_request_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_request_ctx.__aexit__ = AsyncMock(return_value=None)

            # Mock session context manager
            mock_session_instance = AsyncMock()
            mock_session_instance.request = MagicMock(return_value=mock_request_ctx)
            
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session_ctx.__aexit__ = AsyncMock(return_value=None)
            
            mock_session.return_value = mock_session_ctx

            response = await handler.send_request(
                method="GET", url="https://example.com", headers=custom_headers
            )

            # Verify the request was made
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_send_request_with_http2(self, handler):
        """Test request with HTTP/2 enabled"""
        with patch("app.core.request_handler.httpx.AsyncClient") as mock_client:
            # Mock response
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"Content-Type": "application/json"}
            mock_resp.content = b'{"status": "ok"}'
            mock_resp.text = '{"status": "ok"}'

            # Mock client context manager
            mock_client_instance = AsyncMock()
            mock_client_instance.request = AsyncMock(return_value=mock_resp)
            mock_client.return_value.__aenter__ = AsyncMock(
                return_value=mock_client_instance
            )

            response = await handler.send_request(
                method="GET", url="https://example.com", http2=True
            )

            assert response.status_code == 200
            assert response.text == '{"status": "ok"}'

    @pytest.mark.asyncio
    async def test_send_batch_requests(self, handler):
        """Test sending multiple requests concurrently"""
        requests = [
            Request(method="GET", url=f"https://example.com/{i}", headers={})
            for i in range(3)
        ]

        with patch("app.core.request_handler.aiohttp.ClientSession") as mock_session:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.headers = {}
            mock_resp.read = AsyncMock(return_value=b"OK")

            # Mock request context manager
            mock_request_ctx = AsyncMock()
            mock_request_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_request_ctx.__aexit__ = AsyncMock(return_value=None)

            # Mock session context manager
            mock_session_instance = AsyncMock()
            mock_session_instance.request = MagicMock(return_value=mock_request_ctx)
            
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session_ctx.__aexit__ = AsyncMock(return_value=None)
            
            mock_session.return_value = mock_session_ctx

            responses = await handler.send_batch(requests)

            assert len(responses) == 3
            for resp in responses:
                assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test RequestHandler as async context manager"""
        async with RequestHandler() as handler:
            assert handler is not None
            assert isinstance(handler, RequestHandler)


class TestResponse:
    """Test suite for Response model"""

    def test_response_is_success(self):
        """Test is_success property for 2xx status codes"""
        request = Request(method="GET", url="https://example.com", headers={})
        response = Response(
            status_code=200,
            headers={},
            body=b"OK",
            text="OK",
            elapsed_time=0.5,
            request=request,
        )
        assert response.is_success is True

        response.status_code = 201
        assert response.is_success is True

        response.status_code = 404
        assert response.is_success is False

    def test_response_is_redirect(self):
        """Test is_redirect property for 3xx status codes"""
        request = Request(method="GET", url="https://example.com", headers={})
        response = Response(
            status_code=301,
            headers={},
            body=b"",
            text="",
            elapsed_time=0.5,
            request=request,
        )
        assert response.is_redirect is True

        response.status_code = 302
        assert response.is_redirect is True

        response.status_code = 200
        assert response.is_redirect is False

    def test_response_is_client_error(self):
        """Test is_client_error property for 4xx status codes"""
        request = Request(method="GET", url="https://example.com", headers={})
        response = Response(
            status_code=404,
            headers={},
            body=b"Not Found",
            text="Not Found",
            elapsed_time=0.5,
            request=request,
        )
        assert response.is_client_error is True

        response.status_code = 403
        assert response.is_client_error is True

        response.status_code = 500
        assert response.is_client_error is False

    def test_response_is_server_error(self):
        """Test is_server_error property for 5xx status codes"""
        request = Request(method="GET", url="https://example.com", headers={})
        response = Response(
            status_code=500,
            headers={},
            body=b"Internal Server Error",
            text="Internal Server Error",
            elapsed_time=0.5,
            request=request,
        )
        assert response.is_server_error is True

        response.status_code = 503
        assert response.is_server_error is True

        response.status_code = 200
        assert response.is_server_error is False


class TestRequest:
    """Test suite for Request model"""

    def test_request_creation(self):
        """Test creating a Request object"""
        request = Request(
            method="POST",
            url="https://api.example.com/data",
            headers={"Content-Type": "application/json"},
            data={"key": "value"},
            cookies={"session": "abc123"},
            proxy="http://proxy.example.com:8080",
            timeout=60.0,
            follow_redirects=False,
            http2=True,
        )

        assert request.method == "POST"
        assert request.url == "https://api.example.com/data"
        assert request.headers["Content-Type"] == "application/json"
        assert request.data == {"key": "value"}
        assert request.cookies["session"] == "abc123"
        assert request.proxy == "http://proxy.example.com:8080"
        assert request.timeout == 60.0
        assert request.follow_redirects is False
        assert request.http2 is True
        assert isinstance(request.timestamp, datetime)

    def test_request_default_values(self):
        """Test Request object with default values"""
        request = Request(method="GET", url="https://example.com")

        assert request.method == "GET"
        assert request.url == "https://example.com"
        assert request.headers == {}
        assert request.data is None
        assert request.cookies == {}
        assert request.proxy is None
        assert request.timeout == 30.0
        assert request.follow_redirects is True
        assert request.http2 is False
