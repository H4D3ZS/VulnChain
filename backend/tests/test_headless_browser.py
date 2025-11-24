"""Tests for headless browser module"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from app.modules.headless_browser import (
    HeadlessBrowser,
    StorageType,
    StorageData,
    APICall,
    ClickjackingResult,
    BrowserResult,
)
from app.core.request_handler import RequestHandler, Response
from app.models.target import TargetConfig


@pytest.fixture
def request_handler():
    """Create mock request handler"""
    handler = Mock(spec=RequestHandler)
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def headless_browser(request_handler):
    """Create headless browser instance"""
    return HeadlessBrowser(request_handler)


@pytest.fixture
def target_config():
    """Create target configuration"""
    return TargetConfig(
        url="https://example.com",
        custom_headers={"User-Agent": "Test"},
    )


@pytest.fixture
def mock_request():
    """Create mock HTTP request"""
    from app.core.http_models import Request
    return Request(
        method="GET",
        url="https://example.com",
        headers={},
    )


@pytest.fixture
def mock_response(mock_request):
    """Create mock HTTP response"""
    return Response(
        status_code=200,
        headers={
            "content-type": "text/html",
            "x-frame-options": "DENY",
        },
        body=b"<html><body>Test</body></html>",
        text="<html><body>Test</body></html>",
        elapsed_time=0.5,
        request=mock_request,
    )


class TestHeadlessBrowser:
    """Test HeadlessBrowser class"""
    
    def test_initialization(self, request_handler):
        """Test browser initialization"""
        browser = HeadlessBrowser(request_handler)
        
        assert browser.request_handler == request_handler
        assert browser._playwright is None
        assert browser._browser is None
        assert browser._browser_type == "chromium"
    
    @pytest.mark.asyncio
    async def test_close_browser(self, headless_browser):
        """Test browser cleanup"""
        # Mock browser and playwright
        mock_browser = AsyncMock()
        mock_playwright = AsyncMock()
        headless_browser._browser = mock_browser
        headless_browser._playwright = mock_playwright
        
        await headless_browser.close()
        
        mock_browser.close.assert_called_once()
        mock_playwright.stop.assert_called_once()
        assert headless_browser._browser is None
        assert headless_browser._playwright is None
    
    @pytest.mark.asyncio
    async def test_ensure_browser_not_installed(self, headless_browser):
        """Test browser initialization when Playwright not installed"""
        # Mock the import to fail
        with patch('builtins.__import__', side_effect=ImportError("No module named 'playwright'")):
            with pytest.raises(ImportError, match="Playwright not installed"):
                await headless_browser._ensure_browser()
    
    @pytest.mark.asyncio
    async def test_render_page_without_playwright(self, headless_browser, target_config):
        """Test render_page when Playwright is not available"""
        # Mock the import to fail
        with patch('builtins.__import__', side_effect=ImportError("No module named 'playwright'")):
            with pytest.raises(ImportError):
                await headless_browser.render_page(target_config)
    
    @pytest.mark.asyncio
    async def test_clickjacking_no_protection_headers(
        self, headless_browser, target_config, mock_request
    ):
        """Test clickjacking detection when no protection headers present"""
        # Mock response without protection headers
        mock_response = Response(
            status_code=200,
            headers={"content-type": "text/html"},
            body=b"<html><body>Test</body></html>",
            text="<html><body>Test</body></html>",
            elapsed_time=0.5,
            request=mock_request,
        )
        headless_browser.request_handler.send_request.return_value = mock_response
        
        # Mock browser operations
        with patch.object(headless_browser, '_ensure_browser', new_callable=AsyncMock):
            mock_browser = AsyncMock()
            mock_context = AsyncMock()
            mock_page = AsyncMock()
            
            mock_browser.new_context.return_value = mock_context
            mock_context.new_page.return_value = mock_page
            mock_page.evaluate.side_effect = [True, False]  # frameLoaded, frameBustingDetected
            
            headless_browser._browser = mock_browser
            
            result = await headless_browser.test_clickjacking(
                target=target_config,
                generate_poc=False
            )
            
            assert result.is_vulnerable is True
            assert result.x_frame_options is None
            assert result.csp_frame_ancestors is None
            assert "No X-Frame-Options" in result.evidence[0]
    
    @pytest.mark.asyncio
    async def test_clickjacking_with_x_frame_options(
        self, headless_browser, target_config, mock_request
    ):
        """Test clickjacking detection with X-Frame-Options header"""
        # Mock response with X-Frame-Options
        mock_response = Response(
            status_code=200,
            headers={
                "content-type": "text/html",
                "x-frame-options": "DENY"
            },
            body=b"<html><body>Test</body></html>",
            text="<html><body>Test</body></html>",
            elapsed_time=0.5,
            request=mock_request,
        )
        headless_browser.request_handler.send_request.return_value = mock_response
        
        # Mock browser operations
        with patch.object(headless_browser, '_ensure_browser', new_callable=AsyncMock):
            mock_browser = AsyncMock()
            mock_context = AsyncMock()
            mock_page = AsyncMock()
            
            mock_browser.new_context.return_value = mock_context
            mock_context.new_page.return_value = mock_page
            mock_page.evaluate.side_effect = [False, False]  # frameLoaded, frameBustingDetected
            
            headless_browser._browser = mock_browser
            
            result = await headless_browser.test_clickjacking(
                target=target_config,
                generate_poc=False
            )
            
            assert result.x_frame_options == "deny"
            assert "Blocked by security headers" in result.evidence
    
    @pytest.mark.asyncio
    async def test_clickjacking_poc_generation(
        self, headless_browser, target_config, mock_request
    ):
        """Test clickjacking PoC generation"""
        # Mock response without protection
        mock_response = Response(
            status_code=200,
            headers={"content-type": "text/html"},
            body=b"<html><body>Test</body></html>",
            text="<html><body>Test</body></html>",
            elapsed_time=0.5,
            request=mock_request,
        )
        headless_browser.request_handler.send_request.return_value = mock_response
        
        # Mock browser operations
        with patch.object(headless_browser, '_ensure_browser', new_callable=AsyncMock):
            mock_browser = AsyncMock()
            mock_context = AsyncMock()
            mock_page = AsyncMock()
            
            mock_browser.new_context.return_value = mock_context
            mock_context.new_page.return_value = mock_page
            mock_page.evaluate.side_effect = [True, False]
            
            headless_browser._browser = mock_browser
            
            result = await headless_browser.test_clickjacking(
                target=target_config,
                generate_poc=True
            )
            
            assert result.is_vulnerable is True
            assert result.poc_html is not None
            assert target_config.url in result.poc_html
            assert "<iframe" in result.poc_html
            assert "opacity" in result.poc_html
    
    def test_generate_clickjacking_poc(self, headless_browser):
        """Test PoC HTML generation"""
        target_url = "https://example.com/vulnerable"
        
        poc_html = headless_browser._generate_clickjacking_poc(target_url)
        
        assert target_url in poc_html
        assert "<!DOCTYPE html>" in poc_html
        assert "<iframe" in poc_html
        assert "opacity" in poc_html
        assert "z-index" in poc_html
    
    @pytest.mark.asyncio
    async def test_extract_local_storage(self, headless_browser):
        """Test localStorage extraction"""
        mock_page = AsyncMock()
        mock_page.evaluate.return_value = {
            "token": "abc123",
            "user": "testuser"
        }
        mock_page.url = "https://example.com"
        
        storage_data = await headless_browser._extract_local_storage(mock_page)
        
        assert len(storage_data) == 2
        assert all(item.storage_type == StorageType.LOCAL_STORAGE for item in storage_data)
        
        # Check token
        token_item = next(item for item in storage_data if item.key == "token")
        assert token_item.value == "abc123"
        assert token_item.domain == "example.com"
    
    @pytest.mark.asyncio
    async def test_extract_session_storage(self, headless_browser):
        """Test sessionStorage extraction"""
        mock_page = AsyncMock()
        mock_page.evaluate.return_value = {
            "session_id": "xyz789"
        }
        mock_page.url = "https://example.com"
        
        storage_data = await headless_browser._extract_session_storage(mock_page)
        
        assert len(storage_data) == 1
        assert storage_data[0].storage_type == StorageType.SESSION_STORAGE
        assert storage_data[0].key == "session_id"
        assert storage_data[0].value == "xyz789"
    
    @pytest.mark.asyncio
    async def test_extract_indexed_db(self, headless_browser):
        """Test IndexedDB extraction"""
        mock_page = AsyncMock()
        mock_page.evaluate.return_value = [
            {
                "database": "mydb",
                "objectStore": "users",
                "data": [{"id": 1, "name": "Alice"}]
            }
        ]
        mock_page.url = "https://example.com"
        
        storage_data = await headless_browser._extract_indexed_db(mock_page)
        
        assert len(storage_data) == 1
        assert storage_data[0].storage_type == StorageType.INDEXED_DB
        assert storage_data[0].key == "mydb.users"
        assert storage_data[0].metadata["database"] == "mydb"
        assert storage_data[0].metadata["objectStore"] == "users"
    
    @pytest.mark.asyncio
    async def test_extract_storage_error_handling(self, headless_browser):
        """Test storage extraction with errors"""
        mock_page = AsyncMock()
        mock_page.evaluate.side_effect = Exception("JavaScript error")
        mock_page.url = "https://example.com"
        
        # Should not raise, just return empty list
        storage_data = await headless_browser._extract_local_storage(mock_page)
        assert storage_data == []
    
    def test_capture_response(self, headless_browser):
        """Test API response capture"""
        api_calls = [
            APICall(
                url="https://api.example.com/data",
                method="GET",
                headers={},
            )
        ]
        
        mock_response = Mock()
        mock_response.url = "https://api.example.com/data"
        mock_response.status = 200
        mock_response.headers = {"content-type": "application/json"}
        
        headless_browser._capture_response(mock_response, api_calls)
        
        assert api_calls[0].response_status == 200
        assert api_calls[0].response_headers == {"content-type": "application/json"}
    
    def test_capture_response_no_match(self, headless_browser):
        """Test response capture with no matching API call"""
        api_calls = [
            APICall(
                url="https://api.example.com/other",
                method="GET",
                headers={},
            )
        ]
        
        mock_response = Mock()
        mock_response.url = "https://api.example.com/data"
        mock_response.status = 200
        mock_response.headers = {}
        
        # Should not raise
        headless_browser._capture_response(mock_response, api_calls)
        
        # Original API call should be unchanged
        assert api_calls[0].response_status is None


class TestStorageData:
    """Test StorageData dataclass"""
    
    def test_storage_data_creation(self):
        """Test creating StorageData"""
        data = StorageData(
            storage_type=StorageType.LOCAL_STORAGE,
            key="token",
            value="abc123",
            domain="example.com",
            metadata={"expires": "2024-12-31"}
        )
        
        assert data.storage_type == StorageType.LOCAL_STORAGE
        assert data.key == "token"
        assert data.value == "abc123"
        assert data.domain == "example.com"
        assert data.metadata["expires"] == "2024-12-31"
    
    def test_storage_data_defaults(self):
        """Test StorageData default values"""
        data = StorageData(
            storage_type=StorageType.COOKIES,
            key="session",
            value="xyz"
        )
        
        assert data.domain is None
        assert data.metadata == {}


class TestAPICall:
    """Test APICall dataclass"""
    
    def test_api_call_creation(self):
        """Test creating APICall"""
        call = APICall(
            url="https://api.example.com/users",
            method="POST",
            headers={"Content-Type": "application/json"},
            request_body='{"name": "Alice"}',
            response_status=201,
            response_headers={"Location": "/users/123"},
            timestamp=1234567890.0
        )
        
        assert call.url == "https://api.example.com/users"
        assert call.method == "POST"
        assert call.request_body == '{"name": "Alice"}'
        assert call.response_status == 201
        assert call.timestamp == 1234567890.0
    
    def test_api_call_defaults(self):
        """Test APICall default values"""
        call = APICall(
            url="https://api.example.com/data",
            method="GET",
            headers={}
        )
        
        assert call.request_body is None
        assert call.response_status is None
        assert call.response_headers is None
        assert call.timestamp is None


class TestClickjackingResult:
    """Test ClickjackingResult dataclass"""
    
    def test_clickjacking_result_vulnerable(self):
        """Test vulnerable clickjacking result"""
        result = ClickjackingResult(
            is_vulnerable=True,
            frame_busting_present=False,
            frame_busting_bypassed=False,
            x_frame_options=None,
            csp_frame_ancestors=None,
            poc_html="<html>...</html>",
            evidence=["No protection headers"]
        )
        
        assert result.is_vulnerable is True
        assert result.frame_busting_present is False
        assert result.x_frame_options is None
        assert result.poc_html == "<html>...</html>"
        assert len(result.evidence) == 1
    
    def test_clickjacking_result_protected(self):
        """Test protected clickjacking result"""
        result = ClickjackingResult(
            is_vulnerable=False,
            frame_busting_present=False,
            frame_busting_bypassed=False,
            x_frame_options="DENY",
            csp_frame_ancestors="frame-ancestors 'none'",
            evidence=["Protected by X-Frame-Options"]
        )
        
        assert result.is_vulnerable is False
        assert result.x_frame_options == "DENY"
        assert result.csp_frame_ancestors == "frame-ancestors 'none'"


class TestBrowserResult:
    """Test BrowserResult dataclass"""
    
    def test_browser_result_success(self):
        """Test successful browser result"""
        result = BrowserResult(
            url="https://example.com",
            success=True,
            rendered_html="<html>...</html>",
            screenshot=b"image_data",
            console_logs=["[log] Page loaded"],
            network_requests=[{"url": "https://example.com/api"}],
            storage_data=[],
            api_calls=[],
            metadata={"status_code": 200}
        )
        
        assert result.success is True
        assert result.rendered_html == "<html>...</html>"
        assert result.screenshot == b"image_data"
        assert len(result.console_logs) == 1
        assert result.metadata["status_code"] == 200
    
    def test_browser_result_failure(self):
        """Test failed browser result"""
        result = BrowserResult(
            url="https://example.com",
            success=False,
            error="Connection timeout"
        )
        
        assert result.success is False
        assert result.error == "Connection timeout"
        assert result.rendered_html is None
        assert result.screenshot is None


class TestStorageType:
    """Test StorageType enum"""
    
    def test_storage_types(self):
        """Test all storage type values"""
        assert StorageType.LOCAL_STORAGE.value == "localStorage"
        assert StorageType.SESSION_STORAGE.value == "sessionStorage"
        assert StorageType.INDEXED_DB.value == "indexedDB"
        assert StorageType.COOKIES.value == "cookies"
    
    def test_storage_type_list(self):
        """Test getting list of all storage types"""
        types = list(StorageType)
        assert len(types) == 4
        assert StorageType.LOCAL_STORAGE in types
        assert StorageType.SESSION_STORAGE in types
        assert StorageType.INDEXED_DB in types
        assert StorageType.COOKIES in types
