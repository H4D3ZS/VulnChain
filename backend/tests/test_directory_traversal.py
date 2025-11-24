"""Tests for Directory Traversal module"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
from app.modules.directory_traversal import (
    DirectoryTraversalTester,
    InjectionPoint,
    TraversalTechnique,
    TraversalResult,
)
from app.core.request_handler import Response


@pytest.fixture
def mock_request_handler():
    """Create a mock request handler"""
    handler = Mock()
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def tester(mock_request_handler):
    """Create a DirectoryTraversalTester instance"""
    return DirectoryTraversalTester(mock_request_handler)


@pytest.fixture
def injection_point():
    """Create a sample injection point"""
    return InjectionPoint(
        parameter="file",
        location="query",
        original_value="index.php",
        url="http://example.com/view.php?file=index.php",
        method="GET",
    )


class TestDirectoryTraversalTester:
    """Tests for DirectoryTraversalTester class"""
    
    @pytest.mark.asyncio
    async def test_basic_traversal_vulnerable(self, tester, injection_point, mock_request_handler):
        """Test detection of basic directory traversal vulnerability"""
        # Mock baseline response
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Normal page content"
        baseline_response.status_code = 200
        
        # Mock vulnerable response with /etc/passwd content
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        vulnerable_response.status_code = 200
        
        # Configure mock to return different responses
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            vulnerable_response,
        ]
        
        # Test basic traversal
        results = await tester._test_basic_traversal(
            injection_point,
            target_files=["/etc/passwd"],
        )
        
        # Verify vulnerability detected
        assert results is not None
        assert results.is_vulnerable is True
        assert results.technique == TraversalTechnique.BASIC
        assert results.target_file == "/etc/passwd"
        assert results.confidence >= 0.9
        assert "root:x:0:0" in results.file_content
    
    @pytest.mark.asyncio
    async def test_basic_traversal_not_vulnerable(self, tester, injection_point, mock_request_handler):
        """Test when basic directory traversal is not vulnerable"""
        # Mock response without file content
        normal_response = Mock(spec=Response)
        normal_response.text = "Normal page content"
        normal_response.status_code = 200
        
        mock_request_handler.send_request.return_value = normal_response
        
        # Test basic traversal
        results = await tester._test_basic_traversal(
            injection_point,
            target_files=["/etc/passwd"],
        )
        
        # Verify no vulnerability detected
        assert results is not None
        assert results.is_vulnerable is False
        assert results.confidence == 0.0
    
    @pytest.mark.asyncio
    async def test_url_encoded_traversal(self, tester, injection_point, mock_request_handler):
        """Test URL encoded directory traversal"""
        # Mock baseline response
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Normal content"
        baseline_response.status_code = 200
        
        # Mock vulnerable response
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = "127.0.0.1 localhost\n::1 localhost"
        vulnerable_response.status_code = 200
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            vulnerable_response,
        ]
        
        # Test URL encoded traversal
        results = await tester._test_url_encoded_traversal(
            injection_point,
            target_files=["/etc/hosts"],
        )
        
        # Verify vulnerability detected
        assert results is not None
        assert results.is_vulnerable is True
        assert results.technique == TraversalTechnique.URL_ENCODED
        assert "127.0.0.1" in results.file_content
    
    @pytest.mark.asyncio
    async def test_double_encoded_traversal(self, tester, injection_point, mock_request_handler):
        """Test double URL encoded directory traversal"""
        # Mock baseline response
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Normal content"
        baseline_response.status_code = 200
        
        # Mock vulnerable response with Windows ini file
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = "[fonts]\nfont1=arial.ttf\n[extensions]\next1=.txt"
        vulnerable_response.status_code = 200
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            vulnerable_response,
        ]
        
        # Test double encoded traversal
        results = await tester._test_double_encoded_traversal(
            injection_point,
            target_files=["C:\\Windows\\win.ini"],
        )
        
        # Verify vulnerability detected
        assert results is not None
        assert results.is_vulnerable is True
        assert results.technique == TraversalTechnique.DOUBLE_ENCODED
        assert "[fonts]" in results.file_content
    
    @pytest.mark.asyncio
    async def test_null_byte_traversal(self, tester, injection_point, mock_request_handler):
        """Test null byte injection directory traversal"""
        # Mock baseline response
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Normal content"
        baseline_response.status_code = 200
        
        # Mock vulnerable response
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = "root:x:0:0:root:/root:/bin/bash"
        vulnerable_response.status_code = 200
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            vulnerable_response,
        ]
        
        # Test null byte traversal
        results = await tester._test_null_byte_traversal(
            injection_point,
            target_files=["/etc/passwd"],
        )
        
        # Verify vulnerability detected
        assert results is not None
        assert results.is_vulnerable is True
        assert results.technique == TraversalTechnique.NULL_BYTE
        assert "root:x:0:0" in results.file_content
    
    @pytest.mark.asyncio
    async def test_unicode_traversal(self, tester, injection_point, mock_request_handler):
        """Test Unicode encoded directory traversal"""
        # Mock baseline response
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Normal content"
        baseline_response.status_code = 200
        
        # Mock vulnerable response
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = "root:x:0:0:root:/root:/bin/bash"
        vulnerable_response.status_code = 200
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            vulnerable_response,
        ]
        
        # Test Unicode traversal
        results = await tester._test_unicode_traversal(
            injection_point,
            target_files=["/etc/passwd"],
        )
        
        # Verify vulnerability detected
        assert results is not None
        assert results.is_vulnerable is True
        assert results.technique == TraversalTechnique.UNICODE
    
    @pytest.mark.asyncio
    async def test_mixed_encoding_traversal(self, tester, injection_point, mock_request_handler):
        """Test mixed encoding directory traversal"""
        # Mock baseline response
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Normal content"
        baseline_response.status_code = 200
        
        # Mock vulnerable response
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = "root:x:0:0:root:/root:/bin/bash"
        vulnerable_response.status_code = 200
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            vulnerable_response,
        ]
        
        # Test mixed encoding traversal
        results = await tester._test_mixed_encoding_traversal(
            injection_point,
            target_files=["/etc/passwd"],
        )
        
        # Verify vulnerability detected
        assert results is not None
        assert results.is_vulnerable is True
        assert results.technique == TraversalTechnique.MIXED
    
    def test_detect_file_content_passwd(self, tester):
        """Test detection of /etc/passwd content"""
        response_text = "Some content\nroot:x:0:0:root:/root:/bin/bash\nMore content"
        baseline_text = "Some content\nMore content"
        
        is_traversal, file_content = tester._detect_file_content(
            response_text,
            baseline_text,
            "/etc/passwd",
        )
        
        assert is_traversal is True
        assert "root:x:0:0" in file_content
    
    def test_detect_file_content_windows_ini(self, tester):
        """Test detection of Windows INI file content"""
        response_text = "Page content\n[fonts]\nfont1=arial.ttf\n[extensions]"
        baseline_text = "Page content"
        
        is_traversal, file_content = tester._detect_file_content(
            response_text,
            baseline_text,
            "C:\\Windows\\win.ini",
        )
        
        assert is_traversal is True
        assert "[fonts]" in file_content
    
    def test_detect_file_content_length_difference(self, tester):
        """Test detection based on response length difference"""
        response_text = "A" * 1000  # Long response
        baseline_text = "Short"
        
        is_traversal, file_content = tester._detect_file_content(
            response_text,
            baseline_text,
            "/etc/passwd",
        )
        
        assert is_traversal is True
        assert file_content is not None
    
    def test_detect_file_content_no_difference(self, tester):
        """Test when no file content is detected"""
        response_text = "Normal content"
        baseline_text = "Normal content"
        
        is_traversal, file_content = tester._detect_file_content(
            response_text,
            baseline_text,
            "/etc/passwd",
        )
        
        assert is_traversal is False
        assert file_content is None
    
    @pytest.mark.asyncio
    async def test_test_injection_point_all_techniques(self, tester, injection_point, mock_request_handler):
        """Test injection point with all techniques"""
        # Mock responses
        normal_response = Mock(spec=Response)
        normal_response.text = "Normal content"
        normal_response.status_code = 200
        
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = "root:x:0:0:root:/root:/bin/bash"
        vulnerable_response.status_code = 200
        
        # Return vulnerable response on second call
        mock_request_handler.send_request.side_effect = [
            normal_response,  # Baseline
            vulnerable_response,  # Vulnerable
        ]
        
        # Test all techniques
        results = await tester.test_injection_point(injection_point)
        
        # Should have results
        assert len(results) > 0
        
        # At least one should be vulnerable (based on our mock)
        vulnerable_results = [r for r in results if r.is_vulnerable]
        assert len(vulnerable_results) > 0
    
    @pytest.mark.asyncio
    async def test_test_injection_point_specific_technique(self, tester, injection_point, mock_request_handler):
        """Test injection point with specific technique"""
        # Mock responses
        normal_response = Mock(spec=Response)
        normal_response.text = "Normal content"
        normal_response.status_code = 200
        
        mock_request_handler.send_request.return_value = normal_response
        
        # Test only basic technique
        results = await tester.test_injection_point(
            injection_point,
            techniques=[TraversalTechnique.BASIC],
        )
        
        # Should have exactly one result
        assert len(results) == 1
        assert results[0].technique == TraversalTechnique.BASIC
    
    @pytest.mark.asyncio
    async def test_send_request_query_location(self, tester, injection_point, mock_request_handler):
        """Test sending request with query parameter injection"""
        mock_response = Mock(spec=Response)
        mock_response.text = "Response"
        mock_request_handler.send_request.return_value = mock_response
        
        # Send request
        response = await tester._send_request(injection_point, "../../etc/passwd")
        
        # Verify request was made
        assert mock_request_handler.send_request.called
        call_args = mock_request_handler.send_request.call_args
        
        # Check that URL contains the injected value
        assert "url" in call_args.kwargs or len(call_args.args) > 0
    
    @pytest.mark.asyncio
    async def test_send_request_post_location(self, tester, mock_request_handler):
        """Test sending request with POST parameter injection"""
        injection_point = InjectionPoint(
            parameter="filename",
            location="post",
            original_value="file.txt",
            url="http://example.com/download.php",
            method="POST",
            data={"filename": "file.txt"},
        )
        
        mock_response = Mock(spec=Response)
        mock_response.text = "Response"
        mock_request_handler.send_request.return_value = mock_response
        
        # Send request
        response = await tester._send_request(injection_point, "../../etc/passwd")
        
        # Verify request was made with POST data
        assert mock_request_handler.send_request.called
        call_args = mock_request_handler.send_request.call_args
        
        # Check that data parameter was passed
        assert "data" in call_args.kwargs
        assert call_args.kwargs["data"]["filename"] == "../../etc/passwd"
    
    @pytest.mark.asyncio
    async def test_send_request_header_location(self, tester, mock_request_handler):
        """Test sending request with header injection"""
        injection_point = InjectionPoint(
            parameter="X-File-Path",
            location="header",
            original_value="default.txt",
            url="http://example.com/api/file",
            method="GET",
            headers={"X-File-Path": "default.txt"},
        )
        
        mock_response = Mock(spec=Response)
        mock_response.text = "Response"
        mock_request_handler.send_request.return_value = mock_response
        
        # Send request
        response = await tester._send_request(injection_point, "../../etc/passwd")
        
        # Verify request was made with modified header
        assert mock_request_handler.send_request.called
        call_args = mock_request_handler.send_request.call_args
        
        # Check that headers parameter was passed
        assert "headers" in call_args.kwargs
        assert call_args.kwargs["headers"]["X-File-Path"] == "../../etc/passwd"
    
    @pytest.mark.asyncio
    async def test_send_request_cookie_location(self, tester, mock_request_handler):
        """Test sending request with cookie injection"""
        injection_point = InjectionPoint(
            parameter="file_path",
            location="cookie",
            original_value="default.txt",
            url="http://example.com/view",
            method="GET",
        )
        
        mock_response = Mock(spec=Response)
        mock_response.text = "Response"
        mock_request_handler.send_request.return_value = mock_response
        
        # Send request
        response = await tester._send_request(injection_point, "../../etc/passwd")
        
        # Verify request was made with cookie
        assert mock_request_handler.send_request.called
        call_args = mock_request_handler.send_request.call_args
        
        # Check that cookies parameter was passed
        assert "cookies" in call_args.kwargs
        assert call_args.kwargs["cookies"]["file_path"] == "../../etc/passwd"


class TestInjectionPoint:
    """Tests for InjectionPoint dataclass"""
    
    def test_injection_point_creation(self):
        """Test creating an injection point"""
        point = InjectionPoint(
            parameter="file",
            location="query",
            original_value="index.php",
            url="http://example.com/view.php?file=index.php",
            method="GET",
        )
        
        assert point.parameter == "file"
        assert point.location == "query"
        assert point.original_value == "index.php"
        assert point.url == "http://example.com/view.php?file=index.php"
        assert point.method == "GET"


class TestTraversalResult:
    """Tests for TraversalResult dataclass"""
    
    def test_traversal_result_creation(self):
        """Test creating a traversal result"""
        injection_point = InjectionPoint(
            parameter="file",
            location="query",
            original_value="index.php",
            url="http://example.com/view.php",
            method="GET",
        )
        
        result = TraversalResult(
            injection_point=injection_point,
            is_vulnerable=True,
            technique=TraversalTechnique.BASIC,
            payload="../../etc/passwd",
            confidence=0.95,
            file_content="root:x:0:0",
            target_file="/etc/passwd",
            evidence=["File content detected"],
        )
        
        assert result.is_vulnerable is True
        assert result.technique == TraversalTechnique.BASIC
        assert result.payload == "../../etc/passwd"
        assert result.confidence == 0.95
        assert result.file_content == "root:x:0:0"
        assert result.target_file == "/etc/passwd"
        assert len(result.evidence) == 1
