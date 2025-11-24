"""Tests for XXE module"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timezone

from app.modules.xxe import (
    XXETester,
    XXEPoCGenerator,
    InjectionPoint,
    XXEResult,
    XXEType,
)
from app.core.http_models import Response, Request
from app.core.oob_listener import Callback


@pytest.fixture
def request_handler():
    """Create mock request handler"""
    handler = Mock()
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def oob_listener():
    """Create mock OOB listener"""
    listener = Mock()
    listener.generate_unique_id = Mock(return_value="test-unique-id-123")
    listener.get_callback_url = Mock(return_value="http://attacker.com:8080/test-unique-id-123")
    listener.get_dns_callback = Mock(return_value="test-unique-id-123.attacker.com")
    listener.register_payload = AsyncMock()
    listener.wait_for_callback = AsyncMock()
    return listener


@pytest.fixture
def injection_point():
    """Create test injection point"""
    return InjectionPoint(
        parameter="xml_data",
        location="body",
        original_value="<root>test</root>",
        url="https://example.com/api/parse",
        method="POST",
        headers={"Content-Type": "application/xml"},
    )


class TestXXETester:
    """Tests for XXETester class"""
    
    @pytest.mark.asyncio
    async def test_direct_xxe_detection(self, request_handler, injection_point):
        """Test direct XXE detection with visible output"""
        # Create mock request
        mock_request = Request(
            method="POST",
            url="https://example.com/api/parse",
            headers={"Content-Type": "application/xml"},
        )
        
        # Mock baseline response
        baseline_response = Response(
            status_code=200,
            headers={},
            body=b"<response>OK</response>",
            text="<response>OK</response>",
            elapsed_time=0.1,
            request=mock_request,
        )
        
        # Mock XXE response with /etc/passwd content
        xxe_response = Response(
            status_code=200,
            headers={},
            body=b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            elapsed_time=0.2,
            request=mock_request,
        )
        
        # Configure mock to return different responses
        request_handler.send_request.side_effect = [baseline_response, xxe_response]
        
        # Create tester
        tester = XXETester(request_handler=request_handler)
        
        # Test for direct XXE
        results = await tester.test_injection_point(
            injection_point,
            techniques=[XXEType.DIRECT],
            target_files=["/etc/passwd"],
        )
        
        # Verify results
        assert len(results) > 0
        result = results[0]
        assert result.is_vulnerable
        assert result.xxe_type == XXEType.DIRECT
        assert result.target_file == "/etc/passwd"
        assert "root:x:0:0" in result.exfiltrated_data
        assert result.confidence >= 0.9
    
    @pytest.mark.asyncio
    async def test_direct_xxe_not_vulnerable(self, request_handler, injection_point):
        """Test direct XXE when not vulnerable"""
        # Create mock request
        mock_request = Request(
            method="POST",
            url="https://example.com/api/parse",
        )
        
        # Mock response without XXE indicators
        normal_response = Response(
            status_code=200,
            headers={},
            body=b"<response>OK</response>",
            text="<response>OK</response>",
            elapsed_time=0.1,
            request=mock_request,
        )
        
        # All responses are normal
        request_handler.send_request.return_value = normal_response
        
        # Create tester
        tester = XXETester(request_handler=request_handler)
        
        # Test for direct XXE
        results = await tester.test_injection_point(
            injection_point,
            techniques=[XXEType.DIRECT],
            target_files=["/etc/passwd"],
        )
        
        # Verify not vulnerable
        assert len(results) > 0
        result = results[0]
        assert not result.is_vulnerable
        assert result.confidence == 0.0
    
    @pytest.mark.asyncio
    async def test_error_based_xxe_detection(self, request_handler, injection_point):
        """Test error-based XXE detection"""
        # Create mock request
        mock_request = Request(
            method="POST",
            url="https://example.com/api/parse",
        )
        
        # Mock baseline response
        baseline_response = Response(
            status_code=200,
            headers={},
            body=b"<response>OK</response>",
            text="<response>OK</response>",
            elapsed_time=0.1,
            request=mock_request,
        )
        
        # Mock error response with file content
        error_response = Response(
            status_code=500,
            headers={},
            body=b"XML parsing error: file:///etc/passwd contains root:x:0:0:root:/root:/bin/bash",
            text="XML parsing error: file:///etc/passwd contains root:x:0:0:root:/root:/bin/bash",
            elapsed_time=0.2,
            request=mock_request,
        )
        
        # Configure mock
        request_handler.send_request.side_effect = [baseline_response, error_response]
        
        # Create tester
        tester = XXETester(request_handler=request_handler)
        
        # Test for error-based XXE
        results = await tester.test_injection_point(
            injection_point,
            techniques=[XXEType.ERROR_BASED],
            target_files=["/etc/passwd"],
        )
        
        # Verify results
        assert len(results) > 0
        result = results[0]
        assert result.is_vulnerable
        assert result.xxe_type == XXEType.ERROR_BASED
        assert result.target_file == "/etc/passwd"
        # The error message contains the file path and content
        assert "file:///etc/passwd" in result.exfiltrated_data or "root:x:0:0" in result.exfiltrated_data
    
    @pytest.mark.asyncio
    async def test_oob_http_xxe_detection(self, request_handler, oob_listener, injection_point):
        """Test blind XXE with HTTP OOB callbacks"""
        # Create mock request
        mock_request = Request(
            method="POST",
            url="https://example.com/api/parse",
        )
        
        # Mock normal response
        normal_response = Response(
            status_code=200,
            headers={},
            body=b"<response>OK</response>",
            text="<response>OK</response>",
            elapsed_time=0.1,
            request=mock_request,
        )
        request_handler.send_request.return_value = normal_response
        
        # Mock OOB callback with exfiltrated data
        callback = Callback(
            callback_id="callback-123",
            unique_id="test-unique-id-123",
            callback_type="http",
            source_ip="192.168.1.100",
            timestamp=datetime.now(timezone.utc),
            data={
                "method": "GET",
                "path": "/test-unique-id-123",
                "body": "root:x:0:0:root:/root:/bin/bash",
            },
            decoded_data="root:x:0:0:root:/root:/bin/bash",
        )
        oob_listener.wait_for_callback.return_value = callback
        
        # Create tester
        tester = XXETester(
            request_handler=request_handler,
            oob_listener=oob_listener,
        )
        
        # Test for OOB HTTP XXE
        results = await tester.test_injection_point(
            injection_point,
            techniques=[XXEType.BLIND_OOB_HTTP],
            target_files=["/etc/passwd"],
        )
        
        # Verify results
        assert len(results) > 0
        result = results[0]
        assert result.is_vulnerable
        assert result.xxe_type == XXEType.BLIND_OOB_HTTP
        assert result.target_file == "/etc/passwd"
        assert result.oob_callback_id == "callback-123"
        assert "root:x:0:0" in result.exfiltrated_data
        assert result.confidence >= 0.9
        
        # Verify OOB listener was called correctly
        oob_listener.register_payload.assert_called_once()
        oob_listener.wait_for_callback.assert_called_once_with("test-unique-id-123", timeout=15.0)
    
    @pytest.mark.asyncio
    async def test_oob_http_xxe_no_callback(self, request_handler, oob_listener, injection_point):
        """Test blind XXE when no OOB callback received"""
        # Create mock request
        mock_request = Request(
            method="POST",
            url="https://example.com/api/parse",
        )
        
        # Mock normal response
        normal_response = Response(
            status_code=200,
            headers={},
            body=b"<response>OK</response>",
            text="<response>OK</response>",
            elapsed_time=0.1,
            request=mock_request,
        )
        request_handler.send_request.return_value = normal_response
        
        # No callback received (timeout)
        oob_listener.wait_for_callback.return_value = None
        
        # Create tester
        tester = XXETester(
            request_handler=request_handler,
            oob_listener=oob_listener,
        )
        
        # Test for OOB HTTP XXE
        results = await tester.test_injection_point(
            injection_point,
            techniques=[XXEType.BLIND_OOB_HTTP],
            target_files=["/etc/passwd"],
        )
        
        # Verify not vulnerable
        assert len(results) > 0
        result = results[0]
        assert not result.is_vulnerable
        assert result.confidence == 0.0
    
    @pytest.mark.asyncio
    async def test_oob_dns_xxe_detection(self, request_handler, oob_listener, injection_point):
        """Test blind XXE with DNS OOB callbacks"""
        # Create mock request
        mock_request = Request(
            method="POST",
            url="https://example.com/api/parse",
        )
        
        # Mock normal response
        normal_response = Response(
            status_code=200,
            headers={},
            body=b"<response>OK</response>",
            text="<response>OK</response>",
            elapsed_time=0.1,
            request=mock_request,
        )
        request_handler.send_request.return_value = normal_response
        
        # Mock DNS callback
        callback = Callback(
            callback_id="callback-456",
            unique_id="test-unique-id-123",
            callback_type="dns",
            source_ip="192.168.1.100",
            timestamp=datetime.now(timezone.utc),
            data={
                "query": "test-unique-id-123.attacker.com",
                "query_type": "A",
            },
        )
        oob_listener.wait_for_callback.return_value = callback
        
        # Create tester
        tester = XXETester(
            request_handler=request_handler,
            oob_listener=oob_listener,
        )
        
        # Test for OOB DNS XXE
        results = await tester.test_injection_point(
            injection_point,
            techniques=[XXEType.BLIND_OOB_DNS],
            target_files=["/etc/hostname"],
        )
        
        # Verify results
        assert len(results) > 0
        result = results[0]
        assert result.is_vulnerable
        assert result.xxe_type == XXEType.BLIND_OOB_DNS
        assert result.target_file == "/etc/hostname"
        assert result.oob_callback_id == "callback-456"
        assert result.confidence >= 0.9
    
    def test_generate_direct_xxe_payload(self, request_handler):
        """Test direct XXE payload generation"""
        tester = XXETester(request_handler=request_handler)
        
        payload = tester._generate_direct_xxe_payload("/etc/passwd")
        
        assert "<?xml version" in payload
        assert "<!DOCTYPE" in payload
        assert "<!ENTITY xxe SYSTEM" in payload
        assert "file:///etc/passwd" in payload
        assert "&xxe;" in payload
    
    def test_generate_error_based_xxe_payload(self, request_handler):
        """Test error-based XXE payload generation"""
        tester = XXETester(request_handler=request_handler)
        
        payload = tester._generate_error_based_xxe_payload("/etc/passwd")
        
        assert "<?xml version" in payload
        assert "<!DOCTYPE" in payload
        assert "<!ENTITY % file SYSTEM" in payload
        assert "file:///etc/passwd" in payload
        assert "%eval;" in payload
    
    def test_generate_oob_http_xxe_payload(self, request_handler, oob_listener):
        """Test OOB HTTP XXE payload generation"""
        # Mock the callback URL to return expected value
        oob_listener.get_callback_url = Mock(return_value="http://attacker.com:8080/unique-123")
        
        tester = XXETester(
            request_handler=request_handler,
            oob_listener=oob_listener,
        )
        
        payload = tester._generate_oob_http_xxe_payload("unique-123", "/etc/passwd")
        
        assert "<?xml version" in payload
        assert "<!DOCTYPE" in payload
        assert "<!ENTITY % xxe SYSTEM" in payload
        assert "http://attacker.com:8080/unique-123/xxe.dtd" in payload
        assert "%xxe;" in payload
    
    def test_generate_oob_dns_xxe_payload(self, request_handler, oob_listener):
        """Test OOB DNS XXE payload generation"""
        # Mock the DNS callback to return expected value
        oob_listener.get_dns_callback = Mock(return_value="unique-123.attacker.com")
        
        tester = XXETester(
            request_handler=request_handler,
            oob_listener=oob_listener,
        )
        
        payload = tester._generate_oob_dns_xxe_payload("unique-123", "/etc/passwd")
        
        assert "<?xml version" in payload
        assert "<!DOCTYPE" in payload
        assert "<!ENTITY % file SYSTEM" in payload
        assert "file:///etc/passwd" in payload
        assert "unique-123.attacker.com" in payload
    
    def test_detect_xxe_output_with_passwd_content(self, request_handler):
        """Test XXE output detection with /etc/passwd content"""
        tester = XXETester(request_handler=request_handler)
        
        response_text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        baseline_text = "<response>OK</response>"
        
        is_xxe, exfiltrated_data = tester._detect_xxe_output(
            response_text, baseline_text, "/etc/passwd"
        )
        
        assert is_xxe
        assert exfiltrated_data is not None
        assert "root:x:0:0" in exfiltrated_data
    
    def test_detect_xxe_output_no_indicators(self, request_handler):
        """Test XXE output detection with no indicators"""
        tester = XXETester(request_handler=request_handler)
        
        response_text = "<response>OK</response>"
        baseline_text = "<response>OK</response>"
        
        is_xxe, exfiltrated_data = tester._detect_xxe_output(
            response_text, baseline_text, "/etc/passwd"
        )
        
        assert not is_xxe
        assert exfiltrated_data is None


class TestXXEPoCGenerator:
    """Tests for XXEPoCGenerator class"""
    
    def test_generate_direct_poc(self):
        """Test direct XXE PoC generation"""
        # Create mock result
        injection_point = InjectionPoint(
            parameter="xml",
            location="body",
            original_value="<root>test</root>",
            url="https://example.com/api/parse",
            method="POST",
            headers={"Content-Type": "application/xml"},
        )
        
        result = XXEResult(
            injection_point=injection_point,
            is_vulnerable=True,
            xxe_type=XXEType.DIRECT,
            payload="test payload",
            target_file="/etc/passwd",
        )
        
        # Generate PoC
        generator = XXEPoCGenerator(result)
        poc = generator.generate_poc("/etc/shadow")
        
        assert "<?xml version" in poc
        assert "<!DOCTYPE" in poc
        assert "<!ENTITY xxe SYSTEM" in poc
        assert "file:///etc/shadow" in poc
    
    def test_generate_error_based_poc(self):
        """Test error-based XXE PoC generation"""
        injection_point = InjectionPoint(
            parameter="xml",
            location="body",
            original_value="<root>test</root>",
            url="https://example.com/api/parse",
            method="POST",
        )
        
        result = XXEResult(
            injection_point=injection_point,
            is_vulnerable=True,
            xxe_type=XXEType.ERROR_BASED,
            payload="test payload",
            target_file="/etc/passwd",
        )
        
        generator = XXEPoCGenerator(result)
        poc = generator.generate_poc()
        
        assert "<?xml version" in poc
        assert "<!ENTITY % file SYSTEM" in poc
        assert "file:///etc/passwd" in poc
        assert "%eval;" in poc
    
    def test_generate_oob_poc(self):
        """Test OOB XXE PoC generation"""
        injection_point = InjectionPoint(
            parameter="xml",
            location="body",
            original_value="<root>test</root>",
            url="https://example.com/api/parse",
            method="POST",
        )
        
        result = XXEResult(
            injection_point=injection_point,
            is_vulnerable=True,
            xxe_type=XXEType.BLIND_OOB_HTTP,
            payload="test payload",
            target_file="/etc/passwd",
        )
        
        generator = XXEPoCGenerator(result)
        poc = generator.generate_poc()
        
        assert "XXE OOB Proof of Concept" in poc
        assert "xxe.dtd" in poc
        assert "YOUR_SERVER" in poc
    
    def test_generate_curl_command(self):
        """Test curl command generation"""
        injection_point = InjectionPoint(
            parameter="xml",
            location="body",
            original_value="<root>test</root>",
            url="https://example.com/api/parse",
            method="POST",
            headers={"Content-Type": "application/xml"},
        )
        
        result = XXEResult(
            injection_point=injection_point,
            is_vulnerable=True,
            xxe_type=XXEType.DIRECT,
            payload="<?xml version='1.0'?><test/>",
            target_file="/etc/passwd",
        )
        
        generator = XXEPoCGenerator(result)
        curl_cmd = generator.generate_curl_command()
        
        assert "curl" in curl_cmd
        assert "-X POST" in curl_cmd
        assert "Content-Type: application/xml" in curl_cmd
        assert "https://example.com/api/parse" in curl_cmd
    
    def test_generate_python_script(self):
        """Test Python script generation"""
        injection_point = InjectionPoint(
            parameter="xml",
            location="body",
            original_value="<root>test</root>",
            url="https://example.com/api/parse",
            method="POST",
            headers={"Content-Type": "application/xml"},
        )
        
        result = XXEResult(
            injection_point=injection_point,
            is_vulnerable=True,
            xxe_type=XXEType.DIRECT,
            payload="<?xml version='1.0'?><test/>",
            target_file="/etc/passwd",
        )
        
        generator = XXEPoCGenerator(result)
        script = generator.generate_python_script()
        
        assert "#!/usr/bin/env python3" in script
        assert "import requests" in script
        assert "https://example.com/api/parse" in script
        assert "Content-Type" in script
        assert "requests.post" in script
