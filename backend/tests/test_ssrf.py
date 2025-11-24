"""Tests for SSRF module"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch

from app.modules.ssrf import (
    SSRFTester,
    SSRFExploiter,
    InjectionPoint,
    SSRFResult,
    SSRFType,
    CloudProvider,
    CloudMetadataResult,
    PortScanResult,
)
from app.core.request_handler import RequestHandler, Response
from app.core.http_models import Request
from app.core.oob_listener import OOBListener, Callback
from datetime import datetime, timezone


@pytest.fixture
def request_handler():
    """Create mock request handler"""
    handler = Mock(spec=RequestHandler)
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def oob_listener():
    """Create mock OOB listener"""
    listener = Mock(spec=OOBListener)
    listener.generate_unique_id = Mock(return_value="test-unique-id")
    listener.get_callback_url = Mock(return_value="http://oob.example.com/test-unique-id")
    listener.get_dns_callback = Mock(return_value="test-unique-id.oob.example.com")
    listener.wait_for_callback = AsyncMock(return_value=None)
    listener.register_payload = AsyncMock()
    return listener


@pytest.fixture
def injection_point():
    """Create test injection point"""
    return InjectionPoint(
        parameter="url",
        location="query",
        original_value="https://example.com",
        url="http://target.com/fetch",
        method="GET",
        headers={"User-Agent": "Test"},
    )


@pytest.fixture
def ssrf_tester(request_handler):
    """Create SSRF tester instance"""
    return SSRFTester(request_handler)


class TestSSRFTester:
    """Tests for SSRFTester class"""
    
    @pytest.mark.asyncio
    async def test_initialization(self, request_handler):
        """Test SSRF tester initialization"""
        tester = SSRFTester(request_handler)
        
        assert tester.request_handler == request_handler
        assert tester.payload_engine is not None
        assert tester.oob_listener is None
    
    @pytest.mark.asyncio
    async def test_initialization_with_oob(self, request_handler, oob_listener):
        """Test SSRF tester initialization with OOB listener"""
        tester = SSRFTester(request_handler, oob_listener=oob_listener)
        
        assert tester.oob_listener == oob_listener
    
    @pytest.mark.asyncio
    async def test_generate_localhost_bypasses(self, ssrf_tester):
        """Test localhost bypass payload generation"""
        bypasses = ssrf_tester._generate_localhost_bypasses()
        
        # Should generate multiple bypass techniques
        assert len(bypasses) > 10
        
        # Check for specific bypass types
        bypass_techniques = [technique for _, technique in bypasses]
        assert "basic_localhost" in bypass_techniques
        assert "ipv6_localhost" in bypass_techniques
        assert "decimal_ip" in bypass_techniques
        assert "hex_ip" in bypass_techniques
        assert "url_encoded" in bypass_techniques
    
    @pytest.mark.asyncio
    async def test_detect_ssrf_indicators_positive(self, ssrf_tester):
        """Test SSRF indicator detection with positive case"""
        response_text = "<title>Apache Server at localhost</title>"
        baseline_text = "Normal response"
        
        is_ssrf, evidence = ssrf_tester._detect_ssrf_indicators(
            response_text,
            baseline_text,
            len(response_text),
            len(baseline_text),
        )
        
        assert is_ssrf is True
        assert len(evidence) > 0
        assert any("Internal service indicator" in e for e in evidence)
    
    @pytest.mark.asyncio
    async def test_detect_ssrf_indicators_negative(self, ssrf_tester):
        """Test SSRF indicator detection with negative case"""
        response_text = "Normal response"
        baseline_text = "Normal response"
        
        is_ssrf, evidence = ssrf_tester._detect_ssrf_indicators(
            response_text,
            baseline_text,
            len(response_text),
            len(baseline_text),
        )
        
        assert is_ssrf is False
        assert len(evidence) == 0
    
    @pytest.mark.asyncio
    async def test_test_direct_ssrf_vulnerable(
        self, ssrf_tester, injection_point, request_handler
    ):
        """Test direct SSRF detection with vulnerable target"""
        # Mock responses
        baseline_response = Response(
            status_code=200,
            headers={},
            body=b"Normal response",
            text="Normal response",
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        
        ssrf_response = Response(
            status_code=200,
            headers={},
            body=b"<title>Apache Server at localhost</title>",
            text="<title>Apache Server at localhost</title>",
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        
        request_handler.send_request.side_effect = [
            baseline_response,
            ssrf_response,
        ]
        
        # Test
        result = await ssrf_tester._test_direct_ssrf(injection_point)
        
        assert result is not None
        assert result.is_vulnerable is True
        assert result.ssrf_type == SSRFType.DIRECT
        assert result.confidence > 0.8
        assert result.bypass_technique is not None
    
    @pytest.mark.asyncio
    async def test_test_direct_ssrf_not_vulnerable(
        self, ssrf_tester, injection_point, request_handler
    ):
        """Test direct SSRF detection with non-vulnerable target"""
        # Mock same response for all requests
        normal_response = Response(
            status_code=200,
            headers={},
            body=b"Normal response",
            text="Normal response",
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        
        request_handler.send_request.return_value = normal_response
        
        # Test
        result = await ssrf_tester._test_direct_ssrf(injection_point)
        
        assert result is not None
        assert result.is_vulnerable is False
        assert result.confidence == 0.0
    
    @pytest.mark.asyncio
    async def test_identify_service_by_port(self, ssrf_tester):
        """Test service identification by port number"""
        service = ssrf_tester._identify_service("", 3306)
        assert service == "MySQL"
        
        service = ssrf_tester._identify_service("", 6379)
        assert service == "Redis"
        
        service = ssrf_tester._identify_service("", 22)
        assert service == "SSH"
    
    @pytest.mark.asyncio
    async def test_identify_service_by_content(self, ssrf_tester):
        """Test service identification by response content"""
        service = ssrf_tester._identify_service("SSH-2.0-OpenSSH_7.4", 22)
        assert service == "SSH"
        
        service = ssrf_tester._identify_service("220 FTP Server ready", 21)
        assert service == "FTP"
        
        service = ssrf_tester._identify_service("<html><body>Test</body></html>", 8080)
        assert service == "HTTP"
    
    @pytest.mark.asyncio
    async def test_get_cloud_metadata_headers(self, ssrf_tester):
        """Test cloud metadata header generation"""
        # Azure requires Metadata header
        headers = ssrf_tester._get_cloud_metadata_headers(CloudProvider.AZURE)
        assert "Metadata" in headers
        assert headers["Metadata"] == "true"
        
        # GCP requires Metadata-Flavor header
        headers = ssrf_tester._get_cloud_metadata_headers(CloudProvider.GCP)
        assert "Metadata-Flavor" in headers
        assert headers["Metadata-Flavor"] == "Google"
        
        # AWS doesn't require special headers
        headers = ssrf_tester._get_cloud_metadata_headers(CloudProvider.AWS)
        assert len(headers) == 0
    
    @pytest.mark.asyncio
    async def test_is_metadata_accessible_aws(self, ssrf_tester):
        """Test AWS metadata accessibility detection"""
        response = Response(
            status_code=200,
            headers={},
            body=b'{"instance-id": "i-1234567890abcdef0"}',
            text='{"instance-id": "i-1234567890abcdef0"}',
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        
        is_accessible = ssrf_tester._is_metadata_accessible(
            response, CloudProvider.AWS
        )
        
        assert is_accessible is True
    
    @pytest.mark.asyncio
    async def test_is_metadata_accessible_azure(self, ssrf_tester):
        """Test Azure metadata accessibility detection"""
        response = Response(
            status_code=200,
            headers={},
            body=b'{"compute": {"vmId": "12345"}}',
            text='{"compute": {"vmId": "12345"}}',
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        
        is_accessible = ssrf_tester._is_metadata_accessible(
            response, CloudProvider.AZURE
        )
        
        assert is_accessible is True
    
    @pytest.mark.asyncio
    async def test_is_metadata_accessible_gcp(self, ssrf_tester):
        """Test GCP metadata accessibility detection"""
        response = Response(
            status_code=200,
            headers={},
            body=b'{"project-id": "my-project"}',
            text='{"project-id": "my-project"}',
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        
        is_accessible = ssrf_tester._is_metadata_accessible(
            response, CloudProvider.GCP
        )
        
        assert is_accessible is True
    
    @pytest.mark.asyncio
    async def test_extract_credentials_aws(self, ssrf_tester):
        """Test AWS credential extraction"""
        data = '''
        {
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "Token": "AQoDYXdzEJr..."
        }
        '''
        
        credentials = ssrf_tester._extract_credentials(data, CloudProvider.AWS)
        
        assert credentials is not None
        assert "access_key_id" in credentials
        assert credentials["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
        assert "secret_access_key" in credentials
        assert "token" in credentials
    
    @pytest.mark.asyncio
    async def test_extract_credentials_azure(self, ssrf_tester):
        """Test Azure credential extraction"""
        data = '''
        {
            "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
        }
        '''
        
        credentials = ssrf_tester._extract_credentials(data, CloudProvider.AZURE)
        
        assert credentials is not None
        assert "access_token" in credentials
        assert credentials["access_token"].startswith("eyJ0eXAi")
    
    @pytest.mark.asyncio
    async def test_extract_credentials_gcp(self, ssrf_tester):
        """Test GCP credential extraction"""
        data = '''
        {
            "access_token": "ya29.c.Kl6iB..."
        }
        '''
        
        credentials = ssrf_tester._extract_credentials(data, CloudProvider.GCP)
        
        assert credentials is not None
        assert "access_token" in credentials
        assert credentials["access_token"].startswith("ya29")
    
    @pytest.mark.asyncio
    async def test_test_oob_blind_vulnerable(
        self, ssrf_tester, injection_point, request_handler, oob_listener
    ):
        """Test OOB blind SSRF detection with vulnerable target"""
        # Set OOB listener
        ssrf_tester.oob_listener = oob_listener
        
        # Mock callback
        callback = Callback(
            callback_id="callback-123",
            unique_id="test-unique-id",
            callback_type="http",
            source_ip="192.168.1.100",
            timestamp=datetime.now(timezone.utc),
            data={"method": "GET", "path": "/test-unique-id"},
        )
        
        oob_listener.wait_for_callback.return_value = callback
        
        # Mock response
        response = Response(
            status_code=200,
            headers={},
            body=b"OK",
            text="OK",
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        request_handler.send_request.return_value = response
        
        # Test
        result = await ssrf_tester._test_oob_blind(injection_point)
        
        assert result is not None
        assert result.is_vulnerable is True
        assert result.ssrf_type == SSRFType.BLIND_OOB
        assert result.confidence > 0.9
        assert "OOB callback received" in result.evidence[0]


class TestSSRFExploiter:
    """Tests for SSRFExploiter class"""
    
    @pytest.fixture
    def ssrf_result(self, injection_point):
        """Create test SSRF result"""
        return SSRFResult(
            injection_point=injection_point,
            is_vulnerable=True,
            ssrf_type=SSRFType.DIRECT,
            target_url="http://127.0.0.1",
            payload="http://127.0.0.1",
            confidence=0.95,
            bypass_technique="basic_localhost",
        )
    
    @pytest.fixture
    def exploiter(self, request_handler, injection_point, ssrf_result):
        """Create SSRF exploiter instance"""
        return SSRFExploiter(request_handler, injection_point, ssrf_result)
    
    def test_initialization(self, exploiter, request_handler, injection_point, ssrf_result):
        """Test SSRF exploiter initialization"""
        assert exploiter.request_handler == request_handler
        assert exploiter.injection_point == injection_point
        assert exploiter.ssrf_result == ssrf_result
        assert exploiter.tester is not None
    
    @pytest.mark.asyncio
    async def test_read_file(self, exploiter, request_handler):
        """Test file reading via SSRF"""
        # Mock response with file content
        file_content = "root:x:0:0:root:/root:/bin/bash\n"
        response = Response(
            status_code=200,
            headers={},
            body=file_content.encode(),
            text=file_content,
            elapsed_time=0.1,
            request=Mock(),
            history=[],
        )
        request_handler.send_request.return_value = response
        
        # Test
        content = await exploiter.read_file("/etc/passwd")
        
        assert content is not None
        assert "root" in content
        assert "/bin/bash" in content


class TestPortScanResult:
    """Tests for PortScanResult dataclass"""
    
    def test_port_scan_result_creation(self):
        """Test PortScanResult creation"""
        result = PortScanResult(
            host="127.0.0.1",
            port=80,
            is_open=True,
            service="HTTP",
            response_time=0.1,
            banner="Apache/2.4.41",
        )
        
        assert result.host == "127.0.0.1"
        assert result.port == 80
        assert result.is_open is True
        assert result.service == "HTTP"
        assert result.response_time == 0.1
        assert result.banner == "Apache/2.4.41"


class TestCloudMetadataResult:
    """Tests for CloudMetadataResult dataclass"""
    
    def test_cloud_metadata_result_creation(self):
        """Test CloudMetadataResult creation"""
        result = CloudMetadataResult(
            provider=CloudProvider.AWS,
            endpoint="http://169.254.169.254/latest/meta-data/",
            accessible=True,
            data='{"instance-id": "i-1234567890abcdef0"}',
            credentials={"access_key_id": "AKIAIOSFODNN7EXAMPLE"},
            resources=["s3://my-bucket", "ec2://i-1234567890abcdef0"],
        )
        
        assert result.provider == CloudProvider.AWS
        assert result.accessible is True
        assert result.credentials is not None
        assert len(result.resources) == 2


class TestInjectionPoint:
    """Tests for InjectionPoint dataclass"""
    
    def test_injection_point_creation(self):
        """Test InjectionPoint creation"""
        point = InjectionPoint(
            parameter="url",
            location="query",
            original_value="https://example.com",
            url="http://target.com/fetch",
            method="GET",
            headers={"User-Agent": "Test"},
            data=None,
        )
        
        assert point.parameter == "url"
        assert point.location == "query"
        assert point.original_value == "https://example.com"
        assert point.url == "http://target.com/fetch"
        assert point.method == "GET"
        assert "User-Agent" in point.headers


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
