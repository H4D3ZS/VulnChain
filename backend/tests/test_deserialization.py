"""Tests for deserialization exploitation module"""

import pytest
import base64
from unittest.mock import Mock, AsyncMock, patch

from app.modules.deserialization import (
    SerializedDataDetector,
    YsoserialIntegration,
    PhpggcIntegration,
    DeserializationTester,
    DependencyAnalyzer,
    InteractiveShell,
    SerializationFormat,
    ProgrammingLanguage,
    SerializedDataInfo,
    GadgetChain,
)
from app.core.request_handler import Response
from app.models.target import TargetConfig


class TestSerializedDataDetector:
    """Tests for SerializedDataDetector"""
    
    def test_detect_java_serialization(self):
        """Test detection of Java serialization"""
        detector = SerializedDataDetector()
        
        # Java magic bytes
        java_data = b'\xac\xed\x00\x05'
        result = detector.detect_serialized_data(
            java_data,
            location="cookie",
            parameter="session"
        )
        
        assert result is not None
        assert result.format == SerializationFormat.JAVA_SERIALIZED
        assert result.language == ProgrammingLanguage.JAVA
        assert result.confidence >= 0.9
        assert "Java magic bytes" in result.indicators[0]
    
    def test_detect_php_serialization(self):
        """Test detection of PHP serialization"""
        detector = SerializedDataDetector()
        
        # PHP object serialization
        php_data = b'O:8:"stdClass":1:{s:4:"name";s:5:"admin";}'
        result = detector.detect_serialized_data(
            php_data,
            location="post",
            parameter="data"
        )
        
        assert result is not None
        assert result.format == SerializationFormat.PHP_SERIALIZED
        assert result.language == ProgrammingLanguage.PHP
        assert result.confidence >= 0.9
        assert len(result.indicators) > 0
    
    def test_detect_python_pickle(self):
        """Test detection of Python pickle"""
        detector = SerializedDataDetector()
        
        # Python pickle protocol 3
        pickle_data = b'\x80\x03}q\x00.'
        result = detector.detect_serialized_data(
            pickle_data,
            location="header",
            parameter="X-Session"
        )
        
        assert result is not None
        assert result.format == SerializationFormat.PYTHON_PICKLE
        assert result.language == ProgrammingLanguage.PYTHON
        assert result.confidence >= 0.9
    
    def test_detect_base64_encoded_java(self):
        """Test detection of base64-encoded Java serialization"""
        detector = SerializedDataDetector()
        
        # Base64-encoded Java magic bytes
        java_data = b'\xac\xed\x00\x05'
        encoded = base64.b64encode(java_data)
        
        result = detector.detect_serialized_data(
            encoded,
            location="cookie",
            parameter="session"
        )
        
        assert result is not None
        assert result.format == SerializationFormat.JAVA_SERIALIZED
        assert result.language == ProgrammingLanguage.JAVA
    
    def test_no_detection_for_normal_data(self):
        """Test that normal data is not detected as serialized"""
        detector = SerializedDataDetector()
        
        normal_data = b'Hello, World!'
        result = detector.detect_serialized_data(
            normal_data,
            location="post",
            parameter="message"
        )
        
        assert result is None


class TestYsoserialIntegration:
    """Tests for YsoserialIntegration"""
    
    def test_get_available_chains(self):
        """Test getting available gadget chains"""
        ysoserial = YsoserialIntegration()
        chains = ysoserial.get_available_chains()
        
        assert len(chains) > 0
        assert "CommonsCollections1" in chains
        assert "Spring1" in chains
    
    def test_is_available_without_tool(self):
        """Test availability check when tool is not installed"""
        ysoserial = YsoserialIntegration(ysoserial_path="/nonexistent/path")
        assert not ysoserial.is_available()


class TestPhpggcIntegration:
    """Tests for PhpggcIntegration"""
    
    def test_get_available_chains(self):
        """Test getting available gadget chains"""
        # Create with non-existent path to ensure we get default chains
        phpggc = PhpggcIntegration(phpggc_path="/nonexistent/path")
        chains = phpggc.get_available_chains()
        
        # When tool is not available, should return empty list
        # (get_available_chains checks availability first)
        assert isinstance(chains, list)
        
        # Test that default chains are defined in the class
        assert len(PhpggcIntegration.GADGET_CHAINS) > 0
        assert any("Laravel" in chain for chain in PhpggcIntegration.GADGET_CHAINS)
        assert any("Symfony" in chain for chain in PhpggcIntegration.GADGET_CHAINS)
    
    def test_is_available_without_tool(self):
        """Test availability check when tool is not installed"""
        phpggc = PhpggcIntegration(phpggc_path="/nonexistent/path")
        assert not phpggc.is_available()


class TestDependencyAnalyzer:
    """Tests for DependencyAnalyzer"""
    
    def test_analyze_java_dependencies(self):
        """Test analysis of Java dependencies"""
        analyzer = DependencyAnalyzer()
        
        dependencies = [
            "org.apache.commons:commons-collections:3.2.1",
            "org.springframework:spring-core:4.1.4",
        ]
        
        exploitable = analyzer.analyze_dependencies(
            ProgrammingLanguage.JAVA,
            dependencies
        )
        
        assert len(exploitable) == 2
        assert exploitable[0]["artifact_id"] == "commons-collections"
        assert "CommonsCollections" in exploitable[0]["gadget_chains"][0]
        assert exploitable[0]["is_vulnerable_version"]
    
    def test_analyze_php_dependencies(self):
        """Test analysis of PHP dependencies"""
        analyzer = DependencyAnalyzer()
        
        dependencies = [
            "laravel/framework:5.8.0",
            "symfony/symfony:4.1.0",
        ]
        
        exploitable = analyzer.analyze_dependencies(
            ProgrammingLanguage.PHP,
            dependencies
        )
        
        assert len(exploitable) == 2
        assert "laravel/framework" in exploitable[0]["package"]
        assert "Laravel" in exploitable[0]["gadget_chains"][0]
        assert exploitable[0]["is_vulnerable_version"]
    
    def test_suggest_gadget_chains(self):
        """Test gadget chain suggestions"""
        analyzer = DependencyAnalyzer()
        
        dependencies = [
            "org.apache.commons:commons-collections:3.2.1",
        ]
        
        suggested = analyzer.suggest_gadget_chains(
            ProgrammingLanguage.JAVA,
            dependencies
        )
        
        assert len(suggested) > 0
        assert "CommonsCollections1" in suggested
    
    def test_extract_version(self):
        """Test version extraction"""
        analyzer = DependencyAnalyzer()
        
        # Test various version formats
        assert analyzer._extract_version("Apache/2.4.41") == "2.4.41"
        assert analyzer._extract_version("PHP/7.4.3") == "7.4.3"
        assert analyzer._extract_version("v1.2.3") == "1.2.3"
        assert analyzer._extract_version("no version") == "unknown"


@pytest.mark.asyncio
class TestDeserializationTester:
    """Tests for DeserializationTester"""
    
    async def test_scan_for_serialized_data(self):
        """Test scanning response for serialized data"""
        request_handler = Mock()
        tester = DeserializationTester(request_handler)
        
        # Create mock response with Java serialization in cookie
        # Use a real dict for cookies to ensure .items() works
        cookies_dict = {
            "session": base64.b64encode(b'\xac\xed\x00\x05').decode('utf-8')
        }
        
        response = Mock(spec=Response)
        response.body = b'Normal response body'
        response.cookies = cookies_dict
        response.headers = {}
        
        target = TargetConfig(url="https://example.com")
        detected = await tester.scan_for_serialized_data(target, response)
        
        assert len(detected) > 0
        assert detected[0].format == SerializationFormat.JAVA_SERIALIZED
        assert detected[0].location == "cookie"
        assert detected[0].parameter == "session"


@pytest.mark.asyncio
class TestInteractiveShell:
    """Tests for InteractiveShell"""
    
    async def test_execute_command_structure(self):
        """Test command execution structure"""
        request_handler = AsyncMock()
        target = TargetConfig(url="https://example.com")
        
        serialized_data_info = SerializedDataInfo(
            format=SerializationFormat.JAVA_SERIALIZED,
            language=ProgrammingLanguage.JAVA,
            data=b'\xac\xed\x00\x05',
            location="cookie",
            parameter="session",
            confidence=0.95,
        )
        
        gadget_chain = GadgetChain(
            name="CommonsCollections1",
            tool="ysoserial",
            language=ProgrammingLanguage.JAVA,
            command="whoami",
            description="Test chain",
        )
        
        # Mock response
        mock_response = Mock(spec=Response)
        mock_response.status_code = 200
        mock_response.text = "root"
        mock_response.body = b"root"
        request_handler.send_request.return_value = mock_response
        
        shell = InteractiveShell(
            request_handler,
            target,
            serialized_data_info,
            gadget_chain,
        )
        
        # Test that shell is created properly
        assert shell.target == target
        assert shell.serialized_data_info == serialized_data_info
        assert shell.gadget_chain == gadget_chain


def test_serialization_format_enum():
    """Test SerializationFormat enum"""
    assert SerializationFormat.JAVA_SERIALIZED.value == "java_serialized"
    assert SerializationFormat.PHP_SERIALIZED.value == "php_serialized"
    assert SerializationFormat.PYTHON_PICKLE.value == "python_pickle"


def test_programming_language_enum():
    """Test ProgrammingLanguage enum"""
    assert ProgrammingLanguage.JAVA.value == "java"
    assert ProgrammingLanguage.PHP.value == "php"
    assert ProgrammingLanguage.PYTHON.value == "python"
