"""Tests for WebSocket and SSE module"""

import asyncio
import json
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock

from app.modules.websocket_sse import (
    WebSocketTester,
    SSETester,
    MessageAnalyzer,
    WebSocketClient,
    WebSocketMessage,
    SSEMessage,
    MessageType,
    VulnerabilityType,
)
from app.core.request_handler import RequestHandler, Response


@pytest.fixture
def request_handler():
    """Create a mock request handler"""
    handler = Mock(spec=RequestHandler)
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def websocket_tester(request_handler):
    """Create WebSocket tester instance"""
    return WebSocketTester(request_handler)


@pytest.fixture
def sse_tester(request_handler):
    """Create SSE tester instance"""
    return SSETester(request_handler)


@pytest.fixture
def message_analyzer():
    """Create message analyzer instance"""
    return MessageAnalyzer()


class TestMessageType:
    """Test MessageType enum"""
    
    def test_message_types_exist(self):
        """Test that all message types are defined"""
        assert MessageType.TEXT
        assert MessageType.BINARY
        assert MessageType.JSON
        assert MessageType.XML
        assert MessageType.UNKNOWN


class TestVulnerabilityType:
    """Test VulnerabilityType enum"""
    
    def test_vulnerability_types_exist(self):
        """Test that all vulnerability types are defined"""
        assert VulnerabilityType.AUTH_BYPASS
        assert VulnerabilityType.MESSAGE_INJECTION
        assert VulnerabilityType.XSS
        assert VulnerabilityType.SQLI
        assert VulnerabilityType.COMMAND_INJECTION
        assert VulnerabilityType.CSWSH
        assert VulnerabilityType.SSE_INJECTION


class TestWebSocketMessage:
    """Test WebSocketMessage dataclass"""
    
    def test_create_message(self):
        """Test creating a WebSocket message"""
        msg = WebSocketMessage(
            message_id="msg_1",
            direction="sent",
            message_type=MessageType.JSON,
            content='{"test": "data"}',
            timestamp=1234567890.0,
        )
        
        assert msg.message_id == "msg_1"
        assert msg.direction == "sent"
        assert msg.message_type == MessageType.JSON
        assert msg.content == '{"test": "data"}'
        assert msg.timestamp == 1234567890.0


class TestSSEMessage:
    """Test SSEMessage dataclass"""
    
    def test_create_sse_message(self):
        """Test creating an SSE message"""
        msg = SSEMessage(
            event_type="message",
            data="test data",
            event_id="123",
            retry=3000,
            timestamp=1234567890.0,
        )
        
        assert msg.event_type == "message"
        assert msg.data == "test data"
        assert msg.event_id == "123"
        assert msg.retry == 3000


class TestWebSocketTester:
    """Test WebSocketTester class"""
    
    def test_initialization(self, request_handler):
        """Test WebSocket tester initialization"""
        tester = WebSocketTester(request_handler)
        assert tester.request_handler == request_handler
        assert tester.message_history == []
        assert tester.message_counter == 0
    
    def test_detect_message_type_json(self, websocket_tester):
        """Test JSON message type detection"""
        message = '{"test": "data"}'
        msg_type = websocket_tester._detect_message_type(message)
        assert msg_type == MessageType.JSON
    
    def test_detect_message_type_xml(self, websocket_tester):
        """Test XML message type detection"""
        message = '<root><test>data</test></root>'
        msg_type = websocket_tester._detect_message_type(message)
        assert msg_type == MessageType.XML
    
    def test_detect_message_type_text(self, websocket_tester):
        """Test text message type detection"""
        message = 'plain text message'
        msg_type = websocket_tester._detect_message_type(message)
        assert msg_type == MessageType.TEXT
    
    def test_detect_message_type_binary(self, websocket_tester):
        """Test binary message type detection"""
        message = b'binary data'
        msg_type = websocket_tester._detect_message_type(message)
        assert msg_type == MessageType.BINARY
    
    def test_get_message_id(self, websocket_tester):
        """Test message ID generation"""
        msg_id_1 = websocket_tester._get_message_id()
        msg_id_2 = websocket_tester._get_message_id()
        
        assert msg_id_1 != msg_id_2
        assert msg_id_1.startswith("msg_1_")
        assert msg_id_2.startswith("msg_2_")
    
    def test_xss_payloads_defined(self, websocket_tester):
        """Test that XSS payloads are defined"""
        assert len(websocket_tester.XSS_PAYLOADS) > 0
        assert any("script" in payload.lower() for payload in websocket_tester.XSS_PAYLOADS)
    
    def test_sqli_payloads_defined(self, websocket_tester):
        """Test that SQL injection payloads are defined"""
        assert len(websocket_tester.SQLI_PAYLOADS) > 0
        assert any("or" in payload.lower() for payload in websocket_tester.SQLI_PAYLOADS)
    
    def test_cmd_payloads_defined(self, websocket_tester):
        """Test that command injection payloads are defined"""
        assert len(websocket_tester.CMD_PAYLOADS) > 0
        assert any(";" in payload or "|" in payload for payload in websocket_tester.CMD_PAYLOADS)


class TestSSETester:
    """Test SSETester class"""
    
    def test_initialization(self, request_handler):
        """Test SSE tester initialization"""
        tester = SSETester(request_handler)
        assert tester.request_handler == request_handler
    
    def test_parse_sse_stream_simple(self, sse_tester):
        """Test parsing simple SSE stream"""
        stream_data = "data: test message\n\n"
        events = sse_tester._parse_sse_stream(stream_data)
        
        assert len(events) == 1
        assert events[0].data == "test message"
        assert events[0].event_type is None
    
    def test_parse_sse_stream_with_event_type(self, sse_tester):
        """Test parsing SSE stream with event type"""
        stream_data = "event: custom\ndata: test message\n\n"
        events = sse_tester._parse_sse_stream(stream_data)
        
        assert len(events) == 1
        assert events[0].event_type == "custom"
        assert events[0].data == "test message"
    
    def test_parse_sse_stream_with_id(self, sse_tester):
        """Test parsing SSE stream with event ID"""
        stream_data = "id: 123\ndata: test message\n\n"
        events = sse_tester._parse_sse_stream(stream_data)
        
        assert len(events) == 1
        assert events[0].event_id == "123"
        assert events[0].data == "test message"
    
    def test_parse_sse_stream_multiline_data(self, sse_tester):
        """Test parsing SSE stream with multiline data"""
        stream_data = "data: line 1\ndata: line 2\n\n"
        events = sse_tester._parse_sse_stream(stream_data)
        
        assert len(events) == 1
        assert events[0].data == "line 1\nline 2"
    
    def test_parse_sse_stream_multiple_events(self, sse_tester):
        """Test parsing SSE stream with multiple events"""
        stream_data = "data: message 1\n\ndata: message 2\n\n"
        events = sse_tester._parse_sse_stream(stream_data)
        
        assert len(events) == 2
        assert events[0].data == "message 1"
        assert events[1].data == "message 2"
    
    def test_parse_sse_stream_with_comments(self, sse_tester):
        """Test parsing SSE stream with comments"""
        stream_data = ": this is a comment\ndata: test message\n\n"
        events = sse_tester._parse_sse_stream(stream_data)
        
        assert len(events) == 1
        assert events[0].data == "test message"
    
    @pytest.mark.asyncio
    async def test_test_sse_injection_vulnerable(self, sse_tester, request_handler):
        """Test SSE injection detection when vulnerable"""
        payload = "<script>alert(1)</script>"
        
        # Mock response with reflected payload
        mock_response = Mock(spec=Response)
        mock_response.text = f"data: {payload}\n\n"
        request_handler.send_request.return_value = mock_response
        
        result = await sse_tester._test_sse_injection(
            "https://example.com/events",
            payload,
            None,
            None,
        )
        
        assert result is not None
        assert result.is_vulnerable
        assert result.vulnerability_type == VulnerabilityType.SSE_INJECTION
        assert result.payload == payload


class TestMessageAnalyzer:
    """Test MessageAnalyzer class"""
    
    def test_initialization(self, message_analyzer):
        """Test message analyzer initialization"""
        assert message_analyzer is not None
    
    def test_analyze_message_format_json(self, message_analyzer):
        """Test analyzing JSON message format"""
        messages = [
            WebSocketMessage(
                message_id="1",
                direction="sent",
                message_type=MessageType.JSON,
                content='{"action": "test", "data": "hello"}',
                timestamp=1234567890.0,
            ),
            WebSocketMessage(
                message_id="2",
                direction="received",
                message_type=MessageType.JSON,
                content='{"status": "ok", "result": "success"}',
                timestamp=1234567891.0,
            ),
        ]
        
        analysis = message_analyzer.analyze_message_format(messages)
        
        assert "message_types" in analysis
        assert analysis["message_types"]["json"] == 2
        assert "json_fields" in analysis
        assert "action" in analysis["json_fields"]
        assert "data" in analysis["json_fields"]
        assert "status" in analysis["json_fields"]
        assert "result" in analysis["json_fields"]
    
    def test_analyze_message_format_mixed(self, message_analyzer):
        """Test analyzing mixed message formats"""
        messages = [
            WebSocketMessage(
                message_id="1",
                direction="sent",
                message_type=MessageType.JSON,
                content='{"test": "data"}',
                timestamp=1234567890.0,
            ),
            WebSocketMessage(
                message_id="2",
                direction="received",
                message_type=MessageType.TEXT,
                content='plain text',
                timestamp=1234567891.0,
            ),
        ]
        
        analysis = message_analyzer.analyze_message_format(messages)
        
        assert analysis["message_types"]["json"] == 1
        assert analysis["message_types"]["text"] == 1
    
    def test_generate_fuzz_payloads_json(self, message_analyzer):
        """Test generating fuzz payloads for JSON"""
        base_message = '{"action": "test", "data": "hello"}'
        payloads = message_analyzer.generate_fuzz_payloads(base_message, MessageType.JSON)
        
        assert len(payloads) > 0
        
        # Check that payloads contain injection attempts
        payload_str = " ".join(payloads)
        assert "script" in payload_str.lower() or "alert" in payload_str.lower()
        assert "or" in payload_str.lower() or "'" in payload_str
    
    def test_generate_fuzz_payloads_text(self, message_analyzer):
        """Test generating fuzz payloads for text"""
        base_message = "test message"
        payloads = message_analyzer.generate_fuzz_payloads(base_message, MessageType.TEXT)
        
        assert len(payloads) > 0
        
        # Check that payloads are appended to base message
        for payload in payloads:
            assert payload.startswith(base_message)


class TestWebSocketClient:
    """Test WebSocketClient class"""
    
    def test_initialization(self):
        """Test WebSocket client initialization"""
        client = WebSocketClient()
        assert client.connection is None
        assert client.message_history == []
        assert client.message_counter == 0
    
    def test_detect_message_type(self):
        """Test message type detection"""
        client = WebSocketClient()
        
        # Test JSON
        assert client._detect_message_type('{"test": "data"}') == MessageType.JSON
        
        # Test XML
        assert client._detect_message_type('<root>test</root>') == MessageType.XML
        
        # Test text
        assert client._detect_message_type('plain text') == MessageType.TEXT
        
        # Test binary
        assert client._detect_message_type(b'binary') == MessageType.BINARY
    
    def test_get_message_id(self):
        """Test message ID generation"""
        client = WebSocketClient()
        
        msg_id_1 = client._get_message_id()
        msg_id_2 = client._get_message_id()
        
        assert msg_id_1 != msg_id_2
        assert msg_id_1.startswith("msg_1_")
        assert msg_id_2.startswith("msg_2_")
    
    def test_get_message_history(self):
        """Test getting message history"""
        client = WebSocketClient()
        
        # Add some messages
        client.message_history.append(WebSocketMessage(
            message_id="1",
            direction="sent",
            message_type=MessageType.TEXT,
            content="test",
            timestamp=1234567890.0,
        ))
        
        history = client.get_message_history()
        assert len(history) == 1
        assert history[0].message_id == "1"


# Integration tests would require actual WebSocket server
# These are marked as integration tests and skipped by default

@pytest.mark.integration
@pytest.mark.asyncio
async def test_websocket_connection_integration():
    """Integration test for WebSocket connection (requires real server)"""
    # This would test against a real WebSocket server
    # Skipped in unit tests
    pass


@pytest.mark.integration
@pytest.mark.asyncio
async def test_sse_connection_integration():
    """Integration test for SSE connection (requires real server)"""
    # This would test against a real SSE server
    # Skipped in unit tests
    pass
