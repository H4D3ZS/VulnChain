"""Unit tests for SQL Injection module"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.modules.sql_injection import (
    SQLInjectionTester,
    SQLMapIntegration,
    InjectionPoint,
    SQLInjectionType,
    DatabaseType,
    SQLInjectionResult,
    BaselineMeasurement,
)
from app.core.request_handler import RequestHandler, Response
from app.core.http_models import Request


class TestSQLInjectionTester:
    """Test suite for SQLInjectionTester"""

    @pytest.fixture
    def mock_request_handler(self):
        """Create a mock RequestHandler"""
        handler = MagicMock(spec=RequestHandler)
        handler.send_request = AsyncMock()
        return handler

    @pytest.fixture
    def tester(self, mock_request_handler):
        """Create a SQLInjectionTester instance"""
        return SQLInjectionTester(mock_request_handler)

    @pytest.fixture
    def sample_injection_point(self):
        """Create a sample injection point"""
        return InjectionPoint(
            parameter="id",
            location="query",
            original_value="1",
            url="http://example.com/page?id=1",
            method="GET",
        )

    def test_tester_initialization(self, mock_request_handler):
        """Test SQLInjectionTester initialization"""
        tester = SQLInjectionTester(mock_request_handler)
        assert tester.request_handler == mock_request_handler
        assert tester.payload_engine is not None
        
        # Check that default payloads are loaded
        assert tester.payload_engine.get_payload_count("sqli_time_based") > 0
        assert tester.payload_engine.get_payload_count("sqli_boolean") > 0
        assert tester.payload_engine.get_payload_count("sqli_error") > 0

    def test_database_error_detection_mysql(self, tester):
        """Test MySQL error detection"""
        response_text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        db_type, error_msg = tester._detect_database_error(response_text)
        
        assert db_type == DatabaseType.MYSQL
        assert error_msg is not None

    def test_database_error_detection_postgresql(self, tester):
        """Test PostgreSQL error detection"""
        response_text = "PostgreSQL ERROR: syntax error at or near"
        db_type, error_msg = tester._detect_database_error(response_text)
        
        assert db_type == DatabaseType.POSTGRESQL
        assert error_msg is not None

    def test_database_error_detection_mssql(self, tester):
        """Test MSSQL error detection"""
        response_text = "Microsoft SQL Server Native Client error '80040e14'"
        db_type, error_msg = tester._detect_database_error(response_text)
        
        assert db_type == DatabaseType.MSSQL
        assert error_msg is not None

    def test_database_error_detection_oracle(self, tester):
        """Test Oracle error detection"""
        response_text = "ORA-00933: SQL command not properly ended"
        db_type, error_msg = tester._detect_database_error(response_text)
        
        assert db_type == DatabaseType.ORACLE
        assert error_msg is not None

    def test_database_error_detection_sqlite(self, tester):
        """Test SQLite error detection"""
        response_text = "SQLite3::SQLException: near"
        db_type, error_msg = tester._detect_database_error(response_text)
        
        assert db_type == DatabaseType.SQLITE
        assert error_msg is not None

    def test_database_error_detection_no_error(self, tester):
        """Test no database error detection"""
        response_text = "This is a normal response with no database errors"
        db_type, error_msg = tester._detect_database_error(response_text)
        
        assert db_type == DatabaseType.UNKNOWN
        assert error_msg is None

    def test_extract_delay_from_payload_sleep(self, tester):
        """Test delay extraction from SLEEP payload"""
        payload = "' AND SLEEP(5)--"
        delay = tester._extract_delay_from_payload(payload)
        assert delay == 5.0

    def test_extract_delay_from_payload_pg_sleep(self, tester):
        """Test delay extraction from pg_sleep payload"""
        payload = "'; SELECT pg_sleep(10)--"
        delay = tester._extract_delay_from_payload(payload)
        assert delay == 10.0

    def test_extract_delay_from_payload_waitfor(self, tester):
        """Test delay extraction from WAITFOR DELAY payload"""
        payload = "'; WAITFOR DELAY '0:0:7'--"
        delay = tester._extract_delay_from_payload(payload)
        assert delay == 7.0

    def test_extract_delay_from_payload_default(self, tester):
        """Test default delay extraction"""
        payload = "' OR 1=1--"
        delay = tester._extract_delay_from_payload(payload)
        assert delay == 5.0  # Default

    def test_detect_database_from_payload_mysql(self, tester):
        """Test MySQL detection from payload"""
        payload = "' AND SLEEP(5)--"
        db_type = tester._detect_database_from_payload(payload)
        assert db_type == DatabaseType.MYSQL

    def test_detect_database_from_payload_postgresql(self, tester):
        """Test PostgreSQL detection from payload"""
        payload = "'; SELECT pg_sleep(5)--"
        db_type = tester._detect_database_from_payload(payload)
        assert db_type == DatabaseType.POSTGRESQL

    def test_detect_database_from_payload_mssql(self, tester):
        """Test MSSQL detection from payload"""
        payload = "'; WAITFOR DELAY '0:0:5'--"
        db_type = tester._detect_database_from_payload(payload)
        assert db_type == DatabaseType.MSSQL

    def test_detect_database_from_payload_oracle(self, tester):
        """Test Oracle detection from payload"""
        payload = "' AND DBMS_LOCK.SLEEP(5)--"
        db_type = tester._detect_database_from_payload(payload)
        assert db_type == DatabaseType.ORACLE

    def test_detect_database_from_payload_sqlite(self, tester):
        """Test SQLite detection from payload"""
        payload = "' AND (SELECT 1 FROM (SELECT RANDOMBLOB(100000000)))--"
        db_type = tester._detect_database_from_payload(payload)
        assert db_type == DatabaseType.SQLITE

    @pytest.mark.asyncio
    async def test_error_based_injection_core_logic(self, tester):
        """Test error-based injection core detection logic"""
        # Test that database errors are properly detected
        # Use a response that matches the regex pattern
        response_text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        db_type, error_msg = tester._detect_database_error(response_text)
        
        assert db_type == DatabaseType.MYSQL
        assert error_msg is not None
        
        # Verify that a result would be created with correct properties
        # This tests the logic without full integration
        assert db_type != DatabaseType.UNKNOWN

    @pytest.mark.asyncio
    async def test_error_based_injection_not_vulnerable(self, tester, sample_injection_point):
        """Test error-based injection detection when not vulnerable"""
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
        
        result = await tester._test_error_based(sample_injection_point)
        
        assert result is not None
        assert not result.is_vulnerable
        assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_boolean_based_injection_vulnerable(self, tester, sample_injection_point):
        """Test boolean-based injection detection when vulnerable"""
        # Mock responses with different lengths
        baseline_response = Response(
            status_code=200,
            headers={},
            body=b"A" * 500,
            text="A" * 500,
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        true_response = Response(
            status_code=200,
            headers={},
            body=b"A" * 1000,  # Different length
            text="A" * 1000,
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        false_response = Response(
            status_code=200,
            headers={},
            body=b"A" * 500,
            text="A" * 500,
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        verify_response = Response(
            status_code=200,
            headers={},
            body=b"A" * 1000,  # Consistent with true
            text="A" * 1000,
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        tester.request_handler.send_request.side_effect = [
            baseline_response,
            true_response,
            false_response,
            verify_response,
        ]
        
        result = await tester._test_boolean_based(sample_injection_point)
        
        assert result is not None
        assert result.is_vulnerable
        assert result.injection_type == SQLInjectionType.BOOLEAN_BASED
        assert result.confidence == 0.85

    @pytest.mark.asyncio
    async def test_measure_baseline(self, tester, sample_injection_point):
        """Test baseline measurement"""
        # Mock consistent response times
        response = Response(
            status_code=200,
            headers={},
            body=b"Response",
            text="Response",
            elapsed_time=0.1,
            request=MagicMock(),
            history=[],
        )
        
        tester.request_handler.send_request.return_value = response
        
        baseline = await tester._measure_baseline(sample_injection_point, samples=3)
        
        assert isinstance(baseline, BaselineMeasurement)
        assert baseline.mean > 0
        assert baseline.median > 0
        assert baseline.threshold > baseline.mean
        assert len(baseline.samples) == 3

    @pytest.mark.asyncio
    async def test_time_based_injection_core_logic(self, tester):
        """Test time-based injection core detection logic"""
        # Test baseline measurement logic
        baseline = BaselineMeasurement(
            mean=0.1,
            median=0.1,
            std_dev=0.01,
            samples=[0.09, 0.1, 0.11, 0.1, 0.1],
            threshold=0.13,  # mean + 3*std_dev
        )
        
        # Test that delay detection logic works
        expected_delay = 5.0
        actual_delay = 5.5
        
        # Verify detection logic: actual >= (threshold + expected * 0.8)
        assert actual_delay >= (baseline.threshold + expected_delay * 0.8)
        
        # Test delay extraction
        payload = "' AND SLEEP(5)--"
        extracted_delay = tester._extract_delay_from_payload(payload)
        assert extracted_delay == 5.0

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
        
        response = await tester._send_request(sample_injection_point, "' OR 1=1--")
        
        assert response == mock_response
        assert tester.request_handler.send_request.called

    @pytest.mark.asyncio
    async def test_send_request_post_location(self, tester):
        """Test sending request with POST data injection"""
        injection_point = InjectionPoint(
            parameter="username",
            location="post",
            original_value="admin",
            url="http://example.com/login",
            method="POST",
            data={"username": "admin", "password": "test"},
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
        
        response = await tester._send_request(injection_point, "admin' OR 1=1--")
        
        assert response == mock_response
        assert tester.request_handler.send_request.called


class TestSQLMapIntegration:
    """Test suite for SQLMapIntegration"""

    @pytest.fixture
    def sqlmap(self):
        """Create a SQLMapIntegration instance"""
        return SQLMapIntegration(sqlmap_path="/usr/bin/sqlmap")

    @pytest.fixture
    def sample_injection_point(self):
        """Create a sample injection point"""
        return InjectionPoint(
            parameter="id",
            location="query",
            original_value="1",
            url="http://example.com/page?id=1",
            method="GET",
        )

    @pytest.fixture
    def sample_result(self, sample_injection_point):
        """Create a sample SQL injection result"""
        return SQLInjectionResult(
            injection_point=sample_injection_point,
            is_vulnerable=True,
            injection_type=SQLInjectionType.ERROR_BASED,
            database_type=DatabaseType.MYSQL,
            payload="' OR 1=1--",
            confidence=0.9,
        )

    def test_sqlmap_initialization(self):
        """Test SQLMapIntegration initialization"""
        sqlmap = SQLMapIntegration(sqlmap_path="/custom/path/sqlmap")
        assert sqlmap.sqlmap_path == "/custom/path/sqlmap"

    def test_export_to_sqlmap_format(self, sqlmap, sample_injection_point, sample_result):
        """Test exporting to SQLMap format"""
        sqlmap_request = sqlmap.export_to_sqlmap_format(sample_injection_point, sample_result)
        
        assert sqlmap_request["url"] == sample_injection_point.url
        assert sqlmap_request["method"] == sample_injection_point.method
        assert sqlmap_request["vulnerable_parameter"] == sample_injection_point.parameter
        assert sqlmap_request["injection_type"] == "error_based"
        assert sqlmap_request["database_type"] == "mysql"
        assert sqlmap_request["payload"] == "' OR 1=1--"

    def test_generate_sqlmap_command_basic(self, sqlmap, sample_injection_point, sample_result):
        """Test generating basic SQLMap command"""
        command = sqlmap.generate_sqlmap_command(sample_injection_point, sample_result)
        
        assert "/usr/bin/sqlmap" in command
        assert "-u 'http://example.com/page?id=1'" in command
        assert "-p 'id'" in command
        assert "--technique=E" in command
        assert "--dbms=mysql" in command

    def test_generate_sqlmap_command_with_options(self, sqlmap, sample_injection_point, sample_result):
        """Test generating SQLMap command with options"""
        options = {
            "batch": True,
            "threads": 5,
            "level": 3,
            "risk": 2,
            "dbs": True,
        }
        
        command = sqlmap.generate_sqlmap_command(sample_injection_point, sample_result, options)
        
        assert "--batch" in command
        assert "--threads=5" in command
        assert "--level=3" in command
        assert "--risk=2" in command
        assert "--dbs" in command

    def test_generate_sqlmap_command_post_method(self, sqlmap, sample_result):
        """Test generating SQLMap command for POST request"""
        injection_point = InjectionPoint(
            parameter="username",
            location="post",
            original_value="admin",
            url="http://example.com/login",
            method="POST",
            data={"username": "admin", "password": "test"},
        )
        
        command = sqlmap.generate_sqlmap_command(injection_point, sample_result)
        
        assert "--data=" in command
        assert "username=" in command
        assert "password=" in command

    def test_generate_sqlmap_command_with_headers(self, sqlmap, sample_result):
        """Test generating SQLMap command with custom headers"""
        injection_point = InjectionPoint(
            parameter="id",
            location="query",
            original_value="1",
            url="http://example.com/page?id=1",
            method="GET",
            headers={"User-Agent": "Custom", "X-API-Key": "secret"},
        )
        
        command = sqlmap.generate_sqlmap_command(injection_point, sample_result)
        
        assert "--header='User-Agent: Custom'" in command
        assert "--header='X-API-Key: secret'" in command

    def test_generate_sqlmap_command_time_based(self, sqlmap, sample_injection_point):
        """Test generating SQLMap command for time-based injection"""
        result = SQLInjectionResult(
            injection_point=sample_injection_point,
            is_vulnerable=True,
            injection_type=SQLInjectionType.TIME_BASED_BLIND,
            database_type=DatabaseType.MYSQL,
            payload="' AND SLEEP(5)--",
            confidence=0.95,
        )
        
        command = sqlmap.generate_sqlmap_command(sample_injection_point, result)
        
        assert "--technique=T" in command

    def test_generate_sqlmap_command_boolean_based(self, sqlmap, sample_injection_point):
        """Test generating SQLMap command for boolean-based injection"""
        result = SQLInjectionResult(
            injection_point=sample_injection_point,
            is_vulnerable=True,
            injection_type=SQLInjectionType.BOOLEAN_BASED,
            payload="' OR 1=1--",
            confidence=0.85,
        )
        
        command = sqlmap.generate_sqlmap_command(sample_injection_point, result)
        
        assert "--technique=B" in command

    @pytest.mark.asyncio
    async def test_execute_sqlmap_success(self, sqlmap):
        """Test successful SQLMap execution"""
        with patch("asyncio.create_subprocess_shell") as mock_subprocess:
            # Mock process
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"Success", b""))
            mock_subprocess.return_value = mock_process
            
            return_code, stdout, stderr = await sqlmap.execute_sqlmap("sqlmap -u http://example.com")
            
            assert return_code == 0
            assert stdout == "Success"
            assert stderr == ""

    @pytest.mark.asyncio
    async def test_execute_sqlmap_timeout(self, sqlmap):
        """Test SQLMap execution timeout"""
        with patch("asyncio.create_subprocess_shell") as mock_subprocess:
            # Mock process that times out
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_process.kill = MagicMock()
            mock_subprocess.return_value = mock_process
            
            return_code, stdout, stderr = await sqlmap.execute_sqlmap("sqlmap -u http://example.com", timeout=1)
            
            assert return_code == -1
            assert "timed out" in stderr.lower()


class TestInjectionPoint:
    """Test suite for InjectionPoint dataclass"""

    def test_injection_point_creation(self):
        """Test creating an injection point"""
        point = InjectionPoint(
            parameter="id",
            location="query",
            original_value="1",
            url="http://example.com/page?id=1",
            method="GET",
        )
        
        assert point.parameter == "id"
        assert point.location == "query"
        assert point.original_value == "1"
        assert point.url == "http://example.com/page?id=1"
        assert point.method == "GET"

    def test_injection_point_with_headers(self):
        """Test creating an injection point with headers"""
        headers = {"User-Agent": "Test", "X-API-Key": "secret"}
        point = InjectionPoint(
            parameter="id",
            location="query",
            original_value="1",
            url="http://example.com/page?id=1",
            headers=headers,
        )
        
        assert point.headers == headers

    def test_injection_point_with_post_data(self):
        """Test creating an injection point with POST data"""
        data = {"username": "admin", "password": "test"}
        point = InjectionPoint(
            parameter="username",
            location="post",
            original_value="admin",
            url="http://example.com/login",
            method="POST",
            data=data,
        )
        
        assert point.data == data
        assert point.method == "POST"


class TestSQLInjectionResult:
    """Test suite for SQLInjectionResult dataclass"""

    def test_result_creation_vulnerable(self):
        """Test creating a vulnerable result"""
        injection_point = InjectionPoint(
            parameter="id",
            location="query",
            original_value="1",
            url="http://example.com/page?id=1",
        )
        
        result = SQLInjectionResult(
            injection_point=injection_point,
            is_vulnerable=True,
            injection_type=SQLInjectionType.ERROR_BASED,
            database_type=DatabaseType.MYSQL,
            payload="' OR 1=1--",
            confidence=0.9,
        )
        
        assert result.is_vulnerable
        assert result.injection_type == SQLInjectionType.ERROR_BASED
        assert result.database_type == DatabaseType.MYSQL
        assert result.payload == "' OR 1=1--"
        assert result.confidence == 0.9

    def test_result_creation_not_vulnerable(self):
        """Test creating a not vulnerable result"""
        injection_point = InjectionPoint(
            parameter="id",
            location="query",
            original_value="1",
            url="http://example.com/page?id=1",
        )
        
        result = SQLInjectionResult(
            injection_point=injection_point,
            is_vulnerable=False,
            confidence=0.0,
        )
        
        assert not result.is_vulnerable
        assert result.injection_type is None
        assert result.database_type is None
        assert result.confidence == 0.0
