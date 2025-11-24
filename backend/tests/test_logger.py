"""Tests for the Logger module"""

import pytest
import asyncio
from datetime import datetime, timezone

from app.core.logger import Logger, LogLevel, LogEntryType, LogEntry
from app.core.http_models import Request, Response


@pytest.fixture
def logger():
    """Create a Logger instance for testing"""
    return Logger()


@pytest.fixture
def sample_request():
    """Create a sample HTTP request"""
    return Request(
        method="GET",
        url="https://example.com/api/test",
        headers={"User-Agent": "VulnChain/1.0"},
        cookies={"session": "abc123"},
    )


@pytest.fixture
def sample_response(sample_request):
    """Create a sample HTTP response"""
    return Response(
        status_code=200,
        headers={"Content-Type": "application/json"},
        body=b'{"message": "success", "flag": "CTF{test_flag_123}"}',
        text='{"message": "success", "flag": "CTF{test_flag_123}"}',
        elapsed_time=0.5,
        request=sample_request,
    )


def test_logger_initialization():
    """Test logger initialization"""
    logger = Logger()
    assert logger is not None
    assert len(logger._entries) == 0
    assert logger._entry_counter == 0


def test_log_request(logger, sample_request):
    """Test logging HTTP request"""
    logger.log_request(sample_request)
    
    entries = logger.get_entries()
    assert len(entries) == 1
    
    entry = entries[0]
    assert entry.entry_type == LogEntryType.HTTP_REQUEST
    assert entry.level == LogLevel.INFO
    assert "GET" in entry.message
    assert "example.com" in entry.message
    assert entry.data["method"] == "GET"
    assert entry.data["url"] == sample_request.url


def test_log_response(logger, sample_response):
    """Test logging HTTP response"""
    logger.log_response(sample_response)
    
    # Should have response entry and flag entry
    entries = logger.get_entries()
    assert len(entries) >= 1
    
    # Check response entry
    response_entries = [e for e in entries if e.entry_type == LogEntryType.HTTP_RESPONSE]
    assert len(response_entries) == 1
    
    entry = response_entries[0]
    assert entry.data["status_code"] == 200
    assert entry.data["elapsed_time"] == 0.5
    assert "success" in entry.data["body"]


def test_flag_extraction(logger):
    """Test flag extraction from text"""
    text = """
    Here is some text with flags:
    CTF{flag_one}
    FLAG{flag_two}
    flag{flag_three}
    And some more text.
    """
    
    flags = logger.extract_flags(text)
    assert len(flags) >= 3
    assert "CTF{flag_one}" in flags
    assert "FLAG{flag_two}" in flags
    assert "flag{flag_three}" in flags


def test_flag_extraction_no_duplicates(logger):
    """Test that flag extraction removes duplicates"""
    text = "CTF{test} some text CTF{test} more text CTF{test}"
    
    flags = logger.extract_flags(text)
    assert len(flags) == 1
    assert flags[0] == "CTF{test}"


def test_log_flags(logger, sample_response):
    """Test logging extracted flags"""
    flags = ["CTF{test1}", "FLAG{test2}"]
    logger.log_flags(flags, sample_response)
    
    flag_entries = logger.get_flags()
    assert len(flag_entries) == 2
    
    for entry in flag_entries:
        assert entry.entry_type == LogEntryType.FLAG
        assert entry.level == LogLevel.CRITICAL
        assert "Flag found:" in entry.message


def test_automatic_flag_detection_in_response(logger, sample_response):
    """Test that flags are automatically detected when logging responses"""
    logger.log_response(sample_response)
    
    flag_entries = logger.get_flags()
    assert len(flag_entries) >= 1
    assert any("CTF{test_flag_123}" in entry.message for entry in flag_entries)


def test_log_finding(logger):
    """Test logging security findings"""
    finding = {
        "title": "SQL Injection",
        "severity": "HIGH",
        "description": "SQL injection vulnerability found",
        "affected_url": "https://example.com/api/users",
        "workspace_id": "ws_123",
    }
    
    logger.log_finding(finding)
    
    findings = logger.get_findings()
    assert len(findings) == 1
    
    entry = findings[0]
    assert entry.entry_type == LogEntryType.FINDING
    assert entry.level == LogLevel.ERROR  # HIGH severity maps to ERROR
    assert entry.message == "SQL Injection"
    assert entry.workspace_id == "ws_123"


def test_log_error(logger):
    """Test logging errors"""
    try:
        raise ValueError("Test error")
    except ValueError as e:
        logger.log_error("An error occurred", error=e, context={"url": "https://example.com"})
    
    entries = logger.get_entries(level=LogLevel.ERROR)
    assert len(entries) >= 1
    
    entry = entries[0]
    assert entry.level == LogLevel.ERROR
    assert "An error occurred" in entry.message
    assert entry.data["error_type"] == "ValueError"
    assert "Test error" in entry.data["error_message"]


def test_log_info(logger):
    """Test logging info messages"""
    logger.log_info("Test info message", data={"key": "value"})
    
    entries = logger.get_entries(level=LogLevel.INFO)
    assert len(entries) >= 1
    
    entry = entries[0]
    assert entry.level == LogLevel.INFO
    assert entry.message == "Test info message"
    assert entry.data["key"] == "value"


def test_filter_by_level(logger):
    """Test filtering entries by log level"""
    logger.log_info("Info message")
    logger.log_error("Error message")
    
    info_entries = logger.get_entries(level=LogLevel.INFO)
    error_entries = logger.get_entries(level=LogLevel.ERROR)
    
    assert len(info_entries) >= 1
    assert len(error_entries) >= 1
    assert all(e.level == LogLevel.INFO for e in info_entries)
    assert all(e.level == LogLevel.ERROR for e in error_entries)


def test_filter_by_entry_type(logger, sample_request, sample_response):
    """Test filtering entries by entry type"""
    logger.log_request(sample_request)
    logger.log_response(sample_response)
    logger.log_info("Info message")
    
    request_entries = logger.get_entries(entry_type=LogEntryType.HTTP_REQUEST)
    response_entries = logger.get_entries(entry_type=LogEntryType.HTTP_RESPONSE)
    
    assert len(request_entries) >= 1
    assert len(response_entries) >= 1
    assert all(e.entry_type == LogEntryType.HTTP_REQUEST for e in request_entries)
    assert all(e.entry_type == LogEntryType.HTTP_RESPONSE for e in response_entries)


def test_filter_by_workspace(logger):
    """Test filtering entries by workspace ID"""
    finding1 = {"title": "Finding 1", "severity": "HIGH", "workspace_id": "ws_1"}
    finding2 = {"title": "Finding 2", "severity": "HIGH", "workspace_id": "ws_2"}
    
    logger.log_finding(finding1)
    logger.log_finding(finding2)
    
    ws1_entries = logger.get_entries(workspace_id="ws_1")
    ws2_entries = logger.get_entries(workspace_id="ws_2")
    
    assert len(ws1_entries) == 1
    assert len(ws2_entries) == 1
    assert ws1_entries[0].workspace_id == "ws_1"
    assert ws2_entries[0].workspace_id == "ws_2"


def test_search_entries(logger):
    """Test searching log entries"""
    logger.log_info("Message about SQL injection")
    logger.log_info("Message about XSS vulnerability")
    logger.log_info("Message about authentication")
    
    sql_entries = logger.get_entries(search="SQL")
    xss_entries = logger.get_entries(search="XSS")
    
    assert len(sql_entries) >= 1
    assert len(xss_entries) >= 1
    assert any("SQL" in e.message for e in sql_entries)
    assert any("XSS" in e.message for e in xss_entries)


def test_limit_entries(logger):
    """Test limiting number of returned entries"""
    for i in range(10):
        logger.log_info(f"Message {i}")
    
    entries = logger.get_entries(limit=5)
    assert len(entries) == 5


def test_max_entries_limit(logger):
    """Test that logger respects max_entries limit"""
    logger = Logger(config={"max_entries": 10})
    
    # Add more entries than the limit
    for i in range(20):
        logger.log_info(f"Message {i}")
    
    entries = logger.get_entries()
    assert len(entries) <= 10


def test_clear_logs(logger):
    """Test clearing all logs"""
    logger.log_info("Message 1")
    logger.log_info("Message 2")
    
    assert len(logger.get_entries()) >= 2
    
    logger.clear_logs()
    assert len(logger.get_entries()) == 0


def test_clear_logs_by_workspace(logger):
    """Test clearing logs for specific workspace"""
    finding1 = {"title": "Finding 1", "severity": "HIGH", "workspace_id": "ws_1"}
    finding2 = {"title": "Finding 2", "severity": "HIGH", "workspace_id": "ws_2"}
    
    logger.log_finding(finding1)
    logger.log_finding(finding2)
    
    logger.clear_logs(workspace_id="ws_1")
    
    entries = logger.get_entries()
    assert len(entries) == 1
    assert entries[0].workspace_id == "ws_2"


def test_export_logs_json(logger):
    """Test exporting logs as JSON"""
    logger.log_info("Test message 1")
    logger.log_info("Test message 2")
    
    data = logger.export_logs(format="json")
    assert data is not None
    assert isinstance(data, bytes)
    
    # Parse JSON to verify format
    import json
    parsed = json.loads(data.decode("utf-8"))
    assert isinstance(parsed, list)
    assert len(parsed) >= 2


def test_export_logs_jsonl(logger):
    """Test exporting logs as JSON Lines"""
    logger.log_info("Test message 1")
    logger.log_info("Test message 2")
    
    data = logger.export_logs(format="jsonl")
    assert data is not None
    assert isinstance(data, bytes)
    
    # Verify JSON Lines format (one JSON object per line)
    lines = data.decode("utf-8").strip().split("\n")
    assert len(lines) >= 2
    
    import json
    for line in lines:
        parsed = json.loads(line)
        assert isinstance(parsed, dict)


def test_export_logs_with_filters(logger):
    """Test exporting logs with filters"""
    logger.log_info("Info message")
    logger.log_error("Error message")
    
    # Export only error logs
    data = logger.export_logs(format="json", level=LogLevel.ERROR)
    
    import json
    parsed = json.loads(data.decode("utf-8"))
    assert all(entry["level"] == "ERROR" for entry in parsed)


def test_log_entry_to_dict():
    """Test LogEntry to_dict conversion"""
    entry = LogEntry(
        entry_id="log_001",
        timestamp=datetime.now(timezone.utc),
        level=LogLevel.INFO,
        entry_type=LogEntryType.INFO,
        message="Test message",
        data={"key": "value"},
        workspace_id="ws_123",
    )
    
    entry_dict = entry.to_dict()
    assert entry_dict["entry_id"] == "log_001"
    assert entry_dict["level"] == "INFO"
    assert entry_dict["entry_type"] == "info"
    assert entry_dict["message"] == "Test message"
    assert entry_dict["data"]["key"] == "value"
    assert entry_dict["workspace_id"] == "ws_123"


def test_log_entry_to_json():
    """Test LogEntry to_json conversion"""
    entry = LogEntry(
        entry_id="log_001",
        timestamp=datetime.now(timezone.utc),
        level=LogLevel.INFO,
        entry_type=LogEntryType.INFO,
        message="Test message",
        data={"key": "value"},
    )
    
    json_str = entry.to_json()
    assert json_str is not None
    
    import json
    parsed = json.loads(json_str)
    assert parsed["entry_id"] == "log_001"
    assert parsed["message"] == "Test message"


@pytest.mark.asyncio
async def test_stream_logs(logger):
    """Test real-time log streaming"""
    # Start streaming in background
    stream_task = asyncio.create_task(_collect_stream_entries(logger, count=3))
    
    # Give stream time to start
    await asyncio.sleep(0.1)
    
    # Add some log entries
    logger.log_info("Message 1")
    await asyncio.sleep(0.1)
    logger.log_info("Message 2")
    await asyncio.sleep(0.1)
    logger.log_info("Message 3")
    
    # Wait for stream to collect entries
    collected = await asyncio.wait_for(stream_task, timeout=2.0)
    
    assert len(collected) == 3
    assert all(isinstance(entry, LogEntry) for entry in collected)


async def _collect_stream_entries(logger, count):
    """Helper to collect entries from stream"""
    collected = []
    async for entry in logger.stream_logs():
        collected.append(entry)
        if len(collected) >= count:
            break
    return collected


def test_response_body_truncation(logger, sample_request):
    """Test that large response bodies are truncated"""
    # Create response with large body
    large_body = "x" * 20000
    response = Response(
        status_code=200,
        headers={},
        body=large_body.encode(),
        text=large_body,
        elapsed_time=0.5,
        request=sample_request,
    )
    
    logger.log_response(response)
    
    entries = logger.get_entries(entry_type=LogEntryType.HTTP_RESPONSE)
    assert len(entries) == 1
    
    entry = entries[0]
    assert "body_truncated" in entry.data
    assert entry.data["body_truncated"] is True
    assert len(entry.data["body"]) < len(large_body)


def test_custom_flag_pattern(logger):
    """Test adding custom flag patterns"""
    # Add custom pattern
    logger.add_flag_pattern(r"CUSTOM\{[^}]+\}")
    
    text = "Here is a custom flag: CUSTOM{my_custom_flag_123}"
    flags = logger.extract_flags(text)
    
    assert len(flags) >= 1
    assert "CUSTOM{my_custom_flag_123}" in flags


def test_generate_report_from_logger(logger):
    """Test generating report from logger findings"""
    # Add some findings
    finding1 = {
        "finding_id": "find_001",
        "title": "SQL Injection",
        "severity": "HIGH",
        "vulnerability_type": "SQL Injection",
        "description": "SQL injection vulnerability found",
        "affected_url": "https://example.com/api/users",
        "proof_of_concept": "' OR '1'='1",
        "remediation": "Use parameterized queries",
        "workspace_id": "ws_123",
        "flags": ["CTF{sql_found}"],
    }
    
    finding2 = {
        "finding_id": "find_002",
        "title": "XSS Vulnerability",
        "severity": "MEDIUM",
        "vulnerability_type": "XSS",
        "description": "Cross-site scripting vulnerability",
        "affected_url": "https://example.com/search",
        "proof_of_concept": "<script>alert(1)</script>",
        "remediation": "Sanitize user input",
        "workspace_id": "ws_123",
    }
    
    logger.log_finding(finding1)
    logger.log_finding(finding2)
    
    # Generate Markdown report
    report = logger.generate_report(
        format="markdown",
        workspace_id="ws_123",
        workspace_name="Test Workspace",
        target_url="https://example.com",
    )
    
    assert report is not None
    content = report.decode("utf-8")
    assert "SQL Injection" in content
    assert "XSS Vulnerability" in content
    assert "CTF{sql_found}" in content
    
    # Generate JSON report
    json_report = logger.generate_report(
        format="json",
        workspace_id="ws_123",
    )
    
    import json
    data = json.loads(json_report.decode("utf-8"))
    assert len(data["findings"]) == 2
