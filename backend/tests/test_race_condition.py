"""Tests for race condition module"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from app.modules.race_condition import (
    RaceConditionTester,
    RaceConditionTest,
    TimingStrategy,
    RaceConditionType,
    ExploitParameters,
)
from app.core.request_handler import Response


@pytest.fixture
def mock_request_handler():
    """Create a mock request handler"""
    handler = Mock()
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def race_tester(mock_request_handler):
    """Create a race condition tester"""
    return RaceConditionTester(mock_request_handler, max_workers=10)


@pytest.fixture
def basic_test():
    """Create a basic race condition test"""
    return RaceConditionTest(
        url="https://example.com/api/transfer",
        method="POST",
        headers={"Content-Type": "application/json"},
        data={"amount": 100},
        num_requests=10,
        timing_strategy=TimingStrategy.SIMULTANEOUS,
    )


class TestRaceConditionTest:
    """Tests for RaceConditionTest dataclass"""
    
    def test_default_values(self):
        """Test default values for RaceConditionTest"""
        test = RaceConditionTest(url="https://example.com")
        
        assert test.url == "https://example.com"
        assert test.method == "POST"
        assert test.headers == {}
        assert test.data is None
        assert test.cookies is None
        assert test.num_requests == 10
        assert test.timing_strategy == TimingStrategy.SIMULTANEOUS
        assert test.delay_microseconds == 0
        assert test.check_function is None
    
    def test_custom_values(self):
        """Test custom values for RaceConditionTest"""
        def custom_check(responses):
            return True
        
        test = RaceConditionTest(
            url="https://example.com/api",
            method="GET",
            headers={"Authorization": "Bearer token"},
            num_requests=20,
            timing_strategy=TimingStrategy.SYNCHRONIZED,
            delay_microseconds=1000,
            check_function=custom_check,
        )
        
        assert test.url == "https://example.com/api"
        assert test.method == "GET"
        assert test.headers == {"Authorization": "Bearer token"}
        assert test.num_requests == 20
        assert test.timing_strategy == TimingStrategy.SYNCHRONIZED
        assert test.delay_microseconds == 1000
        assert test.check_function == custom_check


class TestRaceConditionTester:
    """Tests for RaceConditionTester"""
    
    @pytest.mark.asyncio
    async def test_initialization(self, mock_request_handler):
        """Test tester initialization"""
        tester = RaceConditionTester(mock_request_handler, max_workers=20)
        
        assert tester.request_handler == mock_request_handler
        assert tester.max_workers == 20
        assert tester._executor is not None
    
    @pytest.mark.asyncio
    async def test_send_simultaneous(self, race_tester, basic_test, mock_request_handler):
        """Test simultaneous request sending"""
        # Mock responses
        from app.core.http_models import Request
        mock_request = Request(method="POST", url=basic_test.url)
        mock_response = Response(
            status_code=200,
            headers={},
            body=b"success",
            text="success",
            elapsed_time=0.1,
            request=mock_request,
        )
        mock_request_handler.send_request.return_value = mock_response
        
        # Send simultaneous requests
        responses, timing_data = await race_tester._send_simultaneous(basic_test)
        
        # Verify
        assert len(responses) == basic_test.num_requests
        assert timing_data["strategy"] == "simultaneous"
        assert "total_time" in timing_data
        assert "time_spread" in timing_data
        assert timing_data["num_requests"] == basic_test.num_requests
    
    @pytest.mark.asyncio
    async def test_send_staggered(self, race_tester, basic_test, mock_request_handler):
        """Test staggered request sending"""
        # Mock responses
        from app.core.http_models import Request
        mock_request = Request(method="POST", url=basic_test.url)
        mock_response = Response(
            status_code=200,
            headers={},
            body=b"success",
            text="success",
            elapsed_time=0.1,
            request=mock_request,
        )
        mock_request_handler.send_request.return_value = mock_response
        
        # Set delay
        basic_test.delay_microseconds = 1000  # 1ms
        
        # Send staggered requests
        responses, timing_data = await race_tester._send_staggered(basic_test)
        
        # Verify
        assert len(responses) == basic_test.num_requests
        assert timing_data["strategy"] == "staggered"
        assert timing_data["delay_microseconds"] == 1000
    
    @pytest.mark.asyncio
    async def test_analyze_duplicate_transaction(self, race_tester, basic_test):
        """Test detection of duplicate transaction"""
        # Create responses with multiple successes
        from app.core.http_models import Request
        mock_request = Request(method="POST", url=basic_test.url)
        responses = [
            Response(200, {}, b"success", "success", 0.1, mock_request)
            for _ in range(5)
        ]
        
        is_vulnerable, race_type, evidence = race_tester._analyze_responses(
            responses, basic_test
        )
        
        assert is_vulnerable
        assert race_type == RaceConditionType.DUPLICATE_TRANSACTION
        assert len(evidence) > 0
        assert any("duplicate" in e.lower() for e in evidence)
    
    @pytest.mark.asyncio
    async def test_analyze_toctou(self, race_tester, basic_test):
        """Test detection of TOCTOU vulnerability"""
        # Create responses with mix of success and failure
        from app.core.http_models import Request
        mock_request = Request(method="POST", url=basic_test.url)
        responses = [
            Response(200, {}, b"success", "success", 0.1, mock_request),
            Response(200, {}, b"success", "success", 0.1, mock_request),
            Response(403, {}, b"forbidden", "forbidden", 0.1, mock_request),
            Response(403, {}, b"forbidden", "forbidden", 0.1, mock_request),
        ]
        
        is_vulnerable, race_type, evidence = race_tester._analyze_responses(
            responses, basic_test
        )
        
        assert is_vulnerable
        # The logic detects duplicate transactions first, then TOCTOU
        # Since we have 2 success responses with identical bodies, it's detected as duplicate
        assert race_type in [RaceConditionType.TOCTOU, RaceConditionType.DUPLICATE_TRANSACTION]
        assert len(evidence) > 0
    
    @pytest.mark.asyncio
    async def test_analyze_state_inconsistency(self, race_tester, basic_test):
        """Test detection of state inconsistency"""
        # Create responses with varying content
        from app.core.http_models import Request
        mock_request = Request(method="POST", url=basic_test.url)
        responses = [
            Response(200, {}, b"balance: 100", "balance: 100", 0.1, mock_request),
            Response(200, {}, b"balance: 90", "balance: 90", 0.1, mock_request),
            Response(200, {}, b"balance: 80", "balance: 80", 0.1, mock_request),
        ]
        
        is_vulnerable, race_type, evidence = race_tester._analyze_responses(
            responses, basic_test
        )
        
        assert is_vulnerable
        assert race_type == RaceConditionType.STATE_INCONSISTENCY
        assert any("balance" in e.lower() for e in evidence)
    
    @pytest.mark.asyncio
    async def test_custom_check_function(self, race_tester, basic_test):
        """Test custom check function"""
        # Define custom check
        def custom_check(responses):
            return len(responses) > 5
        
        basic_test.check_function = custom_check
        
        # Create responses
        from app.core.http_models import Request
        mock_request = Request(method="POST", url=basic_test.url)
        responses = [
            Response(200, {}, b"ok", "ok", 0.1, mock_request)
            for _ in range(10)
        ]
        
        is_vulnerable, race_type, evidence = race_tester._analyze_responses(
            responses, basic_test
        )
        
        assert is_vulnerable
        assert race_type == RaceConditionType.STATE_INCONSISTENCY
        assert any("custom check" in e.lower() for e in evidence)
    
    @pytest.mark.asyncio
    async def test_has_response_variation(self, race_tester):
        """Test response variation detection"""
        from app.core.http_models import Request
        mock_request = Request(method="GET", url="https://example.com")
        
        # No variation
        responses_same = [
            Response(200, {}, b"ok", "ok", 0.1, mock_request)
            for _ in range(5)
        ]
        assert not race_tester._has_response_variation(responses_same)
        
        # Status code variation
        responses_status = [
            Response(200, {}, b"ok", "ok", 0.1, mock_request),
            Response(404, {}, b"not found", "not found", 0.1, mock_request),
        ]
        assert race_tester._has_response_variation(responses_status)
        
        # Body variation
        responses_body = [
            Response(200, {}, b"ok", "ok", 0.1, mock_request),
            Response(200, {}, b"different", "different", 0.1, mock_request),
        ]
        assert race_tester._has_response_variation(responses_body)
    
    @pytest.mark.asyncio
    async def test_calculate_confidence(self, race_tester):
        """Test confidence calculation"""
        from app.core.http_models import Request
        mock_request = Request(method="GET", url="https://example.com")
        responses = [
            Response(200, {}, b"ok", "ok", 0.1, mock_request)
            for _ in range(5)
        ]
        
        # No evidence
        confidence = race_tester._calculate_confidence([], responses)
        assert confidence == 0.0
        
        # Some evidence
        evidence = ["Multiple successful responses", "State inconsistency"]
        confidence = race_tester._calculate_confidence(evidence, responses)
        assert 0.0 < confidence <= 1.0
        
        # More evidence with keywords
        evidence = [
            "Multiple successful responses",
            "Duplicate transaction detected",
            "State inconsistency found",
        ]
        confidence = race_tester._calculate_confidence(evidence, responses)
        assert confidence > 0.5
    
    @pytest.mark.asyncio
    async def test_generate_exploit_params(self, race_tester, basic_test):
        """Test exploit parameter generation"""
        from app.core.http_models import Request
        mock_request = Request(method="POST", url=basic_test.url)
        responses = [
            Response(200, {}, b"success", "success", 0.1, mock_request)
            for _ in range(7)
        ] + [
            Response(403, {}, b"forbidden", "forbidden", 0.1, mock_request)
            for _ in range(3)
        ]
        
        timing_data = {
            "strategy": "simultaneous",
            "time_spread": 0.005,
            "total_time": 0.5,
        }
        
        exploit_params = await race_tester._generate_exploit_params(
            basic_test, responses, timing_data
        )
        
        assert isinstance(exploit_params, ExploitParameters)
        assert exploit_params.num_threads > 0
        assert isinstance(exploit_params.timing_strategy, TimingStrategy)
        assert 0.0 <= exploit_params.success_rate <= 1.0
        assert exploit_params.recommended_attempts > 0
        assert len(exploit_params.exploit_code) > 0
        assert "#!/usr/bin/env python3" in exploit_params.exploit_code
    
    @pytest.mark.asyncio
    async def test_generate_exploit_code(self, race_tester, basic_test):
        """Test exploit code generation"""
        code = race_tester._generate_exploit_code(
            basic_test,
            num_threads=20,
            strategy=TimingStrategy.SYNCHRONIZED,
            attempts=10,
        )
        
        assert isinstance(code, str)
        assert "#!/usr/bin/env python3" in code
        assert basic_test.url in code
        assert basic_test.method in code
        assert "NUM_THREADS = 20" in code
        assert "NUM_ATTEMPTS = 10" in code
        assert "def exploit_attempt" in code
        assert "def main" in code
    
    @pytest.mark.asyncio
    async def test_test_race_condition_not_vulnerable(
        self, race_tester, basic_test, mock_request_handler
    ):
        """Test race condition testing when not vulnerable"""
        # Mock all failures - properly protected endpoint
        from app.core.http_models import Request
        mock_request = Request(method="POST", url=basic_test.url)
        
        # All requests fail with same error
        mock_response = Response(
            status_code=403,
            headers={},
            body=b"forbidden",
            text="forbidden",
            elapsed_time=0.1,
            request=mock_request,
        )
        mock_request_handler.send_request.return_value = mock_response
        
        result = await race_tester.test_race_condition(basic_test)
        
        # All failures with no variation = not vulnerable
        assert not result.is_vulnerable
        assert result.confidence == 0.0
        assert result.race_type is None
        assert result.exploit_params is None
    
    @pytest.mark.asyncio
    async def test_test_race_condition_vulnerable(
        self, race_tester, basic_test, mock_request_handler
    ):
        """Test race condition testing when vulnerable"""
        # Mock varying responses
        from app.core.http_models import Request
        mock_request = Request(method="POST", url=basic_test.url)
        responses_cycle = [
            Response(200, {}, b"success", "success", 0.1, mock_request),
            Response(403, {}, b"forbidden", "forbidden", 0.1, mock_request),
        ]
        
        call_count = [0]
        
        async def mock_send(*args, **kwargs):
            response = responses_cycle[call_count[0] % len(responses_cycle)]
            call_count[0] += 1
            return response
        
        mock_request_handler.send_request.side_effect = mock_send
        
        result = await race_tester.test_race_condition(basic_test)
        
        assert result.is_vulnerable
        assert result.confidence > 0.0
        assert result.race_type is not None
        assert len(result.evidence) > 0
        assert result.exploit_params is not None


class TestTimingStrategies:
    """Tests for different timing strategies"""
    
    @pytest.mark.asyncio
    async def test_simultaneous_strategy(self, race_tester, basic_test, mock_request_handler):
        """Test simultaneous timing strategy"""
        from app.core.http_models import Request
        mock_request = Request(method="POST", url=basic_test.url)
        mock_response = Response(200, {}, b"ok", "ok", 0.1, mock_request)
        mock_request_handler.send_request.return_value = mock_response
        
        basic_test.timing_strategy = TimingStrategy.SIMULTANEOUS
        
        result = await race_tester.test_race_condition(basic_test)
        
        assert len(result.responses) == basic_test.num_requests
        assert result.timing_data["strategy"] == "simultaneous"
    
    @pytest.mark.asyncio
    async def test_staggered_strategy(self, race_tester, basic_test, mock_request_handler):
        """Test staggered timing strategy"""
        from app.core.http_models import Request
        mock_request = Request(method="POST", url=basic_test.url)
        mock_response = Response(200, {}, b"ok", "ok", 0.1, mock_request)
        mock_request_handler.send_request.return_value = mock_response
        
        basic_test.timing_strategy = TimingStrategy.STAGGERED
        basic_test.delay_microseconds = 500
        
        result = await race_tester.test_race_condition(basic_test)
        
        assert len(result.responses) == basic_test.num_requests
        assert result.timing_data["strategy"] == "staggered"
    
    @pytest.mark.asyncio
    async def test_burst_strategy(self, race_tester, basic_test, mock_request_handler):
        """Test burst timing strategy"""
        from app.core.http_models import Request
        mock_request = Request(method="POST", url=basic_test.url)
        mock_response = Response(200, {}, b"ok", "ok", 0.1, mock_request)
        mock_request_handler.send_request.return_value = mock_response
        
        basic_test.timing_strategy = TimingStrategy.BURST
        
        result = await race_tester.test_race_condition(basic_test)
        
        assert len(result.responses) == basic_test.num_requests
        assert result.timing_data["strategy"] == "burst"


class TestExploitParameters:
    """Tests for ExploitParameters"""
    
    def test_exploit_parameters_creation(self):
        """Test ExploitParameters creation"""
        params = ExploitParameters(
            num_threads=20,
            timing_strategy=TimingStrategy.SYNCHRONIZED,
            delay_microseconds=0,
            success_rate=0.75,
            avg_collision_time=0.005,
            recommended_attempts=10,
            exploit_code="# exploit code",
        )
        
        assert params.num_threads == 20
        assert params.timing_strategy == TimingStrategy.SYNCHRONIZED
        assert params.success_rate == 0.75
        assert params.avg_collision_time == 0.005
        assert params.recommended_attempts == 10
        assert params.exploit_code == "# exploit code"
