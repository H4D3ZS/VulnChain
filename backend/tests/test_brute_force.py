"""Tests for brute-force login module"""

import asyncio
import pytest
from unittest.mock import AsyncMock, Mock, patch
from app.modules.brute_force import (
    BruteForceTester,
    BruteForceAttack,
    LoginConfig,
    LoginMethod,
    SuccessDetectionMethod,
    ResponseProfile,
)
from app.core.request_handler import Response
from app.core.session_manager import Session, Cookie


@pytest.fixture
def mock_request_handler():
    """Create mock request handler"""
    handler = Mock()
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def mock_session_manager():
    """Create mock session manager"""
    manager = Mock()
    manager.capture_session = Mock()
    return manager


@pytest.fixture
def brute_force_tester(mock_request_handler, mock_session_manager):
    """Create brute-force tester instance"""
    return BruteForceTester(mock_request_handler, mock_session_manager)


@pytest.fixture
def brute_force_attack(mock_request_handler, mock_session_manager):
    """Create brute-force attack instance"""
    return BruteForceAttack(mock_request_handler, mock_session_manager)


@pytest.fixture
def login_config():
    """Create basic login configuration"""
    return LoginConfig(
        url="http://example.com/login",
        method=LoginMethod.POST,
        username_param="username",
        password_param="password",
        success_detection=SuccessDetectionMethod.REGEX,
        success_regex=r"Welcome|Dashboard",
        failure_regex=r"Invalid|Failed",
    )


class TestLoginConfig:
    """Test LoginConfig dataclass"""
    
    def test_default_values(self):
        """Test default configuration values"""
        config = LoginConfig(url="http://example.com/login")
        
        assert config.method == LoginMethod.POST
        assert config.username_param == "username"
        assert config.password_param == "password"
        assert config.delay_between_attempts == 0.5
        assert config.adaptive_delay is True
        assert config.max_concurrent == 5
    
    def test_custom_values(self):
        """Test custom configuration values"""
        config = LoginConfig(
            url="http://example.com/login",
            method=LoginMethod.GET,
            username_param="user",
            password_param="pass",
            delay_between_attempts=1.0,
            max_concurrent=10,
        )
        
        assert config.method == LoginMethod.GET
        assert config.username_param == "user"
        assert config.password_param == "pass"
        assert config.delay_between_attempts == 1.0
        assert config.max_concurrent == 10


class TestSuccessDetection:
    """Test success detection methods"""
    
    @pytest.mark.asyncio
    async def test_regex_success_detection(self, brute_force_tester, login_config):
        """Test regex-based success detection"""
        # Mock successful response
        mock_response = Mock(spec=Response)
        mock_response.text = "Welcome to the dashboard!"
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.request = Mock(url="http://example.com/login")
        
        brute_force_tester.request_handler.send_request.return_value = mock_response
        
        # Mock session
        mock_session = Mock(spec=Session)
        mock_session.session_id = "test-session"
        mock_session.cookies = {"session": Mock()}
        brute_force_tester.session_manager.capture_session.return_value = mock_session
        
        # Test credentials
        result = await brute_force_tester._test_credentials(
            login_config, "admin", "password"
        )
        
        assert result.success is True
        assert result.username == "admin"
        assert result.password == "password"
    
    @pytest.mark.asyncio
    async def test_regex_failure_detection(self, brute_force_tester, login_config):
        """Test regex-based failure detection"""
        # Mock failed response
        mock_response = Mock(spec=Response)
        mock_response.text = "Invalid username or password"
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.request = Mock(url="http://example.com/login")
        
        brute_force_tester.request_handler.send_request.return_value = mock_response
        
        # Test credentials
        result = await brute_force_tester._test_credentials(
            login_config, "admin", "wrong"
        )
        
        assert result.success is False
    
    @pytest.mark.asyncio
    async def test_status_code_detection(self, brute_force_tester):
        """Test status code-based success detection"""
        config = LoginConfig(
            url="http://example.com/login",
            success_detection=SuccessDetectionMethod.STATUS_CODE,
            success_status_codes=[200, 302],
        )
        
        # Mock successful response with redirect
        mock_response = Mock(spec=Response)
        mock_response.text = ""
        mock_response.status_code = 302
        mock_response.headers = {"Location": "/dashboard"}
        mock_response.request = Mock(url="http://example.com/login")
        
        brute_force_tester.request_handler.send_request.return_value = mock_response
        
        # Mock session
        mock_session = Mock(spec=Session)
        mock_session.session_id = "test-session"
        mock_session.cookies = {"session": Mock()}
        brute_force_tester.session_manager.capture_session.return_value = mock_session
        
        result = await brute_force_tester._test_credentials(
            config, "admin", "password"
        )
        
        assert result.success is True
    
    @pytest.mark.asyncio
    async def test_redirect_detection(self, brute_force_tester):
        """Test redirect-based success detection"""
        config = LoginConfig(
            url="http://example.com/login",
            success_detection=SuccessDetectionMethod.REDIRECT,
        )
        
        # Mock response with redirect
        mock_response = Mock(spec=Response)
        mock_response.text = ""
        mock_response.status_code = 302
        mock_response.headers = {"Location": "/dashboard"}
        mock_response.request = Mock(url="http://example.com/login")
        
        brute_force_tester.request_handler.send_request.return_value = mock_response
        
        # Mock session
        mock_session = Mock(spec=Session)
        mock_session.session_id = "test-session"
        mock_session.cookies = {"session": Mock()}
        brute_force_tester.session_manager.capture_session.return_value = mock_session
        
        result = await brute_force_tester._test_credentials(
            config, "admin", "password"
        )
        
        assert result.success is True
    
    @pytest.mark.asyncio
    async def test_cookie_detection(self, brute_force_tester):
        """Test cookie-based success detection"""
        config = LoginConfig(
            url="http://example.com/login",
            success_detection=SuccessDetectionMethod.COOKIE,
        )
        
        # Mock response with cookies
        mock_response = Mock(spec=Response)
        mock_response.text = ""
        mock_response.status_code = 200
        mock_response.headers = {"Set-Cookie": "session=abc123; Path=/"}
        mock_response.request = Mock(url="http://example.com/login")
        
        brute_force_tester.request_handler.send_request.return_value = mock_response
        
        # Mock session
        mock_session = Mock(spec=Session)
        mock_session.session_id = "test-session"
        mock_session.cookies = {"session": Mock()}
        brute_force_tester.session_manager.capture_session.return_value = mock_session
        
        result = await brute_force_tester._test_credentials(
            config, "admin", "password"
        )
        
        assert result.success is True


class TestSessionCapture:
    """Test automatic session capture"""
    
    @pytest.mark.asyncio
    async def test_session_captured_on_success(self, brute_force_tester, login_config):
        """Test that session is captured on successful login"""
        # Mock successful response
        mock_response = Mock(spec=Response)
        mock_response.text = "Welcome to the dashboard!"
        mock_response.status_code = 200
        mock_response.headers = {"Set-Cookie": "session=abc123"}
        mock_response.request = Mock(url="http://example.com/login")
        
        brute_force_tester.request_handler.send_request.return_value = mock_response
        
        # Mock session
        mock_session = Mock(spec=Session)
        mock_session.session_id = "test-session-id"
        mock_session.cookies = {"session": Mock()}
        brute_force_tester.session_manager.capture_session.return_value = mock_session
        
        # Test credentials
        result = await brute_force_tester._test_credentials(
            login_config, "admin", "password"
        )
        
        assert result.success is True
        assert result.session is not None
        assert result.session.session_id == "test-session-id"
        brute_force_tester.session_manager.capture_session.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_no_session_on_failure(self, brute_force_tester, login_config):
        """Test that session is not captured on failed login"""
        # Mock failed response
        mock_response = Mock(spec=Response)
        mock_response.text = "Invalid credentials"
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.request = Mock(url="http://example.com/login")
        
        brute_force_tester.request_handler.send_request.return_value = mock_response
        
        # Test credentials
        result = await brute_force_tester._test_credentials(
            login_config, "admin", "wrong"
        )
        
        assert result.success is False
        assert result.session is None
        brute_force_tester.session_manager.capture_session.assert_not_called()


class TestUsernameEnumeration:
    """Test username enumeration functionality"""
    
    @pytest.mark.asyncio
    async def test_username_enumeration_by_content_length(self, brute_force_tester, login_config):
        """Test username enumeration based on content length differences"""
        # Mock responses with different lengths
        def mock_send_request(method, url, headers=None, data=None, cookies=None):
            response = Mock(spec=Response)
            response.status_code = 200
            response.headers = {}
            response.request = Mock(url=url)
            
            # Different response for valid username
            if data and data.get("username") == "admin":
                response.text = "Invalid password for user admin" * 10  # Longer
            else:
                response.text = "Invalid username"  # Shorter
            
            return response
        
        brute_force_tester.request_handler.send_request = AsyncMock(
            side_effect=mock_send_request
        )
        
        # Enumerate usernames
        results = await brute_force_tester.enumerate_usernames(
            login_config, ["admin", "invalid"]
        )
        
        # Check results
        admin_result = next(r for r in results if r.username == "admin")
        invalid_result = next(r for r in results if r.username == "invalid")
        
        assert admin_result.exists is True
        assert admin_result.confidence > 0.3
        assert invalid_result.exists is False
    
    @pytest.mark.asyncio
    async def test_username_enumeration_by_timing(self, brute_force_tester, login_config):
        """Test username enumeration based on timing differences"""
        import asyncio
        
        # Mock responses with different timing
        async def mock_send_request(method, url, headers=None, data=None, cookies=None):
            response = Mock(spec=Response)
            response.status_code = 200
            response.headers = {}
            response.request = Mock(url=url)
            response.text = "Invalid credentials"
            
            # Slower response for valid username
            if data and data.get("username") == "admin":
                await asyncio.sleep(0.6)  # Simulate slower response
            else:
                await asyncio.sleep(0.1)
            
            return response
        
        brute_force_tester.request_handler.send_request = mock_send_request
        
        # Enumerate usernames
        results = await brute_force_tester.enumerate_usernames(
            login_config, ["admin", "invalid"]
        )
        
        # Check results
        admin_result = next(r for r in results if r.username == "admin")
        invalid_result = next(r for r in results if r.username == "invalid")
        
        # Admin should have longer response time
        assert admin_result.response_time > invalid_result.response_time


class TestResponseProfile:
    """Test response profile comparison"""
    
    def test_profile_comparison_identical(self, brute_force_tester):
        """Test comparison of identical profiles"""
        profile1 = ResponseProfile(
            status_code=200,
            content_length=1000,
            response_time=0.5,
            has_redirect=False,
            response_hash="abc123",
        )
        
        profile2 = ResponseProfile(
            status_code=200,
            content_length=1000,
            response_time=0.5,
            has_redirect=False,
            response_hash="abc123",
        )
        
        exists, confidence, evidence = brute_force_tester._compare_profiles(
            profile1, profile2, "test"
        )
        
        assert exists is False  # No difference means username doesn't exist
        assert confidence < 0.3
    
    def test_profile_comparison_different(self, brute_force_tester):
        """Test comparison of different profiles"""
        baseline = ResponseProfile(
            status_code=200,
            content_length=1000,
            response_time=0.5,
            has_redirect=False,
            response_hash="abc123",
        )
        
        test = ResponseProfile(
            status_code=200,
            content_length=1500,  # Different length
            response_time=1.2,  # Different timing
            has_redirect=False,
            response_hash="def456",  # Different content
        )
        
        exists, confidence, evidence = brute_force_tester._compare_profiles(
            baseline, test, "admin"
        )
        
        assert exists is True  # Differences suggest username exists
        assert confidence >= 0.3
        assert len(evidence) > 0


class TestBruteForceAttack:
    """Test complete brute-force attack"""
    
    @pytest.mark.asyncio
    async def test_successful_attack(self, brute_force_attack, login_config):
        """Test successful brute-force attack"""
        # Mock responses
        def mock_send_request(method, url, headers=None, data=None, cookies=None):
            response = Mock(spec=Response)
            response.status_code = 200
            response.headers = {}
            response.request = Mock(url=url)
            
            # Success for admin:password
            if data and data.get("username") == "admin" and data.get("password") == "password":
                response.text = "Welcome to the dashboard!"
            else:
                response.text = "Invalid credentials"
            
            return response
        
        brute_force_attack.tester.request_handler.send_request = AsyncMock(
            side_effect=mock_send_request
        )
        
        # Mock session capture
        mock_session = Mock(spec=Session)
        mock_session.session_id = "test-session"
        mock_session.cookies = {"session": Mock()}
        brute_force_attack.tester.session_manager.capture_session.return_value = mock_session
        
        # Execute attack
        results = await brute_force_attack.attack(
            login_config,
            ["admin", "user"],
            ["password", "wrong"],
            enumerate_first=False,
        )
        
        assert results["total_attempts"] == 4
        assert results["successful_attempts"] == 1
        assert len(results["successful_logins"]) == 1
        assert results["successful_logins"][0]["username"] == "admin"
        assert results["successful_logins"][0]["password"] == "password"


class TestAdaptiveTiming:
    """Test adaptive timing functionality"""
    
    @pytest.mark.asyncio
    async def test_delay_increases_on_slow_responses(self, brute_force_tester, login_config):
        """Test that delay increases when responses slow down"""
        import asyncio
        
        # Track delays
        delays = []
        
        # Mock responses that get progressively slower
        call_count = [0]
        
        async def mock_send_request(method, url, headers=None, data=None, cookies=None):
            call_count[0] += 1
            response = Mock(spec=Response)
            response.status_code = 200
            response.headers = {}
            response.request = Mock(url=url)
            response.text = "Invalid"
            
            # Simulate increasing response time
            await asyncio.sleep(0.1 * call_count[0])
            
            return response
        
        brute_force_tester.request_handler.send_request = mock_send_request
        
        # Initial delay
        initial_delay = brute_force_tester._current_delay
        
        # Test multiple credentials (need at least 20 failures to trigger delay increase)
        for i in range(25):
            result = await brute_force_tester._test_credentials(
                login_config, f"user{i}", "password"
            )
            await brute_force_tester._adjust_delay(login_config, result)
        
        # Delay should have increased after 20 failures
        assert brute_force_tester._current_delay > initial_delay


class TestConcurrencyControl:
    """Test concurrent request handling"""
    
    @pytest.mark.asyncio
    async def test_max_concurrent_limit(self, brute_force_tester):
        """Test that max_concurrent limit is respected"""
        config = LoginConfig(
            url="http://example.com/login",
            max_concurrent=2,
            delay_between_attempts=0.1,
        )
        
        # Track concurrent requests
        active_requests = [0]
        max_concurrent = [0]
        
        async def mock_send_request(method, url, headers=None, data=None, cookies=None):
            active_requests[0] += 1
            max_concurrent[0] = max(max_concurrent[0], active_requests[0])
            
            await asyncio.sleep(0.2)  # Simulate request time
            
            active_requests[0] -= 1
            
            response = Mock(spec=Response)
            response.status_code = 200
            response.headers = {}
            response.request = Mock(url=url)
            response.text = "Invalid"
            
            return response
        
        brute_force_tester.request_handler.send_request = mock_send_request
        
        # Test with multiple credentials
        results = await brute_force_tester.brute_force_login(
            config,
            ["user1", "user2", "user3"],
            ["pass1", "pass2"],
        )
        
        # Max concurrent should not exceed limit
        assert max_concurrent[0] <= config.max_concurrent


class TestHTTPMethods:
    """Test different HTTP methods"""
    
    @pytest.mark.asyncio
    async def test_post_method(self, brute_force_tester):
        """Test POST method for login"""
        config = LoginConfig(
            url="http://example.com/login",
            method=LoginMethod.POST,
        )
        
        mock_response = Mock(spec=Response)
        mock_response.text = "Invalid"
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.request = Mock(url="http://example.com/login")
        
        brute_force_tester.request_handler.send_request = AsyncMock(
            return_value=mock_response
        )
        
        await brute_force_tester._test_credentials(config, "admin", "password")
        
        # Verify POST was used
        call_args = brute_force_tester.request_handler.send_request.call_args
        assert call_args[1]["method"] == "POST"
        assert "data" in call_args[1]
    
    @pytest.mark.asyncio
    async def test_get_method(self, brute_force_tester):
        """Test GET method for login"""
        config = LoginConfig(
            url="http://example.com/login",
            method=LoginMethod.GET,
        )
        
        mock_response = Mock(spec=Response)
        mock_response.text = "Invalid"
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.request = Mock(url="http://example.com/login")
        
        brute_force_tester.request_handler.send_request = AsyncMock(
            return_value=mock_response
        )
        
        await brute_force_tester._test_credentials(config, "admin", "password")
        
        # Verify GET was used with parameters in URL
        call_args = brute_force_tester.request_handler.send_request.call_args
        assert call_args[1]["method"] == "GET"
        assert "username=" in call_args[1]["url"]
        assert "password=" in call_args[1]["url"]
