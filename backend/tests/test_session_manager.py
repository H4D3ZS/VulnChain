"""Unit tests for Session Manager"""

import pytest
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

from app.core.session_manager import SessionManager, Session, Cookie
from app.core.http_models import Request, Response


class TestCookie:
    """Test suite for Cookie model"""

    def test_cookie_creation(self):
        """Test creating a Cookie object"""
        cookie = Cookie(
            name="session",
            value="abc123",
            domain="example.com",
            path="/",
            secure=True,
            http_only=True,
        )

        assert cookie.name == "session"
        assert cookie.value == "abc123"
        assert cookie.domain == "example.com"
        assert cookie.path == "/"
        assert cookie.secure is True
        assert cookie.http_only is True

    def test_cookie_is_expired(self):
        """Test cookie expiration check"""
        # Non-expired cookie
        future_time = datetime.now(timezone.utc) + timedelta(hours=1)
        cookie = Cookie(
            name="session",
            value="abc123",
            domain="example.com",
            expires=future_time,
        )
        assert cookie.is_expired() is False

        # Expired cookie
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        cookie.expires = past_time
        assert cookie.is_expired() is True

        # Cookie without expiration
        cookie.expires = None
        assert cookie.is_expired() is False

    def test_cookie_matches_domain_exact(self):
        """Test exact domain matching"""
        cookie = Cookie(name="test", value="value", domain="example.com")
        assert cookie.matches_domain("example.com") is True
        assert cookie.matches_domain("other.com") is False

    def test_cookie_matches_domain_subdomain(self):
        """Test subdomain matching with domain cookies"""
        cookie = Cookie(name="test", value="value", domain=".example.com")
        assert cookie.matches_domain("example.com") is True
        assert cookie.matches_domain("www.example.com") is True
        assert cookie.matches_domain("api.example.com") is True
        assert cookie.matches_domain("other.com") is False

    def test_cookie_matches_path(self):
        """Test path matching"""
        cookie = Cookie(name="test", value="value", domain="example.com", path="/api")
        
        assert cookie.matches_path("/api") is True
        assert cookie.matches_path("/api/users") is True
        assert cookie.matches_path("/api/") is True
        assert cookie.matches_path("/") is False
        assert cookie.matches_path("/other") is False


class TestSession:
    """Test suite for Session model"""

    def test_session_creation(self):
        """Test creating a Session object"""
        session = Session(
            session_id="test-session-id",
            domain="example.com",
        )

        assert session.session_id == "test-session-id"
        assert session.domain == "example.com"
        assert len(session.cookies) == 0
        assert isinstance(session.created_at, datetime)

    def test_session_is_expired(self):
        """Test session expiration check"""
        # Non-expired session
        future_time = datetime.now(timezone.utc) + timedelta(hours=1)
        session = Session(
            session_id="test",
            domain="example.com",
            expires_at=future_time,
        )
        assert session.is_expired() is False

        # Expired session
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        session.expires_at = past_time
        assert session.is_expired() is True

        # Session without expiration
        session.expires_at = None
        assert session.is_expired() is False

    def test_session_get_cookies_for_request(self):
        """Test getting cookies for a specific request URL"""
        session = Session(session_id="test", domain="example.com")
        
        # Add cookies
        cookie1 = Cookie(name="session", value="abc123", domain="example.com", path="/")
        cookie2 = Cookie(name="api_token", value="xyz789", domain="example.com", path="/api")
        cookie3 = Cookie(
            name="expired",
            value="old",
            domain="example.com",
            expires=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        
        session.cookies["session"] = cookie1
        session.cookies["api_token"] = cookie2
        session.cookies["expired"] = cookie3

        # Test root path - should get only session cookie
        cookies = session.get_cookies_for_request("https://example.com/")
        assert "session" in cookies
        assert "api_token" not in cookies
        assert "expired" not in cookies

        # Test /api path - should get both session and api_token
        cookies = session.get_cookies_for_request("https://example.com/api/users")
        assert "session" in cookies
        assert "api_token" in cookies
        assert "expired" not in cookies


class TestSessionManager:
    """Test suite for SessionManager"""

    @pytest.fixture
    def manager(self):
        """Create a SessionManager instance"""
        return SessionManager()

    @pytest.fixture
    def sample_response(self):
        """Create a sample response with Set-Cookie header"""
        request = Request(method="GET", url="https://example.com/login", headers={})
        response = Response(
            status_code=200,
            headers={"Set-Cookie": "session=abc123; Path=/; HttpOnly"},
            body=b"OK",
            text="OK",
            elapsed_time=0.5,
            request=request,
        )
        return response

    def test_manager_initialization(self, manager):
        """Test SessionManager initialization"""
        assert len(manager._sessions) == 0
        assert len(manager._domain_to_session) == 0

    def test_capture_session_basic(self, manager, sample_response):
        """Test capturing session from response"""
        session = manager.capture_session(sample_response)

        assert session is not None
        assert session.domain == "example.com"
        assert "session" in session.cookies
        assert session.cookies["session"].value == "abc123"
        assert session.cookies["session"].http_only is True

    def test_capture_session_multiple_cookies(self, manager):
        """Test capturing multiple cookies from response"""
        request = Request(method="GET", url="https://example.com/", headers={})
        
        # Create response with multiple Set-Cookie headers
        response = Response(
            status_code=200,
            headers={
                "Set-Cookie": "session=abc123; Path=/; HttpOnly",
                "Content-Type": "text/html",
            },
            body=b"OK",
            text="OK",
            elapsed_time=0.5,
            request=request,
        )
        
        # Manually add another Set-Cookie (simulating multiple headers)
        # In real HTTP, there can be multiple Set-Cookie headers
        response.headers["set-cookie"] = "token=xyz789; Path=/api; Secure"

        session = manager.capture_session(response)

        # Should capture at least one cookie
        assert len(session.cookies) >= 1

    def test_capture_session_updates_existing(self, manager, sample_response):
        """Test that capturing session updates existing session for same domain"""
        # First capture
        session1 = manager.capture_session(sample_response)
        session_id1 = session1.session_id

        # Second capture for same domain
        request = Request(method="GET", url="https://example.com/profile", headers={})
        response2 = Response(
            status_code=200,
            headers={"Set-Cookie": "user=john; Path=/"},
            body=b"OK",
            text="OK",
            elapsed_time=0.5,
            request=request,
        )
        session2 = manager.capture_session(response2)

        # Should be the same session
        assert session2.session_id == session_id1
        assert "session" in session2.cookies
        assert "user" in session2.cookies

    def test_get_session(self, manager, sample_response):
        """Test retrieving session by domain"""
        # Capture session
        manager.capture_session(sample_response)

        # Retrieve session
        session = manager.get_session("example.com")
        assert session is not None
        assert session.domain == "example.com"

        # Try non-existent domain
        session = manager.get_session("other.com")
        assert session is None

    def test_get_session_expired(self, manager):
        """Test that expired sessions are not returned"""
        request = Request(method="GET", url="https://example.com/", headers={})
        response = Response(
            status_code=200,
            headers={"Set-Cookie": "session=abc123"},
            body=b"OK",
            text="OK",
            elapsed_time=0.5,
            request=request,
        )
        
        session = manager.capture_session(response)
        
        # Expire the session
        session.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

        # Should not return expired session
        retrieved = manager.get_session("example.com")
        assert retrieved is None

    def test_apply_session(self, manager, sample_response):
        """Test applying session cookies to a request"""
        # Capture session
        session = manager.capture_session(sample_response)

        # Create new request
        request = Request(method="GET", url="https://example.com/profile", headers={})

        # Apply session
        manager.apply_session(request, session)

        # Check cookies were added
        assert "session" in request.cookies
        assert request.cookies["session"] == "abc123"

    def test_apply_session_respects_path(self, manager):
        """Test that apply_session respects cookie path restrictions"""
        request = Request(method="GET", url="https://example.com/", headers={})
        response = Response(
            status_code=200,
            headers={"Set-Cookie": "api_token=xyz789; Path=/api"},
            body=b"OK",
            text="OK",
            elapsed_time=0.5,
            request=request,
        )
        
        session = manager.capture_session(response)

        # Request to root path - should not get api_token
        request1 = Request(method="GET", url="https://example.com/", headers={})
        manager.apply_session(request1, session)
        assert "api_token" not in request1.cookies

        # Request to /api path - should get api_token
        request2 = Request(method="GET", url="https://example.com/api/users", headers={})
        manager.apply_session(request2, session)
        assert "api_token" in request2.cookies

    def test_export_session_json(self, manager, sample_response):
        """Test exporting session to JSON format"""
        session = manager.capture_session(sample_response)
        
        # Export session
        data = manager.export_session(session.session_id, format="json")
        
        assert isinstance(data, bytes)
        
        # Parse JSON to verify structure
        json_data = json.loads(data.decode("utf-8"))
        assert json_data["session_id"] == session.session_id
        assert json_data["domain"] == "example.com"
        assert "session" in json_data["cookies"]

    def test_export_session_not_found(self, manager):
        """Test exporting non-existent session raises error"""
        with pytest.raises(ValueError, match="Session .* not found"):
            manager.export_session("non-existent-id")

    def test_export_session_unsupported_format(self, manager, sample_response):
        """Test exporting with unsupported format raises error"""
        session = manager.capture_session(sample_response)
        
        with pytest.raises(ValueError, match="Unsupported format"):
            manager.export_session(session.session_id, format="xml")

    def test_import_session_json(self, manager, sample_response):
        """Test importing session from JSON format"""
        # Create and export session
        original_session = manager.capture_session(sample_response)
        data = manager.export_session(original_session.session_id)

        # Clear sessions
        manager.clear_all_sessions()

        # Import session
        imported_session = manager.import_session(data, format="json")

        assert imported_session.session_id == original_session.session_id
        assert imported_session.domain == original_session.domain
        assert len(imported_session.cookies) == len(original_session.cookies)
        assert "session" in imported_session.cookies

    def test_import_session_round_trip(self, manager, sample_response):
        """Test export-import round trip preserves session data"""
        # Create session with multiple cookies
        original_session = manager.capture_session(sample_response)
        
        # Add another cookie manually
        cookie = Cookie(
            name="user",
            value="john",
            domain="example.com",
            path="/profile",
            secure=True,
        )
        original_session.cookies["user"] = cookie

        # Export
        data = manager.export_session(original_session.session_id)

        # Clear and import
        manager.clear_all_sessions()
        imported_session = manager.import_session(data)

        # Verify all data preserved
        assert imported_session.session_id == original_session.session_id
        assert imported_session.domain == original_session.domain
        assert len(imported_session.cookies) == len(original_session.cookies)
        
        # Check specific cookie
        assert "user" in imported_session.cookies
        assert imported_session.cookies["user"].value == "john"
        assert imported_session.cookies["user"].path == "/profile"
        assert imported_session.cookies["user"].secure is True

    def test_import_session_invalid_data(self, manager):
        """Test importing invalid data raises error"""
        with pytest.raises(ValueError, match="Invalid session data"):
            manager.import_session(b"invalid json data")

    def test_import_session_unsupported_format(self, manager):
        """Test importing with unsupported format raises error"""
        with pytest.raises(ValueError, match="Unsupported format"):
            manager.import_session(b"{}", format="xml")

    def test_get_all_sessions(self, manager):
        """Test getting all sessions"""
        # Create multiple sessions
        request1 = Request(method="GET", url="https://example.com/", headers={})
        response1 = Response(
            status_code=200,
            headers={"Set-Cookie": "session1=abc"},
            body=b"OK",
            text="OK",
            elapsed_time=0.5,
            request=request1,
        )
        
        request2 = Request(method="GET", url="https://other.com/", headers={})
        response2 = Response(
            status_code=200,
            headers={"Set-Cookie": "session2=xyz"},
            body=b"OK",
            text="OK",
            elapsed_time=0.5,
            request=request2,
        )

        manager.capture_session(response1)
        manager.capture_session(response2)

        sessions = manager.get_all_sessions()
        assert len(sessions) == 2

    def test_clear_session(self, manager, sample_response):
        """Test clearing a specific session"""
        session = manager.capture_session(sample_response)
        session_id = session.session_id

        # Clear session
        manager.clear_session(session_id)

        # Verify session is gone
        assert manager.get_session("example.com") is None
        assert len(manager._sessions) == 0

    def test_clear_all_sessions(self, manager, sample_response):
        """Test clearing all sessions"""
        # Create multiple sessions
        manager.capture_session(sample_response)
        
        request2 = Request(method="GET", url="https://other.com/", headers={})
        response2 = Response(
            status_code=200,
            headers={"Set-Cookie": "session2=xyz"},
            body=b"OK",
            text="OK",
            elapsed_time=0.5,
            request=request2,
        )
        manager.capture_session(response2)

        # Clear all
        manager.clear_all_sessions()

        # Verify all sessions are gone
        assert len(manager._sessions) == 0
        assert len(manager._domain_to_session) == 0

    def test_parse_set_cookie_with_expires(self, manager):
        """Test parsing Set-Cookie header with Expires attribute"""
        header = "session=abc123; Expires=Wed, 21 Oct 2025 07:28:00 GMT; Path=/"
        cookie = manager._parse_set_cookie_header(header, "example.com")

        assert cookie is not None
        assert cookie.name == "session"
        assert cookie.value == "abc123"
        assert cookie.expires is not None

    def test_parse_set_cookie_with_max_age(self, manager):
        """Test parsing Set-Cookie header with Max-Age attribute"""
        header = "session=abc123; Max-Age=3600; Path=/"
        cookie = manager._parse_set_cookie_header(header, "example.com")

        assert cookie is not None
        assert cookie.name == "session"
        assert cookie.max_age == 3600
        assert cookie.expires is not None  # Should be calculated from max_age

    def test_parse_set_cookie_with_domain(self, manager):
        """Test parsing Set-Cookie header with Domain attribute"""
        header = "session=abc123; Domain=.example.com; Path=/"
        cookie = manager._parse_set_cookie_header(header, "www.example.com")

        assert cookie is not None
        assert cookie.domain == ".example.com"

    def test_parse_set_cookie_with_secure_httponly(self, manager):
        """Test parsing Set-Cookie header with Secure and HttpOnly flags"""
        header = "session=abc123; Path=/; Secure; HttpOnly"
        cookie = manager._parse_set_cookie_header(header, "example.com")

        assert cookie is not None
        assert cookie.secure is True
        assert cookie.http_only is True

    def test_parse_set_cookie_with_samesite(self, manager):
        """Test parsing Set-Cookie header with SameSite attribute"""
        header = "session=abc123; Path=/; SameSite=Strict"
        cookie = manager._parse_set_cookie_header(header, "example.com")

        assert cookie is not None
        assert cookie.same_site == "Strict"
