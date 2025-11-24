"""Tests for target configuration models"""

import json
import pytest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from app.models.target import (
    TargetConfig,
    Session,
    RateLimit,
    URLValidationError,
    validate_url,
)


class TestURLValidation:
    """Test URL validation according to RFC 3986"""
    
    def test_valid_http_url(self):
        """Test that valid HTTP URLs are accepted"""
        assert validate_url("http://example.com") is True
    
    def test_valid_https_url(self):
        """Test that valid HTTPS URLs are accepted"""
        assert validate_url("https://example.com") is True
    
    def test_valid_url_with_port(self):
        """Test URL with explicit port"""
        assert validate_url("http://example.com:8080") is True
        assert validate_url("https://example.com:443") is True
    
    def test_valid_url_with_path(self):
        """Test URL with path"""
        assert validate_url("https://example.com/path/to/resource") is True
    
    def test_valid_url_with_query(self):
        """Test URL with query string"""
        assert validate_url("https://example.com/path?query=value&foo=bar") is True
    
    def test_valid_url_with_fragment(self):
        """Test URL with fragment"""
        assert validate_url("https://example.com/path#fragment") is True
    
    def test_valid_url_with_subdomain(self):
        """Test URL with subdomain"""
        assert validate_url("https://sub.domain.example.com") is True
    
    def test_valid_ipv4_url(self):
        """Test URL with IPv4 address"""
        assert validate_url("http://192.168.1.1") is True
        assert validate_url("http://192.168.1.1:8080") is True
    
    def test_valid_ipv6_url(self):
        """Test URL with IPv6 address"""
        assert validate_url("http://[2001:db8::1]") is True
        assert validate_url("http://[::1]:8080") is True
    
    def test_valid_localhost(self):
        """Test localhost URLs"""
        assert validate_url("http://localhost") is True
        assert validate_url("http://localhost:3000") is True
    
    def test_invalid_empty_url(self):
        """Test that empty URL is rejected"""
        with pytest.raises(URLValidationError, match="non-empty string"):
            validate_url("")
    
    def test_invalid_none_url(self):
        """Test that None is rejected"""
        with pytest.raises(URLValidationError, match="non-empty string"):
            validate_url(None)
    
    def test_invalid_missing_scheme(self):
        """Test that URL without scheme is rejected"""
        with pytest.raises(URLValidationError):
            validate_url("example.com")
    
    def test_invalid_unsupported_scheme(self):
        """Test that non-HTTP schemes are rejected"""
        with pytest.raises(URLValidationError, match="Unsupported scheme"):
            validate_url("ftp://example.com")
        
        with pytest.raises(URLValidationError, match="Unsupported scheme"):
            validate_url("file:///path/to/file")
    
    def test_invalid_port_range(self):
        """Test that invalid port numbers are rejected"""
        with pytest.raises(URLValidationError, match="Invalid port number"):
            validate_url("http://example.com:0")
        
        with pytest.raises(URLValidationError, match="Invalid port number"):
            validate_url("http://example.com:65536")
    
    def test_invalid_malformed_url(self):
        """Test that malformed URLs are rejected"""
        with pytest.raises(URLValidationError):
            validate_url("http://")
        
        with pytest.raises(URLValidationError):
            validate_url("http:///path")


class TestTargetConfig:
    """Test TargetConfig model"""
    
    def test_create_basic_target(self):
        """Test creating a basic target configuration"""
        target = TargetConfig(url="https://example.com")
        assert target.url == "https://example.com"
        assert target.custom_headers == {}
        assert target.proxy is None
        assert target.waf_bypass_profile is None
        assert target.rate_limit is None
        assert target.session_id is None
        assert isinstance(target.created_at, datetime)
        assert isinstance(target.updated_at, datetime)
    
    def test_create_target_with_headers(self):
        """Test creating target with custom headers"""
        headers = {"Authorization": "Bearer token123", "X-Custom": "value"}
        target = TargetConfig(url="https://example.com", custom_headers=headers)
        assert target.custom_headers == headers
    
    def test_create_target_with_proxy(self):
        """Test creating target with proxy"""
        target = TargetConfig(
            url="https://example.com",
            proxy="http://proxy.example.com:8080"
        )
        assert target.proxy == "http://proxy.example.com:8080"
    
    def test_create_target_with_waf_profile(self):
        """Test creating target with WAF bypass profile"""
        target = TargetConfig(
            url="https://example.com",
            waf_bypass_profile="cloudflare"
        )
        assert target.waf_bypass_profile == "cloudflare"
    
    def test_create_target_with_rate_limit(self):
        """Test creating target with rate limiting"""
        rate_limit = RateLimit(requests_per_second=5.0, burst_size=10)
        target = TargetConfig(url="https://example.com", rate_limit=rate_limit)
        assert target.rate_limit.requests_per_second == 5.0
        assert target.rate_limit.burst_size == 10
    
    def test_create_target_with_metadata(self):
        """Test creating target with name and description"""
        target = TargetConfig(
            url="https://example.com",
            name="Test Target",
            description="A test target for CTF"
        )
        assert target.name == "Test Target"
        assert target.description == "A test target for CTF"
    
    def test_invalid_url_raises_error(self):
        """Test that invalid URL raises error on creation"""
        with pytest.raises(URLValidationError):
            TargetConfig(url="not-a-valid-url")
    
    def test_invalid_proxy_raises_error(self):
        """Test that invalid proxy URL raises error"""
        with pytest.raises(URLValidationError):
            TargetConfig(url="https://example.com", proxy="invalid-proxy")
    
    def test_to_dict(self):
        """Test converting target to dictionary"""
        target = TargetConfig(
            url="https://example.com",
            custom_headers={"X-Test": "value"},
            proxy="http://proxy.example.com:8080",
            waf_bypass_profile="cloudflare"
        )
        data = target.to_dict()
        
        assert data["url"] == "https://example.com"
        assert data["custom_headers"] == {"X-Test": "value"}
        assert data["proxy"] == "http://proxy.example.com:8080"
        assert data["waf_bypass_profile"] == "cloudflare"
        assert isinstance(data["created_at"], str)
        assert isinstance(data["updated_at"], str)
    
    def test_from_dict(self):
        """Test creating target from dictionary"""
        data = {
            "url": "https://example.com",
            "custom_headers": {"X-Test": "value"},
            "proxy": "http://proxy.example.com:8080",
            "waf_bypass_profile": "cloudflare",
            "created_at": "2024-01-01T00:00:00+00:00",
            "updated_at": "2024-01-01T00:00:00+00:00"
        }
        target = TargetConfig.from_dict(data)
        
        assert target.url == "https://example.com"
        assert target.custom_headers == {"X-Test": "value"}
        assert target.proxy == "http://proxy.example.com:8080"
        assert target.waf_bypass_profile == "cloudflare"
        assert isinstance(target.created_at, datetime)
        assert isinstance(target.updated_at, datetime)
    
    def test_from_dict_with_rate_limit(self):
        """Test creating target from dictionary with rate limit"""
        data = {
            "url": "https://example.com",
            "rate_limit": {
                "requests_per_second": 5.0,
                "burst_size": 10
            }
        }
        target = TargetConfig.from_dict(data)
        
        assert target.rate_limit is not None
        assert target.rate_limit.requests_per_second == 5.0
        assert target.rate_limit.burst_size == 10
    
    def test_save_and_load(self):
        """Test saving and loading target configuration"""
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "target.json"
            
            # Create and save target
            original = TargetConfig(
                url="https://example.com",
                custom_headers={"X-Test": "value"},
                proxy="http://proxy.example.com:8080",
                waf_bypass_profile="cloudflare",
                name="Test Target"
            )
            original.save(filepath)
            
            # Load target
            loaded = TargetConfig.load(filepath)
            
            assert loaded.url == original.url
            assert loaded.custom_headers == original.custom_headers
            assert loaded.proxy == original.proxy
            assert loaded.waf_bypass_profile == original.waf_bypass_profile
            assert loaded.name == original.name
    
    def test_save_creates_directory(self):
        """Test that save creates parent directories"""
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "subdir" / "target.json"
            
            target = TargetConfig(url="https://example.com")
            target.save(filepath)
            
            assert filepath.exists()
            assert filepath.parent.exists()
    
    def test_load_nonexistent_file(self):
        """Test loading from nonexistent file raises error"""
        with pytest.raises(FileNotFoundError):
            TargetConfig.load(Path("/nonexistent/path/target.json"))
    
    def test_update_fields(self):
        """Test updating target configuration fields"""
        target = TargetConfig(url="https://example.com")
        original_updated_at = target.updated_at
        
        # Small delay to ensure timestamp changes
        import time
        time.sleep(0.01)
        
        target.update(
            custom_headers={"X-New": "header"},
            waf_bypass_profile="akamai"
        )
        
        assert target.custom_headers == {"X-New": "header"}
        assert target.waf_bypass_profile == "akamai"
        assert target.updated_at > original_updated_at
    
    def test_update_url_validates(self):
        """Test that updating URL validates the new URL"""
        target = TargetConfig(url="https://example.com")
        
        # Valid update should work
        target.update(url="https://newexample.com")
        assert target.url == "https://newexample.com"
        
        # Invalid update should raise error
        with pytest.raises(URLValidationError):
            target.update(url="invalid-url")
    
    def test_update_proxy_validates(self):
        """Test that updating proxy validates the new proxy URL"""
        target = TargetConfig(url="https://example.com")
        
        # Valid update should work
        target.update(proxy="http://proxy.example.com:8080")
        assert target.proxy == "http://proxy.example.com:8080"
        
        # Invalid update should raise error
        with pytest.raises(URLValidationError):
            target.update(proxy="invalid-proxy")


class TestSession:
    """Test Session model"""
    
    def test_create_session(self):
        """Test creating a session"""
        session = Session(
            session_id="sess123",
            domain="example.com",
            cookies={"session": "abc123"},
            headers={"Authorization": "Bearer token"}
        )
        
        assert session.session_id == "sess123"
        assert session.domain == "example.com"
        assert session.cookies == {"session": "abc123"}
        assert session.headers == {"Authorization": "Bearer token"}
        assert isinstance(session.created_at, datetime)
        assert session.expires_at is None
    
    def test_session_to_dict(self):
        """Test converting session to dictionary"""
        session = Session(
            session_id="sess123",
            domain="example.com",
            cookies={"session": "abc123"}
        )
        data = session.to_dict()
        
        assert data["session_id"] == "sess123"
        assert data["domain"] == "example.com"
        assert data["cookies"] == {"session": "abc123"}
        assert isinstance(data["created_at"], str)
    
    def test_session_from_dict(self):
        """Test creating session from dictionary"""
        data = {
            "session_id": "sess123",
            "domain": "example.com",
            "cookies": {"session": "abc123"},
            "headers": {},
            "created_at": "2024-01-01T00:00:00+00:00"
        }
        session = Session.from_dict(data)
        
        assert session.session_id == "sess123"
        assert session.domain == "example.com"
        assert isinstance(session.created_at, datetime)
    
    def test_session_not_expired(self):
        """Test that session without expiry is not expired"""
        session = Session(session_id="sess123", domain="example.com")
        assert session.is_expired() is False
    
    def test_session_expired(self):
        """Test that expired session is detected"""
        from datetime import timedelta
        
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        session = Session(
            session_id="sess123",
            domain="example.com",
            expires_at=past_time
        )
        assert session.is_expired() is True
    
    def test_session_not_yet_expired(self):
        """Test that future expiry is not expired"""
        from datetime import timedelta
        
        future_time = datetime.now(timezone.utc) + timedelta(hours=1)
        session = Session(
            session_id="sess123",
            domain="example.com",
            expires_at=future_time
        )
        assert session.is_expired() is False


class TestRateLimit:
    """Test RateLimit model"""
    
    def test_create_rate_limit(self):
        """Test creating rate limit configuration"""
        rate_limit = RateLimit(requests_per_second=5.0, burst_size=10)
        assert rate_limit.requests_per_second == 5.0
        assert rate_limit.burst_size == 10
    
    def test_default_rate_limit(self):
        """Test default rate limit values"""
        rate_limit = RateLimit()
        assert rate_limit.requests_per_second == 10.0
        assert rate_limit.burst_size == 20
