"""Tests for WAF bypass profile system"""

import pytest

from app.core.waf_profiles import (
    WAFBypassProfile,
    WAFProfileManager,
    get_waf_profile,
    list_waf_profiles,
    apply_waf_profile,
)


class TestWAFBypassProfile:
    """Test WAFBypassProfile model"""
    
    def test_create_profile(self):
        """Test creating a WAF bypass profile"""
        profile = WAFBypassProfile(
            name="test_profile",
            description="Test profile",
            headers={"X-Test": "value"},
            vendor="TestVendor",
            effectiveness="high"
        )
        
        assert profile.name == "test_profile"
        assert profile.description == "Test profile"
        assert profile.headers == {"X-Test": "value"}
        assert profile.vendor == "TestVendor"
        assert profile.effectiveness == "high"
    
    def test_apply_to_headers_empty(self):
        """Test applying profile to empty headers"""
        profile = WAFBypassProfile(
            name="test",
            description="Test",
            headers={"X-Forwarded-For": "127.0.0.1"}
        )
        
        result = profile.apply_to_headers({})
        assert result == {"X-Forwarded-For": "127.0.0.1"}
    
    def test_apply_to_headers_existing(self):
        """Test applying profile to existing headers"""
        profile = WAFBypassProfile(
            name="test",
            description="Test",
            headers={"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}
        )
        
        existing = {"User-Agent": "TestAgent", "Accept": "application/json"}
        result = profile.apply_to_headers(existing)
        
        assert result["User-Agent"] == "TestAgent"
        assert result["Accept"] == "application/json"
        assert result["X-Forwarded-For"] == "127.0.0.1"
        assert result["X-Real-IP"] == "127.0.0.1"
    
    def test_apply_to_headers_override(self):
        """Test that profile headers override existing ones"""
        profile = WAFBypassProfile(
            name="test",
            description="Test",
            headers={"X-Forwarded-For": "127.0.0.1"}
        )
        
        existing = {"X-Forwarded-For": "192.168.1.1"}
        result = profile.apply_to_headers(existing)
        
        assert result["X-Forwarded-For"] == "127.0.0.1"
    
    def test_apply_to_headers_no_mutation(self):
        """Test that applying profile doesn't mutate original headers"""
        profile = WAFBypassProfile(
            name="test",
            description="Test",
            headers={"X-Forwarded-For": "127.0.0.1"}
        )
        
        existing = {"User-Agent": "TestAgent"}
        original_existing = existing.copy()
        
        result = profile.apply_to_headers(existing)
        
        # Original should be unchanged
        assert existing == original_existing
        # Result should have both
        assert result["User-Agent"] == "TestAgent"
        assert result["X-Forwarded-For"] == "127.0.0.1"


class TestWAFProfileManager:
    """Test WAFProfileManager"""
    
    def test_builtin_profiles_exist(self):
        """Test that built-in profiles are available"""
        manager = WAFProfileManager()
        
        expected_profiles = [
            "cloudflare",
            "akamai",
            "aws_waf",
            "modsecurity",
            "imperva",
            "f5_bigip",
            "fortiweb",
            "barracuda",
            "generic",
            "aggressive",
        ]
        
        for profile_name in expected_profiles:
            profile = manager.get_profile(profile_name)
            assert profile is not None
            assert profile.name == profile_name
    
    def test_get_cloudflare_profile(self):
        """Test getting Cloudflare profile"""
        manager = WAFProfileManager()
        profile = manager.get_profile("cloudflare")
        
        assert profile is not None
        assert profile.name == "cloudflare"
        assert profile.vendor == "Cloudflare"
        assert "CF-Connecting-IP" in profile.headers
        assert "X-Forwarded-For" in profile.headers
    
    def test_get_akamai_profile(self):
        """Test getting Akamai profile"""
        manager = WAFProfileManager()
        profile = manager.get_profile("akamai")
        
        assert profile is not None
        assert profile.name == "akamai"
        assert profile.vendor == "Akamai"
        assert "True-Client-IP" in profile.headers
    
    def test_get_aws_waf_profile(self):
        """Test getting AWS WAF profile"""
        manager = WAFProfileManager()
        profile = manager.get_profile("aws_waf")
        
        assert profile is not None
        assert profile.name == "aws_waf"
        assert profile.vendor == "AWS"
        assert "X-Forwarded-For" in profile.headers
    
    def test_get_generic_profile(self):
        """Test getting generic profile"""
        manager = WAFProfileManager()
        profile = manager.get_profile("generic")
        
        assert profile is not None
        assert profile.name == "generic"
        assert len(profile.headers) > 5  # Should have many headers
    
    def test_get_aggressive_profile(self):
        """Test getting aggressive profile"""
        manager = WAFProfileManager()
        profile = manager.get_profile("aggressive")
        
        assert profile is not None
        assert profile.name == "aggressive"
        assert profile.effectiveness == "high"
        assert len(profile.headers) > 10  # Should have many headers
    
    def test_get_nonexistent_profile(self):
        """Test getting non-existent profile returns None"""
        manager = WAFProfileManager()
        profile = manager.get_profile("nonexistent")
        
        assert profile is None
    
    def test_list_profiles(self):
        """Test listing all profiles"""
        manager = WAFProfileManager()
        profiles = manager.list_profiles()
        
        assert len(profiles) >= 10  # At least 10 built-in profiles
        assert "cloudflare" in profiles
        assert "akamai" in profiles
        assert "generic" in profiles
    
    def test_list_builtin_profiles(self):
        """Test listing built-in profiles"""
        manager = WAFProfileManager()
        profiles = manager.list_builtin_profiles()
        
        assert len(profiles) >= 10
        assert "cloudflare" in profiles
    
    def test_list_custom_profiles_empty(self):
        """Test listing custom profiles when none exist"""
        manager = WAFProfileManager()
        profiles = manager.list_custom_profiles()
        
        assert profiles == []
    
    def test_add_custom_profile(self):
        """Test adding a custom profile"""
        manager = WAFProfileManager()
        
        custom_profile = WAFBypassProfile(
            name="custom_test",
            description="Custom test profile",
            headers={"X-Custom": "value"}
        )
        
        manager.add_custom_profile(custom_profile)
        
        # Should be retrievable
        retrieved = manager.get_profile("custom_test")
        assert retrieved is not None
        assert retrieved.name == "custom_test"
        
        # Should appear in custom list
        custom_profiles = manager.list_custom_profiles()
        assert "custom_test" in custom_profiles
    
    def test_custom_profile_overrides_builtin(self):
        """Test that custom profiles take precedence over built-in"""
        manager = WAFProfileManager()
        
        # Create custom profile with same name as built-in
        custom_profile = WAFBypassProfile(
            name="cloudflare",
            description="Custom Cloudflare profile",
            headers={"X-Custom": "override"}
        )
        
        manager.add_custom_profile(custom_profile)
        
        # Should get custom version
        retrieved = manager.get_profile("cloudflare")
        assert retrieved.description == "Custom Cloudflare profile"
        assert "X-Custom" in retrieved.headers
    
    def test_remove_custom_profile(self):
        """Test removing a custom profile"""
        manager = WAFProfileManager()
        
        custom_profile = WAFBypassProfile(
            name="custom_test",
            description="Custom test profile",
            headers={"X-Custom": "value"}
        )
        
        manager.add_custom_profile(custom_profile)
        assert manager.get_profile("custom_test") is not None
        
        # Remove it
        result = manager.remove_custom_profile("custom_test")
        assert result is True
        
        # Should no longer exist
        assert manager.get_profile("custom_test") is None
    
    def test_remove_nonexistent_profile(self):
        """Test removing non-existent profile returns False"""
        manager = WAFProfileManager()
        result = manager.remove_custom_profile("nonexistent")
        assert result is False
    
    def test_get_profile_info(self):
        """Test getting profile information"""
        manager = WAFProfileManager()
        info = manager.get_profile_info("cloudflare")
        
        assert info is not None
        assert info["name"] == "cloudflare"
        assert info["vendor"] == "Cloudflare"
        assert info["effectiveness"] == "medium"
        assert info["header_count"] > 0
    
    def test_get_profile_info_nonexistent(self):
        """Test getting info for non-existent profile"""
        manager = WAFProfileManager()
        info = manager.get_profile_info("nonexistent")
        
        assert info is None
    
    def test_apply_profile_to_headers(self):
        """Test applying profile through manager"""
        manager = WAFProfileManager()
        
        existing = {"User-Agent": "TestAgent"}
        result = manager.apply_profile_to_headers("cloudflare", existing)
        
        assert result["User-Agent"] == "TestAgent"
        assert "CF-Connecting-IP" in result
        assert "X-Forwarded-For" in result
    
    def test_apply_nonexistent_profile_raises(self):
        """Test applying non-existent profile raises error"""
        manager = WAFProfileManager()
        
        with pytest.raises(ValueError, match="not found"):
            manager.apply_profile_to_headers("nonexistent", {})


class TestConvenienceFunctions:
    """Test convenience functions"""
    
    def test_get_waf_profile(self):
        """Test get_waf_profile convenience function"""
        profile = get_waf_profile("cloudflare")
        
        assert profile is not None
        assert profile.name == "cloudflare"
    
    def test_list_waf_profiles(self):
        """Test list_waf_profiles convenience function"""
        profiles = list_waf_profiles()
        
        assert len(profiles) >= 10
        assert "cloudflare" in profiles
        assert "akamai" in profiles
    
    def test_apply_waf_profile(self):
        """Test apply_waf_profile convenience function"""
        existing = {"User-Agent": "TestAgent"}
        result = apply_waf_profile("cloudflare", existing)
        
        assert result["User-Agent"] == "TestAgent"
        assert "CF-Connecting-IP" in result
    
    def test_apply_waf_profile_nonexistent_raises(self):
        """Test applying non-existent profile raises error"""
        with pytest.raises(ValueError, match="not found"):
            apply_waf_profile("nonexistent", {})


class TestProfileHeaders:
    """Test that profiles contain appropriate headers"""
    
    def test_all_profiles_have_ip_spoofing(self):
        """Test that all profiles include IP spoofing headers"""
        manager = WAFProfileManager()
        
        for profile_name in manager.list_builtin_profiles():
            profile = manager.get_profile(profile_name)
            
            # At least one IP-related header should be present
            ip_headers = [
                "X-Forwarded-For",
                "X-Real-IP",
                "X-Client-IP",
                "X-Originating-IP",
                "True-Client-IP",
                "CF-Connecting-IP",
            ]
            
            has_ip_header = any(h in profile.headers for h in ip_headers)
            assert has_ip_header, f"Profile {profile_name} missing IP spoofing headers"
    
    def test_cloudflare_specific_headers(self):
        """Test Cloudflare profile has CF-specific headers"""
        profile = get_waf_profile("cloudflare")
        assert "CF-Connecting-IP" in profile.headers
    
    def test_akamai_specific_headers(self):
        """Test Akamai profile has Akamai-specific headers"""
        profile = get_waf_profile("akamai")
        assert "True-Client-IP" in profile.headers
    
    def test_imperva_specific_headers(self):
        """Test Imperva profile has Imperva-specific headers"""
        profile = get_waf_profile("imperva")
        assert "Incap-Client-IP" in profile.headers
    
    def test_aggressive_has_most_headers(self):
        """Test aggressive profile has the most headers"""
        manager = WAFProfileManager()
        
        aggressive = manager.get_profile("aggressive")
        aggressive_count = len(aggressive.headers)
        
        # Aggressive should have more headers than any other profile
        for profile_name in manager.list_builtin_profiles():
            if profile_name == "aggressive":
                continue
            
            profile = manager.get_profile(profile_name)
            assert aggressive_count >= len(profile.headers)
