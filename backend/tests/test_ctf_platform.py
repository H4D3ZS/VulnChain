"""Tests for CTF platform integration"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from app.core.ctf_platform import (
    CTFPlatformIntegration,
    PlatformType,
    Challenge,
    ChallengeStatus,
    Flag,
    ScoreInfo,
)


class TestCTFPlatformIntegration:
    """Test CTF platform integration"""
    
    @pytest.mark.asyncio
    async def test_ctfd_initialization(self):
        """Test CTFd platform initialization"""
        platform = CTFPlatformIntegration(
            platform_type=PlatformType.CTFD,
            base_url="https://ctf.example.com",
            api_token="test_token"
        )
        
        assert platform.platform_type == PlatformType.CTFD
        assert platform.base_url == "https://ctf.example.com"
        assert platform.api_token == "test_token"
    
    @pytest.mark.asyncio
    async def test_hackthebox_initialization(self):
        """Test HackTheBox platform initialization"""
        platform = CTFPlatformIntegration(
            platform_type=PlatformType.HACKTHEBOX,
            base_url="https://www.hackthebox.com",
            api_token="htb_token"
        )
        
        assert platform.platform_type == PlatformType.HACKTHEBOX
        assert platform.base_url == "https://www.hackthebox.com"
    
    @pytest.mark.asyncio
    async def test_detect_flag_ctf_format(self):
        """Test flag detection with CTF{} format"""
        platform = CTFPlatformIntegration(
            platform_type=PlatformType.CTFD,
            base_url="https://ctf.example.com",
            api_token="test"
        )
        
        text = "The flag is CTF{th1s_1s_4_fl4g} hidden in the response"
        flags = platform.detect_flag(text)
        
        assert len(flags) == 1
        assert "CTF{th1s_1s_4_fl4g}" in flags
    
    @pytest.mark.asyncio
    async def test_detect_flag_multiple_formats(self):
        """Test flag detection with multiple formats"""
        platform = CTFPlatformIntegration(
            platform_type=PlatformType.CTFD,
            base_url="https://ctf.example.com",
            api_token="test"
        )
        
        text = """
        First flag: CTF{flag1}
        Second flag: FLAG{flag2}
        Third flag: HTB{flag3}
        """
        flags = platform.detect_flag(text)
        
        assert len(flags) >= 3
        assert any("CTF{flag1}" in f for f in flags)
        assert any("FLAG{flag2}" in f for f in flags)
        assert any("HTB{flag3}" in f for f in flags)
    
    @pytest.mark.asyncio
    async def test_detect_flag_no_duplicates(self):
        """Test flag detection removes duplicates"""
        platform = CTFPlatformIntegration(
            platform_type=PlatformType.CTFD,
            base_url="https://ctf.example.com",
            api_token="test"
        )
        
        text = "CTF{flag} and CTF{flag} again"
        flags = platform.detect_flag(text)
        
        # Should only return one instance
        ctf_flags = [f for f in flags if "CTF{flag}" in f]
        assert len(ctf_flags) == 1
    
    @pytest.mark.asyncio
    async def test_extract_url_from_text(self):
        """Test URL extraction from text"""
        platform = CTFPlatformIntegration(
            platform_type=PlatformType.CTFD,
            base_url="https://ctf.example.com",
            api_token="test"
        )
        
        text = "Connect to https://challenge.example.com:8080 to start"
        url = platform._extract_url_from_text(text)
        
        assert url == "https://challenge.example.com:8080"
    
    @pytest.mark.asyncio
    async def test_extract_url_no_url(self):
        """Test URL extraction when no URL present"""
        platform = CTFPlatformIntegration(
            platform_type=PlatformType.CTFD,
            base_url="https://ctf.example.com",
            api_token="test"
        )
        
        text = "No URL in this text"
        url = platform._extract_url_from_text(text)
        
        assert url is None
    
    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager"""
        platform = CTFPlatformIntegration(
            platform_type=PlatformType.CTFD,
            base_url="https://ctf.example.com",
            api_token="test"
        )
        
        # Mock the authentication
        with patch.object(platform, '_authenticate', new_callable=AsyncMock):
            async with platform as p:
                assert p.session is not None
            
            # Session should be closed after context exit
            assert platform.session is None
    
    @pytest.mark.asyncio
    async def test_flag_object_creation(self):
        """Test Flag object creation"""
        flag = Flag(
            flag="CTF{test}",
            challenge_id="123",
            challenge_name="Test Challenge",
            submitted=True,
            correct=True,
            points_awarded=100,
            submission_time=datetime.now()
        )
        
        assert flag.flag == "CTF{test}"
        assert flag.challenge_id == "123"
        assert flag.correct is True
        assert flag.points_awarded == 100
    
    @pytest.mark.asyncio
    async def test_challenge_object_creation(self):
        """Test Challenge object creation"""
        challenge = Challenge(
            challenge_id="456",
            name="Web Challenge",
            description="Exploit the web app",
            category="Web",
            points=200,
            status=ChallengeStatus.UNSOLVED,
            target_url="https://challenge.example.com",
            solves=42
        )
        
        assert challenge.challenge_id == "456"
        assert challenge.name == "Web Challenge"
        assert challenge.category == "Web"
        assert challenge.points == 200
        assert challenge.status == ChallengeStatus.UNSOLVED
        assert challenge.solves == 42
    
    @pytest.mark.asyncio
    async def test_score_info_creation(self):
        """Test ScoreInfo object creation"""
        score_info = ScoreInfo(
            score=1500,
            rank=5,
            total_teams=100,
            solved_challenges=15,
            total_challenges=50
        )
        
        assert score_info.score == 1500
        assert score_info.rank == 5
        assert score_info.total_teams == 100
        assert score_info.solved_challenges == 15
        assert score_info.total_challenges == 50
    
    @pytest.mark.asyncio
    async def test_base_url_trailing_slash_removed(self):
        """Test that trailing slash is removed from base URL"""
        platform = CTFPlatformIntegration(
            platform_type=PlatformType.CTFD,
            base_url="https://ctf.example.com/",
            api_token="test"
        )
        
        assert platform.base_url == "https://ctf.example.com"
    
    @pytest.mark.asyncio
    async def test_flag_patterns_exist(self):
        """Test that flag patterns are defined"""
        platform = CTFPlatformIntegration(
            platform_type=PlatformType.CTFD,
            base_url="https://ctf.example.com",
            api_token="test"
        )
        
        assert len(platform.flag_patterns) > 0
        assert any("CTF" in pattern for pattern in platform.flag_patterns)
    
    @pytest.mark.asyncio
    async def test_detect_md5_like_flag(self):
        """Test detection of MD5-like flags"""
        platform = CTFPlatformIntegration(
            platform_type=PlatformType.CTFD,
            base_url="https://ctf.example.com",
            api_token="test"
        )
        
        text = "The flag is: 5d41402abc4b2a76b9719d911017c592"
        flags = platform.detect_flag(text)
        
        # Should detect the MD5-like string
        assert len(flags) > 0
        assert any("5d41402abc4b2a76b9719d911017c592" in f for f in flags)
