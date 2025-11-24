"""Tests for Quick-Scan module"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from dataclasses import dataclass

from app.modules.quick_scan import (
    QuickScanModule,
    QuickScanPreset,
    VulnerabilityCategory,
    VulnerabilityIndicator,
    CTFPattern,
    QuickScanResult,
)
from app.models.target import TargetConfig


@dataclass
class MockResponse:
    """Mock HTTP response"""
    status_code: int
    headers: dict
    body: bytes
    text: str
    elapsed_time: float


@pytest.fixture
def mock_request_handler():
    """Create mock request handler"""
    handler = Mock()
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def quick_scan_module(mock_request_handler):
    """Create QuickScanModule instance"""
    return QuickScanModule(mock_request_handler)


@pytest.fixture
def sample_target():
    """Create sample target configuration"""
    return TargetConfig(
        url="http://example.com",
        custom_headers={"User-Agent": "Test"}
    )


class TestQuickScanModule:
    """Test QuickScanModule functionality"""
    
    @pytest.mark.asyncio
    async def test_quick_scan_basic(self, quick_scan_module, sample_target, mock_request_handler):
        """Test basic quick-scan execution"""
        # Mock response
        mock_response = MockResponse(
            status_code=200,
            headers={"server": "Apache/2.4.41", "x-powered-by": "PHP/7.4"},
            body=b"<html><body>Test</body></html>",
            text="<html><body>Test</body></html>",
            elapsed_time=0.5
        )
        mock_request_handler.send_request.return_value = mock_response
        
        # Execute quick-scan
        result = await quick_scan_module.quick_scan(sample_target)
        
        # Verify result structure
        assert isinstance(result, QuickScanResult)
        assert result.target_url == sample_target.url
        assert isinstance(result.indicators, list)
        assert isinstance(result.ctf_patterns, list)
        assert isinstance(result.recommended_modules, list)
        assert result.scan_duration > 0
        assert result.error is None
    
    @pytest.mark.asyncio
    async def test_information_disclosure_detection(self, quick_scan_module, sample_target, mock_request_handler):
        """Test detection of information disclosure"""
        mock_response = MockResponse(
            status_code=200,
            headers={
                "server": "Apache/2.4.41 (Ubuntu)",
                "x-powered-by": "PHP/7.4.3"
            },
            body=b"<html><body>Test</body></html>",
            text="<html><body>Test</body></html>",
            elapsed_time=0.5
        )
        mock_request_handler.send_request.return_value = mock_response
        
        result = await quick_scan_module.quick_scan(sample_target)
        
        # Should detect information disclosure
        info_indicators = [
            ind for ind in result.indicators
            if ind.category == VulnerabilityCategory.INFORMATION_DISCLOSURE
        ]
        assert len(info_indicators) > 0
    
    @pytest.mark.asyncio
    async def test_sql_injection_error_detection(self, quick_scan_module, sample_target, mock_request_handler):
        """Test detection of SQL injection via error messages"""
        # First call - baseline
        baseline_response = MockResponse(
            status_code=200,
            headers={},
            body=b"Normal response",
            text="Normal response",
            elapsed_time=0.5
        )
        
        # Second call - SQL error
        error_response = MockResponse(
            status_code=500,
            headers={},
            body=b"SQL syntax error near 'test' at line 1",
            text="SQL syntax error near 'test' at line 1",
            elapsed_time=0.6
        )
        
        # Need multiple responses for baseline + injection tests + admin path tests
        mock_request_handler.send_request.side_effect = [
            baseline_response,  # Initial baseline
            baseline_response,  # Admin path test
            error_response,     # SQL injection test 1
            error_response,     # SQL injection test 2
        ]
        
        result = await quick_scan_module.quick_scan(
            sample_target,
            categories=[VulnerabilityCategory.SQL_INJECTION]
        )
        
        # Should detect SQL injection
        sqli_indicators = [
            ind for ind in result.indicators
            if ind.category == VulnerabilityCategory.SQL_INJECTION
        ]
        assert len(sqli_indicators) > 0
    
    @pytest.mark.asyncio
    async def test_ctf_flag_detection(self, quick_scan_module, sample_target, mock_request_handler):
        """Test detection of CTF flags"""
        mock_response = MockResponse(
            status_code=200,
            headers={},
            body=b"<html><body>CTF{test_flag_12345}</body></html>",
            text="<html><body>CTF{test_flag_12345}</body></html>",
            elapsed_time=0.5
        )
        mock_request_handler.send_request.return_value = mock_response
        
        result = await quick_scan_module.quick_scan(sample_target)
        
        # Should detect flag pattern
        flag_patterns = [
            p for p in result.ctf_patterns
            if p.pattern_type == 'flag_format'
        ]
        assert len(flag_patterns) > 0
        assert 'CTF{test_flag_12345}' in flag_patterns[0].value
    
    @pytest.mark.asyncio
    async def test_hint_comment_detection(self, quick_scan_module, sample_target, mock_request_handler):
        """Test detection of hint comments"""
        mock_response = MockResponse(
            status_code=200,
            headers={},
            body=b"<html><!-- hint: check /admin --><body>Test</body></html>",
            text="<html><!-- hint: check /admin --><body>Test</body></html>",
            elapsed_time=0.5
        )
        mock_request_handler.send_request.return_value = mock_response
        
        result = await quick_scan_module.quick_scan(sample_target)
        
        # Should detect hint comment
        hint_patterns = [
            p for p in result.ctf_patterns
            if p.pattern_type == 'hint_comment'
        ]
        assert len(hint_patterns) > 0
    
    @pytest.mark.asyncio
    async def test_category_specific_scan(self, quick_scan_module, sample_target, mock_request_handler):
        """Test scanning specific categories only"""
        mock_response = MockResponse(
            status_code=200,
            headers={},
            body=b"Test",
            text="Test",
            elapsed_time=0.5
        )
        mock_request_handler.send_request.return_value = mock_response
        
        # Scan only XSS and SQL injection
        categories = [
            VulnerabilityCategory.XSS,
            VulnerabilityCategory.SQL_INJECTION
        ]
        
        result = await quick_scan_module.quick_scan(sample_target, categories=categories)
        
        # Should only test specified categories
        assert result.error is None
        # All indicators should be from specified categories
        for indicator in result.indicators:
            assert indicator.category in categories or \
                   indicator.category in [
                       VulnerabilityCategory.INFORMATION_DISCLOSURE,
                       VulnerabilityCategory.AUTHENTICATION,
                       VulnerabilityCategory.MISCONFIGURATION
                   ]  # These are always tested
    
    def test_generate_recommendations(self, quick_scan_module):
        """Test recommendation generation"""
        indicators = [
            VulnerabilityIndicator(
                category=VulnerabilityCategory.SQL_INJECTION,
                confidence=0.8,
                evidence="SQL error detected",
                description="Potential SQL injection",
                recommended_modules=["SQL Injection"]
            ),
            VulnerabilityIndicator(
                category=VulnerabilityCategory.SQL_INJECTION,
                confidence=0.6,
                evidence="Timing difference",
                description="Time-based blind SQLi",
                recommended_modules=["SQL Injection"]
            ),
            VulnerabilityIndicator(
                category=VulnerabilityCategory.XSS,
                confidence=0.5,
                evidence="Reflected input",
                description="Potential XSS",
                recommended_modules=["XSS Testing"]
            ),
        ]
        
        recommendations = quick_scan_module._generate_recommendations(indicators)
        
        # SQL Injection should be first (higher total confidence)
        assert recommendations[0] == "SQL Injection"
        assert "XSS Testing" in recommendations
    
    def test_detailed_recommendations(self, quick_scan_module):
        """Test detailed recommendation generation"""
        indicators = [
            VulnerabilityIndicator(
                category=VulnerabilityCategory.SQL_INJECTION,
                confidence=0.8,
                evidence="SQL error",
                description="SQL injection detected",
                recommended_modules=["SQL Injection", "Database Testing"]
            ),
        ]
        
        detailed = quick_scan_module.get_detailed_recommendations(indicators)
        
        assert len(detailed) > 0
        assert 'module' in detailed[0]
        assert 'score' in detailed[0]
        assert 'reasoning' in detailed[0]
        assert 'indicator_count' in detailed[0]
    
    def test_ctf_pattern_analysis(self, quick_scan_module):
        """Test CTF pattern analysis"""
        patterns = [
            CTFPattern(
                pattern_type='flag_format',
                value='CTF{test}',
                location='body',
                description='Flag found'
            ),
            CTFPattern(
                pattern_type='hint_comment',
                value='<!-- hint: admin -->',
                location='html_comment',
                description='Hint found'
            ),
        ]
        
        analysis = quick_scan_module.analyze_ctf_patterns(patterns)
        
        assert analysis['has_flags'] is True
        assert analysis['has_hints'] is True
        assert len(analysis['priority_actions']) > 0
        assert analysis['priority_actions'][0]['priority'] == 'CRITICAL'


class TestQuickScanPreset:
    """Test QuickScanPreset functionality"""
    
    def test_get_default_preset(self):
        """Test getting default preset"""
        preset = QuickScanPreset.get_preset('default')
        
        assert preset['name'] == 'Default Quick Scan'
        assert 'categories' in preset
        assert 'timeout' in preset
        assert len(preset['categories']) > 0
    
    def test_get_hackthebox_preset(self):
        """Test getting HackTheBox preset"""
        preset = QuickScanPreset.get_preset('hackthebox')
        
        assert preset['name'] == 'HackTheBox Preset'
        assert VulnerabilityCategory.SQL_INJECTION in preset['categories']
        assert VulnerabilityCategory.COMMAND_INJECTION in preset['categories']
    
    def test_list_presets(self):
        """Test listing all presets"""
        presets = QuickScanPreset.list_presets()
        
        assert len(presets) >= 6  # At least 6 built-in presets
        assert all('name' in p for p in presets)
        assert all('categories' in p for p in presets)
    
    def test_create_custom_preset(self):
        """Test creating custom preset"""
        custom = QuickScanPreset.create_custom_preset(
            name="My Custom Scan",
            description="Test preset",
            categories=[VulnerabilityCategory.SQL_INJECTION],
            timeout=25
        )
        
        assert custom['name'] == "My Custom Scan"
        assert custom['description'] == "Test preset"
        assert len(custom['categories']) == 1
        assert custom['timeout'] == 25
    
    def test_save_and_retrieve_custom_preset(self):
        """Test saving and retrieving custom preset"""
        custom = QuickScanPreset.create_custom_preset(
            name="Saved Preset",
            description="Test",
            categories=[VulnerabilityCategory.XSS],
            save=True
        )
        
        # Should be able to retrieve it
        retrieved = QuickScanPreset.get_preset("Saved Preset")
        assert retrieved['name'] == "Saved Preset"
        
        # Clean up
        QuickScanPreset.delete_custom_preset("Saved Preset")
    
    def test_modify_preset(self):
        """Test modifying existing preset"""
        modified = QuickScanPreset.modify_preset(
            'default',
            timeout=60,
            max_payloads_per_category=5
        )
        
        assert modified['timeout'] == 60
        assert modified['max_payloads_per_category'] == 5
        assert '(Modified)' in modified['name']
    
    def test_export_import_preset(self):
        """Test exporting and importing presets"""
        # Export
        json_str = QuickScanPreset.export_preset('default')
        assert isinstance(json_str, str)
        assert 'Default Quick Scan' in json_str
        
        # Import
        imported = QuickScanPreset.import_preset(json_str, save=False)
        assert imported['name'] == 'Default Quick Scan'
        assert 'categories' in imported
    
    def test_get_preset_for_platform(self):
        """Test getting preset for specific platform"""
        htb_preset = QuickScanPreset.get_preset_for_platform('hackthebox')
        assert 'HackTheBox' in htb_preset['name']
        
        ctfd_preset = QuickScanPreset.get_preset_for_platform('ctfd')
        assert 'CTFd' in ctfd_preset['name']
        
        # Test alias
        htb_alias = QuickScanPreset.get_preset_for_platform('htb')
        assert htb_alias == htb_preset
    
    def test_delete_custom_preset(self):
        """Test deleting custom preset"""
        # Create and save
        QuickScanPreset.create_custom_preset(
            name="To Delete",
            description="Test",
            categories=[VulnerabilityCategory.XSS],
            save=True
        )
        
        # Delete
        result = QuickScanPreset.delete_custom_preset("To Delete")
        assert result is True
        
        # Try to delete again
        result = QuickScanPreset.delete_custom_preset("To Delete")
        assert result is False


class TestVulnerabilityCategory:
    """Test VulnerabilityCategory enum"""
    
    def test_all_categories_exist(self):
        """Test that all expected categories exist"""
        expected_categories = [
            'SQL_INJECTION',
            'XSS',
            'COMMAND_INJECTION',
            'SSRF',
            'XXE',
            'DIRECTORY_TRAVERSAL',
            'SSTI',
            'DESERIALIZATION',
            'AUTHENTICATION',
            'AUTHORIZATION',
            'INFORMATION_DISCLOSURE',
            'MISCONFIGURATION',
        ]
        
        for cat_name in expected_categories:
            assert hasattr(VulnerabilityCategory, cat_name)
    
    def test_category_values(self):
        """Test category values are human-readable"""
        assert VulnerabilityCategory.SQL_INJECTION.value == "SQL Injection"
        assert VulnerabilityCategory.XSS.value == "Cross-Site Scripting"
        assert VulnerabilityCategory.COMMAND_INJECTION.value == "Command Injection"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
