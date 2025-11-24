"""Unit tests for reconnaissance module"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, mock_open

from app.modules.reconnaissance import (
    ReconnaissanceModule,
    Technology,
    FingerprintResult,
    DirectoryEntry,
    Subdomain,
    Parameter,
    JavaScriptEndpoint,
)
from app.core.request_handler import RequestHandler
from app.core.http_models import Response, Request
from app.models.target import TargetConfig


@pytest.fixture
def request_handler():
    """Create a mock request handler"""
    handler = MagicMock(spec=RequestHandler)
    handler.send_request = AsyncMock()
    return handler


@pytest.fixture
def recon_module(request_handler):
    """Create reconnaissance module instance"""
    return ReconnaissanceModule(request_handler)


@pytest.fixture
def target_config():
    """Create a test target configuration"""
    return TargetConfig(
        url="https://example.com",
        custom_headers={"User-Agent": "TestAgent"},
        proxy=None
    )


class TestWhatWebFingerprinting:
    """Tests for WhatWeb integration"""
    
    @pytest.mark.asyncio
    async def test_whatweb_success(self, recon_module, target_config):
        """Test successful WhatWeb execution"""
        # Mock subprocess
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(
            b'{"target":"https://example.com","plugins":{"Apache":{"version":["2.4.41"]},"PHP":{"version":["7.4.3"]}}}\n',
            b''
        ))
        
        with patch('asyncio.create_subprocess_exec', return_value=mock_process):
            # Mock HTTP request for headers
            mock_response = Response(
                status_code=200,
                headers={'server': 'Apache/2.4.41', 'x-powered-by': 'PHP/7.4.3'},
                body=b'',
                text='',
                elapsed_time=0.1,
                request=Request(method='GET', url=target_config.url),
                history=[]
            )
            recon_module.request_handler.send_request.return_value = mock_response
            
            result = await recon_module.fingerprint_whatweb(target_config)
            
            assert result.url == target_config.url
            assert result.error is None
            assert len(result.technologies) >= 2
            assert result.server == 'Apache/2.4.41'
            assert result.powered_by == 'PHP/7.4.3'
            
            # Check technologies
            tech_names = [t.name for t in result.technologies]
            assert 'Apache' in tech_names
            assert 'PHP' in tech_names
    
    @pytest.mark.asyncio
    async def test_whatweb_not_found(self, recon_module, target_config):
        """Test WhatWeb not installed"""
        with patch('asyncio.create_subprocess_exec', side_effect=FileNotFoundError()):
            result = await recon_module.fingerprint_whatweb(target_config)
            
            assert result.error is not None
            assert 'WhatWeb not found' in result.error
    
    @pytest.mark.asyncio
    async def test_whatweb_execution_failure(self, recon_module, target_config):
        """Test WhatWeb execution failure"""
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(b'', b'Error message'))
        
        with patch('asyncio.create_subprocess_exec', return_value=mock_process):
            result = await recon_module.fingerprint_whatweb(target_config)
            
            assert result.error is not None
            assert 'execution failed' in result.error


class TestWappalyzerFingerprinting:
    """Tests for Wappalyzer-style detection"""
    
    @pytest.mark.asyncio
    async def test_detect_react(self, recon_module, target_config):
        """Test React detection"""
        html = '<html><script src="react@17.0.2.js"></script><div id="root"></div></html>'
        
        mock_response = Response(
            status_code=200,
            headers={},
            body=html.encode(),
            text=html,
            elapsed_time=0.1,
            request=Request(method='GET', url=target_config.url),
            history=[]
        )
        recon_module.request_handler.send_request.return_value = mock_response
        
        result = await recon_module.fingerprint_wappalyzer(target_config)
        
        assert result.error is None
        tech_names = [t.name for t in result.technologies]
        assert 'React' in tech_names
        
        # Check version extraction
        react_tech = next(t for t in result.technologies if t.name == 'React')
        assert react_tech.version == '17.0.2'
    
    @pytest.mark.asyncio
    async def test_detect_wordpress(self, recon_module, target_config):
        """Test WordPress detection"""
        html = '''
        <html>
        <meta name="generator" content="WordPress 5.8.1" />
        <link rel="stylesheet" href="/wp-content/themes/theme.css">
        </html>
        '''
        
        mock_response = Response(
            status_code=200,
            headers={},
            body=html.encode(),
            text=html,
            elapsed_time=0.1,
            request=Request(method='GET', url=target_config.url),
            history=[]
        )
        recon_module.request_handler.send_request.return_value = mock_response
        
        result = await recon_module.fingerprint_wappalyzer(target_config)
        
        tech_names = [t.name for t in result.technologies]
        assert 'WordPress' in tech_names
        
        # Check version extraction
        wp_tech = next(t for t in result.technologies if t.name == 'WordPress')
        assert wp_tech.version == '5.8.1'
    
    @pytest.mark.asyncio
    async def test_detect_multiple_technologies(self, recon_module, target_config):
        """Test detection of multiple technologies"""
        html = '''
        <html>
        <script src="jquery-3.6.0.min.js"></script>
        <link rel="stylesheet" href="bootstrap-5.1.3.min.css">
        <script>var angular = {};</script>
        </html>
        '''
        
        mock_response = Response(
            status_code=200,
            headers={'server': 'nginx/1.18.0', 'x-powered-by': 'Express'},
            body=html.encode(),
            text=html,
            elapsed_time=0.1,
            request=Request(method='GET', url=target_config.url),
            history=[]
        )
        recon_module.request_handler.send_request.return_value = mock_response
        
        result = await recon_module.fingerprint_wappalyzer(target_config)
        
        tech_names = [t.name for t in result.technologies]
        assert 'jQuery' in tech_names
        assert 'Bootstrap' in tech_names
        assert 'Angular' in tech_names
        assert result.server == 'nginx/1.18.0'
        assert result.powered_by == 'Express'


class TestAttackModuleSuggestion:
    """Tests for attack module suggestion"""
    
    def test_suggest_wordpress_modules(self, recon_module):
        """Test WordPress attack module suggestions"""
        technologies = [
            Technology(name='WordPress', version='5.0', category='CMS')
        ]
        
        suggestions = recon_module.suggest_attack_modules(technologies)
        
        assert 'WordPress' in suggestions
        assert 'CMS Scanner (WPScan)' in suggestions['WordPress']
        assert 'SQL Injection' in suggestions['WordPress']
    
    def test_suggest_nodejs_modules(self, recon_module):
        """Test Node.js attack module suggestions"""
        technologies = [
            Technology(name='Node.js', version='14.17.0', category='Runtime'),
            Technology(name='Express', category='Framework')
        ]
        
        suggestions = recon_module.suggest_attack_modules(technologies)
        
        assert 'Node.js' in suggestions
        assert 'Prototype Pollution' in suggestions['Node.js']
        assert 'Express' in suggestions
        assert 'Prototype Pollution' in suggestions['Express']
    
    def test_suggest_multiple_technologies(self, recon_module):
        """Test suggestions for multiple technologies"""
        technologies = [
            Technology(name='PHP', version='7.4.3'),
            Technology(name='MySQL', version='8.0'),
            Technology(name='Apache', version='2.4.41')
        ]
        
        suggestions = recon_module.suggest_attack_modules(technologies)
        
        assert len(suggestions) >= 3
        assert 'PHP' in suggestions
        assert 'MySQL' in suggestions
        assert 'Apache' in suggestions


class TestDirectoryFuzzing:
    """Tests for directory and file fuzzing"""
    
    @pytest.mark.asyncio
    async def test_fuzz_directories_success(self, recon_module, target_config, tmp_path):
        """Test successful directory fuzzing"""
        # Create temporary wordlist
        wordlist = tmp_path / "wordlist.txt"
        wordlist.write_text("admin\nlogin\napi\n.git\n")
        
        # Mock responses
        async def mock_send_request(method, url, **kwargs):
            if '/admin' in url:
                return Response(200, {}, b'Admin page', 'Admin page', 0.1, 
                              Request(method, url), [])
            elif '/.git' in url:
                return Response(200, {}, b'Git directory', 'Git directory', 0.1,
                              Request(method, url), [])
            elif '/login' in url:
                return Response(302, {'location': '/auth'}, b'', '', 0.1,
                              Request(method, url), [])
            else:
                return Response(404, {}, b'Not found', 'Not found', 0.1,
                              Request(method, url), [])
        
        recon_module.request_handler.send_request = mock_send_request
        
        results = await recon_module.fuzz_directories(
            target_config,
            str(wordlist),
            status_codes=[200, 302]
        )
        
        assert len(results) == 3  # admin, .git, login
        
        # Check sensitive file detection
        git_entry = next(e for e in results if '.git' in e.path)
        assert git_entry.is_sensitive is True
        
        # Check redirect detection
        login_entry = next(e for e in results if 'login' in e.path)
        assert login_entry.redirect_location == '/auth'
    
    @pytest.mark.asyncio
    async def test_fuzz_wordlist_not_found(self, recon_module, target_config):
        """Test fuzzing with non-existent wordlist"""
        with pytest.raises(FileNotFoundError):
            await recon_module.fuzz_directories(
                target_config,
                "/nonexistent/wordlist.txt"
            )


class TestSubdomainEnumeration:
    """Tests for subdomain enumeration"""
    
    @pytest.mark.asyncio
    async def test_enumerate_crt_sh(self, recon_module):
        """Test certificate transparency log enumeration"""
        mock_response = Response(
            status_code=200,
            headers={},
            body=b'',
            text=json.dumps([
                {'name_value': 'www.example.com'},
                {'name_value': 'api.example.com'},
                {'name_value': 'mail.example.com'}
            ]),
            elapsed_time=0.1,
            request=Request(method='GET', url='https://crt.sh'),
            history=[]
        )
        recon_module.request_handler.send_request.return_value = mock_response
        
        subdomains = await recon_module._enumerate_crt_sh('example.com')
        
        assert len(subdomains) == 3
        assert 'www.example.com' in subdomains
        assert 'api.example.com' in subdomains
    
    @pytest.mark.asyncio
    async def test_enumerate_dns_brute(self, recon_module, tmp_path):
        """Test DNS brute-force enumeration"""
        # Create temporary wordlist
        wordlist = tmp_path / "subdomains.txt"
        wordlist.write_text("www\napi\nmail\n")
        
        # Mock nslookup
        async def mock_subprocess(*args, **kwargs):
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b'Address: 1.2.3.4', b''))
            return mock_process
        
        with patch('asyncio.create_subprocess_exec', side_effect=mock_subprocess):
            subdomains = await recon_module._enumerate_dns_brute(
                'example.com',
                str(wordlist),
                max_concurrent=10
            )
            
            assert len(subdomains) == 3


class TestParameterDiscovery:
    """Tests for parameter discovery"""
    
    @pytest.mark.asyncio
    async def test_extract_form_parameters(self, recon_module, target_config):
        """Test parameter extraction from forms"""
        html = '''
        <form>
            <input type="text" name="username">
            <input type="password" name="password">
            <select name="role">
                <option>admin</option>
            </select>
            <textarea name="comment"></textarea>
        </form>
        '''
        
        mock_response = Response(
            status_code=200,
            headers={},
            body=html.encode(),
            text=html,
            elapsed_time=0.1,
            request=Request(method='GET', url=target_config.url),
            history=[]
        )
        recon_module.request_handler.send_request.return_value = mock_response
        
        parameters = await recon_module.discover_parameters(target_config)
        
        param_names = [p.name for p in parameters]
        assert 'username' in param_names
        assert 'password' in param_names
        assert 'role' in param_names
        assert 'comment' in param_names
    
    @pytest.mark.asyncio
    async def test_extract_javascript_parameters(self, recon_module, target_config):
        """Test parameter extraction from JavaScript"""
        html = '''
        <script>
        var config = {
            "apiKey": "test123",
            "userId": 42
        };
        fetch('/api/data?id=123');
        $.get('search', {query: 'test'});
        </script>
        '''
        
        mock_response = Response(
            status_code=200,
            headers={},
            body=html.encode(),
            text=html,
            elapsed_time=0.1,
            request=Request(method='GET', url=target_config.url),
            history=[]
        )
        recon_module.request_handler.send_request.return_value = mock_response
        
        parameters = await recon_module.discover_parameters(target_config)
        
        param_names = [p.name for p in parameters]
        # Should find parameters from JavaScript
        assert any('api' in name.lower() or 'id' in name.lower() for name in param_names)


class TestJavaScriptAnalysis:
    """Tests for JavaScript analysis"""
    
    @pytest.mark.asyncio
    async def test_extract_javascript_files(self, recon_module, target_config):
        """Test JavaScript file extraction"""
        html = '''
        <html>
        <script src="/js/app.js"></script>
        <script src="https://cdn.example.com/lib.js"></script>
        <script src="../vendor/jquery.js"></script>
        </html>
        '''
        
        mock_response = Response(
            status_code=200,
            headers={},
            body=html.encode(),
            text=html,
            elapsed_time=0.1,
            request=Request(method='GET', url=target_config.url),
            history=[]
        )
        recon_module.request_handler.send_request.return_value = mock_response
        
        result = await recon_module.analyze_javascript(target_config)
        
        assert len(result['js_files']) == 3
        assert any('app.js' in f for f in result['js_files'])
        assert any('cdn.example.com' in f for f in result['js_files'])
    
    @pytest.mark.asyncio
    async def test_extract_api_endpoints(self, recon_module, target_config):
        """Test API endpoint extraction from JavaScript"""
        html = '<html><script src="/app.js"></script></html>'
        js_content = '''
        fetch('/api/users');
        axios.get('/api/v1/posts');
        $.ajax('/api/comments');
        '''
        
        # Mock main page response
        mock_main_response = Response(
            status_code=200,
            headers={},
            body=html.encode(),
            text=html,
            elapsed_time=0.1,
            request=Request(method='GET', url=target_config.url),
            history=[]
        )
        
        # Mock JS file response
        mock_js_response = Response(
            status_code=200,
            headers={},
            body=js_content.encode(),
            text=js_content,
            elapsed_time=0.1,
            request=Request(method='GET', url='https://example.com/app.js'),
            history=[]
        )
        
        async def mock_send_request(method, url, **kwargs):
            if url == target_config.url:
                return mock_main_response
            else:
                return mock_js_response
        
        recon_module.request_handler.send_request = mock_send_request
        
        result = await recon_module.analyze_javascript(target_config)
        
        assert len(result['endpoints']) >= 3
        endpoint_urls = [e.url for e in result['endpoints']]
        assert any('/api/users' in url for url in endpoint_urls)
        assert any('/api/v1/posts' in url for url in endpoint_urls)
    
    @pytest.mark.asyncio
    async def test_extract_api_keys(self, recon_module, target_config):
        """Test API key extraction from JavaScript"""
        html = '<html><script src="/config.js"></script></html>'
        js_content = '''
        const config = {
            api_key: "sk_test_1234567890abcdefghij",
            apiSecret: "secret_abcdefghijklmnopqrstuvwxyz",
            AWS_ACCESS_KEY: "AKIAIOSFODNN7EXAMPLE"
        };
        '''
        
        mock_main_response = Response(
            status_code=200,
            headers={},
            body=html.encode(),
            text=html,
            elapsed_time=0.1,
            request=Request(method='GET', url=target_config.url),
            history=[]
        )
        
        mock_js_response = Response(
            status_code=200,
            headers={},
            body=js_content.encode(),
            text=js_content,
            elapsed_time=0.1,
            request=Request(method='GET', url='https://example.com/config.js'),
            history=[]
        )
        
        async def mock_send_request(method, url, **kwargs):
            if url == target_config.url:
                return mock_main_response
            else:
                return mock_js_response
        
        recon_module.request_handler.send_request = mock_send_request
        
        result = await recon_module.analyze_javascript(target_config)
        
        assert len(result['api_keys']) >= 2
        assert any('sk_test' in key for key in result['api_keys'])
        assert any('AKIA' in key for key in result['api_keys'])
    
    @pytest.mark.asyncio
    async def test_extract_sensitive_comments(self, recon_module, target_config):
        """Test sensitive comment extraction"""
        html = '<html><script src="/app.js"></script></html>'
        js_content = '''
        // TODO: Remove hardcoded password before production
        const password = "admin123";
        
        /* FIXME: This is a security bug
           Need to validate user input */
        function processInput(data) {
            // HACK: Temporary workaround
            return data;
        }
        '''
        
        mock_main_response = Response(
            status_code=200,
            headers={},
            body=html.encode(),
            text=html,
            elapsed_time=0.1,
            request=Request(method='GET', url=target_config.url),
            history=[]
        )
        
        mock_js_response = Response(
            status_code=200,
            headers={},
            body=js_content.encode(),
            text=js_content,
            elapsed_time=0.1,
            request=Request(method='GET', url='https://example.com/app.js'),
            history=[]
        )
        
        async def mock_send_request(method, url, **kwargs):
            if url == target_config.url:
                return mock_main_response
            else:
                return mock_js_response
        
        recon_module.request_handler.send_request = mock_send_request
        
        result = await recon_module.analyze_javascript(target_config)
        
        assert len(result['comments']) >= 3
        assert any('password' in comment.lower() for comment in result['comments'])
        assert any('bug' in comment.lower() for comment in result['comments'])



class TestCMSScanners:
    """Tests for CMS-specific scanners"""
    
    @pytest.mark.asyncio
    async def test_wordpress_scan_success(self, recon_module, target_config):
        """Test successful WordPress scan"""
        mock_process = AsyncMock()
        mock_process.returncode = 4  # Vulnerabilities found
        
        wpscan_output = {
            "version": {
                "number": "5.8.0",
                "vulnerabilities": [
                    {
                        "title": "WordPress XSS Vulnerability",
                        "cve": "CVE-2021-12345",
                        "references": {
                            "url": ["https://example.com/vuln"]
                        },
                        "fixed_in": "5.8.1"
                    }
                ]
            },
            "plugins": {
                "contact-form-7": {
                    "version": {"number": "5.4.0"},
                    "location": "/wp-content/plugins/contact-form-7/",
                    "vulnerabilities": [
                        {
                            "title": "Contact Form 7 SQL Injection",
                            "cve": "CVE-2021-54321"
                        }
                    ]
                }
            },
            "themes": {
                "twentytwenty": {
                    "version": {"number": "1.7"},
                    "location": "/wp-content/themes/twentytwenty/"
                }
            },
            "users": {
                "1": {"username": "admin"},
                "2": {"username": "editor"}
            }
        }
        
        mock_process.communicate = AsyncMock(return_value=(
            json.dumps(wpscan_output).encode(),
            b''
        ))
        
        with patch('asyncio.create_subprocess_exec', return_value=mock_process):
            result = await recon_module.scan_wordpress(target_config)
            
            assert result.cms_type == 'wordpress'
            assert result.version == '5.8.0'
            assert result.error is None
            
            # Check plugins
            assert len(result.plugins) == 1
            assert result.plugins[0]['name'] == 'contact-form-7'
            assert result.plugins[0]['version'] == '5.4.0'
            
            # Check themes
            assert len(result.themes) == 1
            assert result.themes[0]['name'] == 'twentytwenty'
            
            # Check users
            assert len(result.users) == 2
            assert 'admin' in result.users
            
            # Check vulnerabilities
            assert len(result.vulnerabilities) >= 2
            vuln_titles = [v.title for v in result.vulnerabilities]
            assert 'WordPress XSS Vulnerability' in vuln_titles
    
    @pytest.mark.asyncio
    async def test_wordpress_scan_not_found(self, recon_module, target_config):
        """Test WordPress scan when WPScan not installed"""
        with patch('asyncio.create_subprocess_exec', side_effect=FileNotFoundError()):
            result = await recon_module.scan_wordpress(target_config)
            
            assert result.error is not None
            assert 'WPScan not found' in result.error
    
    @pytest.mark.asyncio
    async def test_drupal_scan_success(self, recon_module, target_config):
        """Test successful Drupal scan"""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        
        droopescan_output = {
            "version": ["7.58"],
            "plugins": {
                "views": {"version": "7.x-3.20"},
                "ctools": {}
            },
            "themes": {
                "bartik": {}
            },
            "interesting_urls": [
                "/CHANGELOG.txt",
                "/README.txt"
            ]
        }
        
        mock_process.communicate = AsyncMock(return_value=(
            json.dumps(droopescan_output).encode(),
            b''
        ))
        
        with patch('asyncio.create_subprocess_exec', return_value=mock_process):
            result = await recon_module.scan_drupal(target_config)
            
            assert result.cms_type == 'drupal'
            assert result.version == '7.58'
            assert result.error is None
            
            # Check plugins
            assert len(result.plugins) == 2
            plugin_names = [p['name'] for p in result.plugins]
            assert 'views' in plugin_names
            
            # Check themes
            assert len(result.themes) == 1
            
            # Check config issues
            assert len(result.config_issues) == 2
            
            # Check for known vulnerabilities
            assert len(result.vulnerabilities) > 0
    
    @pytest.mark.asyncio
    async def test_joomla_scan_success(self, recon_module, target_config):
        """Test successful Joomla scan"""
        mock_process = AsyncMock()
        mock_process.returncode = 0
        
        joomscan_output = """
        Joomla Version : 3.9.0
        
        Components:
        com_content
        com_users
        com_contact
        
        Configuration Issues:
        Directory listing enabled
        """
        
        mock_process.communicate = AsyncMock(return_value=(
            joomscan_output.encode(),
            b''
        ))
        
        with patch('asyncio.create_subprocess_exec', return_value=mock_process):
            result = await recon_module.scan_joomla(target_config)
            
            assert result.cms_type == 'joomla'
            assert result.version == '3.9.0'
            assert result.error is None
            
            # Check components
            assert len(result.plugins) >= 3
            plugin_names = [p['name'] for p in result.plugins]
            assert 'com_content' in plugin_names
            
            # Check config issues
            assert len(result.config_issues) >= 1
            assert 'Directory listing enabled' in result.config_issues
    
    @pytest.mark.asyncio
    async def test_detect_and_scan_wordpress(self, recon_module, target_config):
        """Test automatic CMS detection and scanning for WordPress"""
        # Mock Wappalyzer detection
        html = '<html><link rel="stylesheet" href="/wp-content/themes/theme.css"></html>'
        mock_wappalyzer_response = Response(
            status_code=200,
            headers={},
            body=html.encode(),
            text=html,
            elapsed_time=0.1,
            request=Request(method='GET', url=target_config.url),
            history=[]
        )
        
        # Mock WPScan
        mock_wpscan_process = AsyncMock()
        mock_wpscan_process.returncode = 0
        mock_wpscan_process.communicate = AsyncMock(return_value=(
            b'{"version": {"number": "5.8.0"}}',
            b''
        ))
        
        recon_module.request_handler.send_request.return_value = mock_wappalyzer_response
        
        with patch('asyncio.create_subprocess_exec', return_value=mock_wpscan_process):
            result = await recon_module.detect_and_scan_cms(target_config)
            
            assert result is not None
            assert result.cms_type == 'wordpress'
            assert result.version == '5.8.0'
    
    @pytest.mark.asyncio
    async def test_detect_and_scan_no_cms(self, recon_module, target_config):
        """Test CMS detection when no CMS is present"""
        html = '<html><h1>Plain HTML site</h1></html>'
        mock_response = Response(
            status_code=200,
            headers={},
            body=html.encode(),
            text=html,
            elapsed_time=0.1,
            request=Request(method='GET', url=target_config.url),
            history=[]
        )
        
        recon_module.request_handler.send_request.return_value = mock_response
        
        result = await recon_module.detect_and_scan_cms(target_config)
        
        assert result is None


class TestCVECrossReference:
    """Tests for CVE cross-referencing"""
    
    @pytest.mark.asyncio
    async def test_cross_reference_cve_success(self, recon_module):
        """Test successful CVE cross-reference"""
        nvd_response_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [
                            {"lang": "en", "value": "SQL injection vulnerability"}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL"
                                    }
                                }
                            ]
                        },
                        "published": "2021-01-01T00:00:00.000",
                        "references": [
                            {"url": "https://example.com/advisory"}
                        ]
                    }
                }
            ]
        }
        
        mock_response = Response(
            status_code=200,
            headers={},
            body=b'',
            text=json.dumps(nvd_response_data),
            elapsed_time=0.1,
            request=Request(method='GET', url='https://services.nvd.nist.gov'),
            history=[]
        )
        
        recon_module.request_handler.send_request.return_value = mock_response
        
        result = await recon_module.cross_reference_cve('CVE-2021-12345')
        
        assert result['cve_id'] == 'CVE-2021-12345'
        assert result['description'] == 'SQL injection vulnerability'
        assert result['cvss_score'] == 9.8
        assert result['severity'] == 'critical'
        assert len(result['references']) >= 1
        assert len(result['exploits']) >= 2  # Metasploit and GitHub placeholders
    
    @pytest.mark.asyncio
    async def test_cross_reference_cve_not_found(self, recon_module):
        """Test CVE cross-reference when CVE not found"""
        nvd_response_data = {"vulnerabilities": []}
        
        mock_response = Response(
            status_code=200,
            headers={},
            body=b'',
            text=json.dumps(nvd_response_data),
            elapsed_time=0.1,
            request=Request(method='GET', url='https://services.nvd.nist.gov'),
            history=[]
        )
        
        recon_module.request_handler.send_request.return_value = mock_response
        
        result = await recon_module.cross_reference_cve('CVE-9999-99999')
        
        assert result['cve_id'] == 'CVE-9999-99999'
        assert result['description'] is None
    
    @pytest.mark.asyncio
    async def test_enrich_vulnerabilities_with_cve(self, recon_module):
        """Test enriching CMS vulnerabilities with CVE data"""
        from app.modules.reconnaissance import CMSScanResult, CMSVulnerability
        
        cms_result = CMSScanResult(
            cms_type='wordpress',
            version='5.0',
            vulnerabilities=[
                CMSVulnerability(
                    title='Test Vulnerability',
                    severity='medium',
                    description='',
                    cve_id='CVE-2021-12345'
                )
            ]
        )
        
        # Mock CVE lookup
        nvd_response_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [
                            {"lang": "en", "value": "Detailed CVE description"}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL"
                                    }
                                }
                            ]
                        },
                        "references": [
                            {"url": "https://example.com/advisory"}
                        ]
                    }
                }
            ]
        }
        
        mock_response = Response(
            status_code=200,
            headers={},
            body=b'',
            text=json.dumps(nvd_response_data),
            elapsed_time=0.1,
            request=Request(method='GET', url='https://services.nvd.nist.gov'),
            history=[]
        )
        
        recon_module.request_handler.send_request.return_value = mock_response
        
        enriched = await recon_module.enrich_vulnerabilities_with_cve(cms_result)
        
        assert enriched.vulnerabilities[0].description == 'Detailed CVE description'
        assert enriched.vulnerabilities[0].severity == 'critical'
        assert len(enriched.vulnerabilities[0].references) > 0
