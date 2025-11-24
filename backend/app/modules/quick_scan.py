"""Quick-scan module for rapid vulnerability triage and CTF pattern detection"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum

from app.core.request_handler import RequestHandler
from app.models.target import TargetConfig


class VulnerabilityCategory(Enum):
    """Vulnerability categories for quick scanning"""
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    COMMAND_INJECTION = "Command Injection"
    SSRF = "Server-Side Request Forgery"
    XXE = "XML External Entity"
    DIRECTORY_TRAVERSAL = "Directory Traversal"
    SSTI = "Server-Side Template Injection"
    DESERIALIZATION = "Insecure Deserialization"
    AUTHENTICATION = "Authentication Issues"
    AUTHORIZATION = "Authorization Issues"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    MISCONFIGURATION = "Security Misconfiguration"


@dataclass
class VulnerabilityIndicator:
    """Indicator of a potential vulnerability"""
    
    category: VulnerabilityCategory
    confidence: float  # 0.0 to 1.0
    evidence: str
    description: str
    recommended_modules: List[str] = field(default_factory=list)


@dataclass
class CTFPattern:
    """Detected CTF-specific pattern"""
    
    pattern_type: str  # flag_format, hint_comment, debug_endpoint, etc.
    value: str
    location: str  # url, header, body, etc.
    description: str


@dataclass
class QuickScanResult:
    """Result of a quick-scan operation"""
    
    target_url: str
    indicators: List[VulnerabilityIndicator] = field(default_factory=list)
    ctf_patterns: List[CTFPattern] = field(default_factory=list)
    recommended_modules: List[str] = field(default_factory=list)
    scan_duration: float = 0.0
    error: Optional[str] = None


class QuickScanModule:
    """
    Quick-scan module for rapid vulnerability triage.
    
    Provides:
    - Lightweight tests across all major vulnerability categories
    - Vulnerability likelihood ranking based on response patterns
    - CTF-specific pattern detection
    - Prioritized attack module recommendations
    """
    
    def __init__(self, request_handler: RequestHandler):
        """
        Initialize quick-scan module.
        
        Args:
            request_handler: RequestHandler instance for HTTP operations
        """
        self.request_handler = request_handler
        
        # CTF flag patterns
        self._flag_patterns = [
            r'CTF\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'flag\{[^}]+\}',
            r'[A-Za-z0-9]{32}',  # MD5-like
            r'[A-Za-z0-9_-]{20,}',  # Base64-like
        ]
        
        # Error message patterns indicating vulnerabilities
        self._error_patterns = {
            VulnerabilityCategory.SQL_INJECTION: [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_',
                r'valid MySQL result',
                r'MySqlClient\.',
                r'PostgreSQL.*ERROR',
                r'Warning.*pg_',
                r'valid PostgreSQL result',
                r'Npgsql\.',
                r'Driver.*SQL.*Server',
                r'OLE DB.*SQL Server',
                r'SQLServer JDBC Driver',
                r'SqlException',
                r'Oracle error',
                r'Oracle.*Driver',
                r'Warning.*oci_',
                r'Warning.*ora_',
            ],
            VulnerabilityCategory.COMMAND_INJECTION: [
                r'sh: .*: command not found',
                r'bash: .*: command not found',
                r'/bin/sh',
                r'/bin/bash',
                r'root:.*:0:0:',
                r'daemon:.*:1:1:',
            ],
            VulnerabilityCategory.DIRECTORY_TRAVERSAL: [
                r'root:.*:0:0:',
                r'\[boot loader\]',
                r'\[operating systems\]',
                r'<\?xml version',
            ],
            VulnerabilityCategory.SSTI: [
                r'TemplateSyntaxError',
                r'Jinja2',
                r'Template.*Error',
                r'Twig_Error',
            ],
            VulnerabilityCategory.DESERIALIZATION: [
                r'unserialize\(\)',
                r'ObjectInputStream',
                r'pickle\.loads',
                r'yaml\.load',
            ],
        }
        
        # Lightweight test payloads for each category
        self._test_payloads = {
            VulnerabilityCategory.SQL_INJECTION: ["'", "1' OR '1'='1", "1 AND 1=1"],
            VulnerabilityCategory.XSS: ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            VulnerabilityCategory.COMMAND_INJECTION: [";id", "|whoami", "`whoami`"],
            VulnerabilityCategory.SSRF: ["http://localhost", "http://127.0.0.1"],
            VulnerabilityCategory.DIRECTORY_TRAVERSAL: ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"],
            VulnerabilityCategory.SSTI: ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
        }
    
    async def quick_scan(
        self,
        target: TargetConfig,
        categories: Optional[List[VulnerabilityCategory]] = None
    ) -> QuickScanResult:
        """
        Perform a quick-scan of the target.
        
        Args:
            target: Target configuration
            categories: Specific categories to test (default: all)
            
        Returns:
            QuickScanResult with detected indicators and recommendations
        """
        import time
        start_time = time.time()
        
        result = QuickScanResult(target_url=target.url)
        
        try:
            # If no categories specified, test all
            if categories is None:
                categories = list(VulnerabilityCategory)
            
            # 1. Baseline request to understand normal behavior
            baseline_response = await self._get_baseline(target)
            
            # 2. Test for information disclosure
            info_indicators = await self._test_information_disclosure(target, baseline_response)
            result.indicators.extend(info_indicators)
            
            # 3. Test for authentication/authorization issues
            auth_indicators = await self._test_authentication(target)
            result.indicators.extend(auth_indicators)
            
            # 4. Test injection vulnerabilities with lightweight payloads
            injection_indicators = await self._test_injections(target, baseline_response, categories)
            result.indicators.extend(injection_indicators)
            
            # 5. Detect CTF-specific patterns
            ctf_patterns = await self._detect_ctf_patterns(target, baseline_response)
            result.ctf_patterns.extend(ctf_patterns)
            
            # 6. Rank indicators by confidence and generate recommendations
            result.indicators.sort(key=lambda x: x.confidence, reverse=True)
            result.recommended_modules = self._generate_recommendations(result.indicators)
            
            result.scan_duration = time.time() - start_time
            
        except Exception as e:
            result.error = f"Error during quick-scan: {str(e)}"
        
        return result
    
    async def _get_baseline(self, target: TargetConfig) -> any:
        """Get baseline response for comparison"""
        try:
            response = await self.request_handler.send_request(
                method='GET',
                url=target.url,
                headers=target.custom_headers,
                proxy=target.proxy,
                timeout=10.0
            )
            return response
        except Exception:
            return None
    
    async def _test_information_disclosure(
        self, target: TargetConfig, baseline_response: any
    ) -> List[VulnerabilityIndicator]:
        """Test for information disclosure vulnerabilities"""
        indicators = []
        
        if baseline_response is None:
            return indicators
        
        # Check response headers for information disclosure
        headers = baseline_response.headers
        body = baseline_response.text
        
        # Server header disclosure
        if 'server' in headers:
            server = headers['server']
            if any(tech in server.lower() for tech in ['apache', 'nginx', 'iis', 'tomcat']):
                indicators.append(VulnerabilityIndicator(
                    category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
                    confidence=0.3,
                    evidence=f"Server header: {server}",
                    description="Server version disclosed in headers",
                    recommended_modules=["Header Analysis", "Reconnaissance"]
                ))
        
        # X-Powered-By header
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by']
            indicators.append(VulnerabilityIndicator(
                category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
                confidence=0.4,
                evidence=f"X-Powered-By: {powered_by}",
                description="Technology stack disclosed in headers",
                recommended_modules=["Header Analysis", "Reconnaissance"]
            ))
        
        # Check for debug/error messages in response
        debug_patterns = [
            r'DEBUG\s*=\s*True',
            r'FLASK_ENV\s*=\s*development',
            r'APP_DEBUG\s*=\s*true',
            r'Traceback \(most recent call last\)',
            r'Stack trace:',
            r'Exception in thread',
        ]
        
        for pattern in debug_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                indicators.append(VulnerabilityIndicator(
                    category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
                    confidence=0.7,
                    evidence=f"Debug pattern found: {pattern}",
                    description="Debug mode or verbose errors enabled",
                    recommended_modules=["Information Gathering"]
                ))
                break
        
        # Check for missing security headers
        security_headers = ['x-frame-options', 'x-content-type-options', 'strict-transport-security']
        missing_headers = [h for h in security_headers if h not in headers]
        
        if missing_headers:
            indicators.append(VulnerabilityIndicator(
                category=VulnerabilityCategory.MISCONFIGURATION,
                confidence=0.5,
                evidence=f"Missing headers: {', '.join(missing_headers)}",
                description="Security headers not configured",
                recommended_modules=["Header Analysis"]
            ))
        
        return indicators
    
    async def _test_authentication(self, target: TargetConfig) -> List[VulnerabilityIndicator]:
        """Test for authentication and authorization issues"""
        indicators = []
        
        # Test common admin paths
        admin_paths = ['/admin', '/administrator', '/wp-admin', '/login', '/dashboard']
        
        for path in admin_paths:
            try:
                from urllib.parse import urljoin
                url = urljoin(target.url, path)
                
                response = await self.request_handler.send_request(
                    method='GET',
                    url=url,
                    headers=target.custom_headers,
                    proxy=target.proxy,
                    timeout=5.0,
                    follow_redirects=False
                )
                
                # If we get 200 OK, admin panel might be accessible
                if response.status_code == 200:
                    indicators.append(VulnerabilityIndicator(
                        category=VulnerabilityCategory.AUTHENTICATION,
                        confidence=0.6,
                        evidence=f"Admin path accessible: {path}",
                        description="Administrative interface found",
                        recommended_modules=["Brute Force", "Authentication Testing"]
                    ))
                    break  # Found one, that's enough for quick scan
                
            except Exception:
                continue
        
        return indicators
    
    async def _test_injections(
        self,
        target: TargetConfig,
        baseline_response: any,
        categories: List[VulnerabilityCategory]
    ) -> List[VulnerabilityIndicator]:
        """Test for injection vulnerabilities with lightweight payloads"""
        indicators = []
        
        if baseline_response is None:
            return indicators
        
        baseline_length = len(baseline_response.body)
        baseline_time = baseline_response.elapsed_time
        
        # Test each category with lightweight payloads
        for category in categories:
            if category not in self._test_payloads:
                continue
            
            payloads = self._test_payloads[category]
            
            for payload in payloads[:2]:  # Only test first 2 payloads for speed
                try:
                    # Try payload in URL parameter
                    from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
                    parsed = urlparse(target.url)
                    
                    # Add test parameter
                    params = parse_qs(parsed.query)
                    params['test'] = [payload]
                    new_query = urlencode(params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    response = await self.request_handler.send_request(
                        method='GET',
                        url=test_url,
                        headers=target.custom_headers,
                        proxy=target.proxy,
                        timeout=10.0
                    )
                    
                    # Check for error patterns
                    if category in self._error_patterns:
                        for error_pattern in self._error_patterns[category]:
                            if re.search(error_pattern, response.text, re.IGNORECASE):
                                indicators.append(VulnerabilityIndicator(
                                    category=category,
                                    confidence=0.8,
                                    evidence=f"Error pattern matched: {error_pattern}",
                                    description=f"Potential {category.value} detected via error message",
                                    recommended_modules=[self._category_to_module(category)]
                                ))
                                break
                    
                    # Check for timing differences (blind injection)
                    if category == VulnerabilityCategory.SQL_INJECTION:
                        if response.elapsed_time > baseline_time * 2:
                            indicators.append(VulnerabilityIndicator(
                                category=category,
                                confidence=0.6,
                                evidence=f"Response time increased: {response.elapsed_time:.2f}s vs {baseline_time:.2f}s",
                                description="Potential time-based blind SQL injection",
                                recommended_modules=["SQL Injection"]
                            ))
                    
                    # Check for significant response length changes
                    response_length = len(response.body)
                    if abs(response_length - baseline_length) > baseline_length * 0.3:
                        indicators.append(VulnerabilityIndicator(
                            category=category,
                            confidence=0.5,
                            evidence=f"Response length changed significantly: {response_length} vs {baseline_length}",
                            description=f"Potential {category.value} - response behavior changed",
                            recommended_modules=[self._category_to_module(category)]
                        ))
                
                except Exception:
                    continue
        
        return indicators
    
    async def _detect_ctf_patterns(
        self, target: TargetConfig, baseline_response: any
    ) -> List[CTFPattern]:
        """Detect CTF-specific patterns"""
        patterns = []
        
        if baseline_response is None:
            return patterns
        
        body = baseline_response.text
        headers = baseline_response.headers
        
        # 1. Check for flag patterns in response body
        for flag_pattern in self._flag_patterns:
            matches = re.findall(flag_pattern, body)
            for match in matches:
                patterns.append(CTFPattern(
                    pattern_type='flag_format',
                    value=match,
                    location='response_body',
                    description=f"Potential flag found: {match}"
                ))
        
        # 2. Check for hint comments in HTML
        hint_patterns = [
            r'<!--.*hint.*-->',
            r'<!--.*flag.*-->',
            r'<!--.*password.*-->',
            r'<!--.*TODO.*-->',
            r'<!--.*FIXME.*-->',
            r'<!--.*NOTE.*-->',
        ]
        
        for hint_pattern in hint_patterns:
            matches = re.findall(hint_pattern, body, re.IGNORECASE | re.DOTALL)
            for match in matches:
                patterns.append(CTFPattern(
                    pattern_type='hint_comment',
                    value=match.strip(),
                    location='html_comment',
                    description="Hint found in HTML comment"
                ))
        
        # 3. Check for debug endpoints in response
        debug_indicators = [
            '/debug', '/test', '/dev', '/api/debug', '/.git', '/backup',
            '/phpinfo.php', '/info.php', '/test.php', '/admin', '/console',
            '/swagger', '/api-docs', '/graphql', '/.env'
        ]
        
        for indicator in debug_indicators:
            if indicator in body:
                patterns.append(CTFPattern(
                    pattern_type='debug_endpoint',
                    value=indicator,
                    location='response_body',
                    description=f"Debug endpoint reference found: {indicator}"
                ))
        
        # 4. Check for custom headers that might contain hints
        custom_header_patterns = ['x-flag', 'x-hint', 'x-debug', 'x-ctf', 'x-challenge']
        for header_name in headers:
            if any(pattern in header_name.lower() for pattern in custom_header_patterns):
                patterns.append(CTFPattern(
                    pattern_type='custom_header',
                    value=f"{header_name}: {headers[header_name]}",
                    location='response_headers',
                    description="Custom header with potential hint"
                ))
        
        # 5. Check for common CTF challenge indicators
        ctf_indicators = [
            (r'challenge\s*:\s*([^\n<]+)', 'challenge_name'),
            (r'difficulty\s*:\s*([^\n<]+)', 'difficulty_level'),
            (r'points\s*:\s*(\d+)', 'point_value'),
            (r'author\s*:\s*([^\n<]+)', 'challenge_author'),
        ]
        
        for pattern, pattern_type in ctf_indicators:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches:
                patterns.append(CTFPattern(
                    pattern_type=pattern_type,
                    value=match.strip(),
                    location='response_body',
                    description=f"CTF metadata found: {pattern_type}"
                ))
        
        # 6. Check for encoded data that might be flags
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        base64_matches = re.findall(base64_pattern, body)
        for match in base64_matches[:5]:  # Limit to first 5 to avoid noise
            # Try to decode and check if it looks like a flag
            try:
                import base64
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if any(flag_word in decoded.lower() for flag_word in ['flag', 'ctf', 'key']):
                    patterns.append(CTFPattern(
                        pattern_type='encoded_flag',
                        value=f"{match} -> {decoded}",
                        location='response_body',
                        description="Base64-encoded data containing flag-related keywords"
                    ))
            except Exception:
                pass
        
        return patterns
    
    def analyze_ctf_patterns(self, patterns: List[CTFPattern]) -> Dict:
        """
        Analyze CTF patterns to provide actionable insights.
        
        Returns:
            Dictionary with analysis results and recommendations
        """
        analysis = {
            'has_flags': False,
            'has_hints': False,
            'has_debug_endpoints': False,
            'has_metadata': False,
            'priority_actions': [],
            'pattern_summary': {},
        }
        
        # Count patterns by type
        from collections import Counter
        pattern_counts = Counter(p.pattern_type for p in patterns)
        analysis['pattern_summary'] = dict(pattern_counts)
        
        # Analyze what we found
        if any(p.pattern_type == 'flag_format' for p in patterns):
            analysis['has_flags'] = True
            analysis['priority_actions'].append({
                'action': 'Extract and submit flags',
                'priority': 'CRITICAL',
                'description': 'Direct flags found in response - extract and submit immediately'
            })
        
        if any(p.pattern_type == 'hint_comment' for p in patterns):
            analysis['has_hints'] = True
            analysis['priority_actions'].append({
                'action': 'Review hint comments',
                'priority': 'HIGH',
                'description': 'HTML comments contain hints - review for exploitation guidance'
            })
        
        if any(p.pattern_type == 'debug_endpoint' for p in patterns):
            analysis['has_debug_endpoints'] = True
            analysis['priority_actions'].append({
                'action': 'Explore debug endpoints',
                'priority': 'HIGH',
                'description': 'Debug endpoints referenced - explore for additional information'
            })
        
        if any(p.pattern_type in ['challenge_name', 'difficulty_level', 'point_value'] for p in patterns):
            analysis['has_metadata'] = True
            analysis['priority_actions'].append({
                'action': 'Review challenge metadata',
                'priority': 'MEDIUM',
                'description': 'Challenge metadata found - use to understand challenge context'
            })
        
        if any(p.pattern_type == 'encoded_flag' for p in patterns):
            analysis['priority_actions'].append({
                'action': 'Decode and verify encoded data',
                'priority': 'HIGH',
                'description': 'Encoded data with flag keywords found - decode and verify'
            })
        
        # Sort actions by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        analysis['priority_actions'].sort(key=lambda x: priority_order.get(x['priority'], 99))
        
        return analysis
    
    def _category_to_module(self, category: VulnerabilityCategory) -> str:
        """Map vulnerability category to attack module name"""
        mapping = {
            VulnerabilityCategory.SQL_INJECTION: "SQL Injection",
            VulnerabilityCategory.XSS: "XSS Testing",
            VulnerabilityCategory.COMMAND_INJECTION: "Command Injection",
            VulnerabilityCategory.SSRF: "SSRF Testing",
            VulnerabilityCategory.XXE: "XXE Testing",
            VulnerabilityCategory.DIRECTORY_TRAVERSAL: "Directory Traversal",
            VulnerabilityCategory.SSTI: "SSTI Testing",
            VulnerabilityCategory.DESERIALIZATION: "Deserialization",
            VulnerabilityCategory.AUTHENTICATION: "Authentication Testing",
            VulnerabilityCategory.AUTHORIZATION: "Authorization Testing",
            VulnerabilityCategory.INFORMATION_DISCLOSURE: "Information Gathering",
            VulnerabilityCategory.MISCONFIGURATION: "Security Configuration",
        }
        return mapping.get(category, "General Testing")
    
    def _generate_recommendations(
        self, indicators: List[VulnerabilityIndicator]
    ) -> List[str]:
        """Generate prioritized list of recommended attack modules"""
        # Count recommendations by module with weighted scoring
        module_scores = {}
        module_categories = {}  # Track which categories recommend each module
        
        for indicator in indicators:
            for module in indicator.recommended_modules:
                if module not in module_scores:
                    module_scores[module] = 0.0
                    module_categories[module] = set()
                
                # Weight by confidence (primary factor)
                module_scores[module] += indicator.confidence
                
                # Track category diversity (bonus for modules recommended by multiple categories)
                module_categories[module].add(indicator.category)
        
        # Apply diversity bonus (modules recommended by multiple categories get a boost)
        for module in module_scores:
            diversity_bonus = len(module_categories[module]) * 0.1
            module_scores[module] += diversity_bonus
        
        # Sort by score
        sorted_modules = sorted(
            module_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        # Return top modules
        return [module for module, score in sorted_modules]
    
    def get_detailed_recommendations(
        self, indicators: List[VulnerabilityIndicator]
    ) -> List[Dict]:
        """
        Generate detailed recommendations with reasoning.
        
        Returns:
            List of dictionaries with module name, score, and reasoning
        """
        module_data = {}
        
        for indicator in indicators:
            for module in indicator.recommended_modules:
                if module not in module_data:
                    module_data[module] = {
                        'module': module,
                        'score': 0.0,
                        'indicators': [],
                        'categories': set(),
                        'max_confidence': 0.0,
                    }
                
                data = module_data[module]
                data['score'] += indicator.confidence
                data['indicators'].append(indicator)
                data['categories'].add(indicator.category)
                data['max_confidence'] = max(data['max_confidence'], indicator.confidence)
        
        # Apply diversity bonus
        for module, data in module_data.items():
            diversity_bonus = len(data['categories']) * 0.1
            data['score'] += diversity_bonus
        
        # Convert to list and sort
        recommendations = []
        for module, data in module_data.items():
            # Generate reasoning
            reasoning_parts = []
            
            # Mention highest confidence indicator
            if data['max_confidence'] >= 0.7:
                reasoning_parts.append(f"High confidence indicator detected ({data['max_confidence']:.1%})")
            
            # Mention number of indicators
            if len(data['indicators']) > 1:
                reasoning_parts.append(f"{len(data['indicators'])} indicators point to this vulnerability")
            
            # Mention category diversity
            if len(data['categories']) > 1:
                reasoning_parts.append(f"Multiple vulnerability types suggest this module")
            
            reasoning = "; ".join(reasoning_parts) if reasoning_parts else "Potential vulnerability detected"
            
            recommendations.append({
                'module': module,
                'score': data['score'],
                'reasoning': reasoning,
                'indicator_count': len(data['indicators']),
                'max_confidence': data['max_confidence'],
                'categories': [cat.value for cat in data['categories']],
            })
        
        # Sort by score
        recommendations.sort(key=lambda x: x['score'], reverse=True)
        
        return recommendations


class QuickScanPreset:
    """Predefined quick-scan configurations for different CTF platforms"""
    
    # Store custom presets
    _custom_presets = {}
    
    @staticmethod
    def get_preset(preset_name: str) -> Dict:
        """
        Get a predefined quick-scan preset.
        
        Args:
            preset_name: Name of the preset (e.g., 'hackthebox', 'ctfd', 'picoctf')
            
        Returns:
            Dictionary with preset configuration
        """
        presets = {
            'default': {
                'name': 'Default Quick Scan',
                'description': 'Balanced scan across all vulnerability categories',
                'categories': list(VulnerabilityCategory),
                'timeout': 30,
                'max_payloads_per_category': 2,
                'enable_ctf_detection': True,
            },
            'hackthebox': {
                'name': 'HackTheBox Preset',
                'description': 'Optimized for HackTheBox challenges',
                'categories': [
                    VulnerabilityCategory.SQL_INJECTION,
                    VulnerabilityCategory.COMMAND_INJECTION,
                    VulnerabilityCategory.DIRECTORY_TRAVERSAL,
                    VulnerabilityCategory.AUTHENTICATION,
                    VulnerabilityCategory.INFORMATION_DISCLOSURE,
                ],
                'timeout': 45,
                'max_payloads_per_category': 3,
                'enable_ctf_detection': True,
            },
            'ctfd': {
                'name': 'CTFd Platform Preset',
                'description': 'Optimized for CTFd-based competitions',
                'categories': [
                    VulnerabilityCategory.SQL_INJECTION,
                    VulnerabilityCategory.XSS,
                    VulnerabilityCategory.SSTI,
                    VulnerabilityCategory.INFORMATION_DISCLOSURE,
                ],
                'timeout': 30,
                'max_payloads_per_category': 2,
                'enable_ctf_detection': True,
            },
            'picoctf': {
                'name': 'PicoCTF Preset',
                'description': 'Optimized for PicoCTF challenges',
                'categories': [
                    VulnerabilityCategory.SQL_INJECTION,
                    VulnerabilityCategory.COMMAND_INJECTION,
                    VulnerabilityCategory.XSS,
                    VulnerabilityCategory.AUTHENTICATION,
                ],
                'timeout': 30,
                'max_payloads_per_category': 2,
                'enable_ctf_detection': True,
            },
            'web_only': {
                'name': 'Web Vulnerabilities Only',
                'description': 'Focus on common web vulnerabilities',
                'categories': [
                    VulnerabilityCategory.SQL_INJECTION,
                    VulnerabilityCategory.XSS,
                    VulnerabilityCategory.AUTHENTICATION,
                    VulnerabilityCategory.AUTHORIZATION,
                ],
                'timeout': 20,
                'max_payloads_per_category': 2,
                'enable_ctf_detection': False,
            },
            'injection_focus': {
                'name': 'Injection Vulnerabilities Focus',
                'description': 'Deep focus on injection-type vulnerabilities',
                'categories': [
                    VulnerabilityCategory.SQL_INJECTION,
                    VulnerabilityCategory.COMMAND_INJECTION,
                    VulnerabilityCategory.XXE,
                    VulnerabilityCategory.SSTI,
                    VulnerabilityCategory.SSRF,
                ],
                'timeout': 40,
                'max_payloads_per_category': 3,
                'enable_ctf_detection': False,
            },
            'fast_triage': {
                'name': 'Fast Triage',
                'description': 'Ultra-fast scan for quick vulnerability assessment',
                'categories': [
                    VulnerabilityCategory.SQL_INJECTION,
                    VulnerabilityCategory.XSS,
                    VulnerabilityCategory.AUTHENTICATION,
                    VulnerabilityCategory.INFORMATION_DISCLOSURE,
                ],
                'timeout': 15,
                'max_payloads_per_category': 1,
                'enable_ctf_detection': True,
            },
            'comprehensive': {
                'name': 'Comprehensive Scan',
                'description': 'Thorough scan with extended testing',
                'categories': list(VulnerabilityCategory),
                'timeout': 60,
                'max_payloads_per_category': 5,
                'enable_ctf_detection': True,
            },
        }
        
        # Check custom presets first
        if preset_name in QuickScanPreset._custom_presets:
            return QuickScanPreset._custom_presets[preset_name]
        
        return presets.get(preset_name, presets['default'])
    
    @staticmethod
    def list_presets() -> List[Dict]:
        """List all available presets (built-in and custom)"""
        preset_names = [
            'default', 'hackthebox', 'ctfd', 'picoctf', 
            'web_only', 'injection_focus', 'fast_triage', 'comprehensive'
        ]
        
        # Add built-in presets
        presets = [QuickScanPreset.get_preset(name) for name in preset_names]
        
        # Add custom presets
        for name, preset in QuickScanPreset._custom_presets.items():
            presets.append(preset)
        
        return presets
    
    @staticmethod
    def create_custom_preset(
        name: str,
        description: str,
        categories: List[VulnerabilityCategory],
        timeout: int = 30,
        max_payloads_per_category: int = 2,
        enable_ctf_detection: bool = True,
        save: bool = False
    ) -> Dict:
        """
        Create a custom quick-scan preset.
        
        Args:
            name: Preset name
            description: Preset description
            categories: List of vulnerability categories to test
            timeout: Scan timeout in seconds
            max_payloads_per_category: Maximum payloads to test per category
            enable_ctf_detection: Whether to enable CTF pattern detection
            save: Whether to save this preset for future use
            
        Returns:
            Custom preset configuration
        """
        preset = {
            'name': name,
            'description': description,
            'categories': categories,
            'timeout': timeout,
            'max_payloads_per_category': max_payloads_per_category,
            'enable_ctf_detection': enable_ctf_detection,
            'custom': True,
        }
        
        if save:
            QuickScanPreset._custom_presets[name] = preset
        
        return preset
    
    @staticmethod
    def modify_preset(
        preset_name: str,
        **modifications
    ) -> Dict:
        """
        Modify an existing preset with custom parameters.
        
        Args:
            preset_name: Name of the preset to modify
            **modifications: Parameters to override (categories, timeout, etc.)
            
        Returns:
            Modified preset configuration
        """
        # Get base preset
        base_preset = QuickScanPreset.get_preset(preset_name).copy()
        
        # Apply modifications
        for key, value in modifications.items():
            if key in base_preset:
                base_preset[key] = value
        
        # Mark as modified
        base_preset['name'] = f"{base_preset['name']} (Modified)"
        base_preset['custom'] = True
        
        return base_preset
    
    @staticmethod
    def save_custom_preset(preset: Dict) -> None:
        """
        Save a custom preset for future use.
        
        Args:
            preset: Preset configuration to save
        """
        if 'name' not in preset:
            raise ValueError("Preset must have a 'name' field")
        
        QuickScanPreset._custom_presets[preset['name']] = preset
    
    @staticmethod
    def delete_custom_preset(preset_name: str) -> bool:
        """
        Delete a custom preset.
        
        Args:
            preset_name: Name of the preset to delete
            
        Returns:
            True if deleted, False if not found
        """
        if preset_name in QuickScanPreset._custom_presets:
            del QuickScanPreset._custom_presets[preset_name]
            return True
        return False
    
    @staticmethod
    def export_preset(preset_name: str) -> str:
        """
        Export a preset to JSON string.
        
        Args:
            preset_name: Name of the preset to export
            
        Returns:
            JSON string representation of the preset
        """
        import json
        preset = QuickScanPreset.get_preset(preset_name)
        
        # Convert enums to strings for JSON serialization
        export_data = preset.copy()
        if 'categories' in export_data:
            export_data['categories'] = [cat.value for cat in export_data['categories']]
        
        return json.dumps(export_data, indent=2)
    
    @staticmethod
    def import_preset(json_string: str, save: bool = True) -> Dict:
        """
        Import a preset from JSON string.
        
        Args:
            json_string: JSON string representation of the preset
            save: Whether to save the imported preset
            
        Returns:
            Imported preset configuration
        """
        import json
        data = json.loads(json_string)
        
        # Convert category strings back to enums
        if 'categories' in data:
            category_map = {cat.value: cat for cat in VulnerabilityCategory}
            data['categories'] = [
                category_map[cat_str] for cat_str in data['categories']
                if cat_str in category_map
            ]
        
        if save and 'name' in data:
            QuickScanPreset._custom_presets[data['name']] = data
        
        return data
    
    @staticmethod
    def get_preset_for_platform(platform: str) -> Dict:
        """
        Get the best preset for a specific CTF platform.
        
        Args:
            platform: Platform name (e.g., 'hackthebox', 'tryhackme', 'ctfd')
            
        Returns:
            Recommended preset configuration
        """
        platform_mapping = {
            'hackthebox': 'hackthebox',
            'htb': 'hackthebox',
            'tryhackme': 'hackthebox',  # Similar to HTB
            'thm': 'hackthebox',
            'ctfd': 'ctfd',
            'picoctf': 'picoctf',
            'pico': 'picoctf',
            'overthewire': 'web_only',
            'portswigger': 'web_only',
            'bugbounty': 'comprehensive',
        }
        
        preset_name = platform_mapping.get(platform.lower(), 'default')
        return QuickScanPreset.get_preset(preset_name)
