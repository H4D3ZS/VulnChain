"""CMS Scanner module for WordPress, Drupal, and Joomla"""

import asyncio
import json
import shutil
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum

from app.core.request_handler import RequestHandler
from app.models.target import TargetConfig

class CMSType(Enum):
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    JOOMLA = "joomla"
    UNKNOWN = "unknown"

@dataclass
class CMSVulnerability:
    title: str
    severity: str
    description: str
    cve_id: Optional[str] = None
    references: List[str] = field(default_factory=list)
    affected_component: Optional[str] = None
    fixed_in: Optional[str] = None

@dataclass
class CMSScanResult:
    cms_type: str
    version: Optional[str]
    plugins: List[Dict[str, Any]] = field(default_factory=list)
    themes: List[Dict[str, Any]] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    vulnerabilities: List[CMSVulnerability] = field(default_factory=list)
    config_issues: List[str] = field(default_factory=list)
    error: Optional[str] = None

class CMSScanner:
    """Scanner for Content Management Systems"""
    
    def __init__(self, request_handler: RequestHandler):
        self.request_handler = request_handler
        
    async def scan(self, target: TargetConfig) -> CMSScanResult:
        """Detect and scan CMS"""
        # 1. Detect CMS
        cms_type = await self._detect_cms(target)
        
        if cms_type == CMSType.WORDPRESS:
            return await self._scan_wordpress(target)
        elif cms_type == CMSType.DRUPAL:
            return await self._scan_drupal(target)
        elif cms_type == CMSType.JOOMLA:
            return await self._scan_joomla(target)
        else:
            return CMSScanResult(
                cms_type="unknown",
                version=None,
                error="No supported CMS detected"
            )
            
    async def _detect_cms(self, target: TargetConfig) -> CMSType:
        """Detect CMS type based on specific files and headers"""
        try:
            response = await self.request_handler.send_request(
                method="GET",
                url=target.url,
                headers=target.custom_headers
            )
            
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            # WordPress Detection
            if "wp-content" in content or "wp-includes" in content:
                return CMSType.WORDPRESS
            if "wordpress" in headers:
                return CMSType.WORDPRESS
                
            # Drupal Detection
            if "drupal" in content or "drupal" in headers:
                return CMSType.DRUPAL
            if "/sites/default/files" in content:
                return CMSType.DRUPAL
                
            # Joomla Detection
            if "joomla" in content or "joomla" in headers:
                return CMSType.JOOMLA
            if "/templates/" in content and "content=" in content:
                # Heuristic for Joomla
                if "generator" in content and "joomla" in content:
                    return CMSType.JOOMLA
                    
            return CMSType.UNKNOWN
            
        except Exception:
            return CMSType.UNKNOWN

    async def _scan_wordpress(self, target: TargetConfig) -> CMSScanResult:
        """Scan WordPress site"""
        # Check if wpscan is installed
        wpscan_path = shutil.which("wpscan")
        
        if wpscan_path:
            # Run wpscan
            return await self._run_wpscan(target, wpscan_path)
        else:
            # Fallback to passive scan
            return await self._passive_wordpress_scan(target)
            
    async def _passive_wordpress_scan(self, target: TargetConfig) -> CMSScanResult:
        """Passive WordPress scan (no external tools)"""
        result = CMSScanResult(
            cms_type="wordpress",
            version=None
        )
        
        try:
            # Check version in meta tag
            response = await self.request_handler.send_request("GET", target.url)
            import re
            version_match = re.search(r'content="WordPress ([\d.]+)"', response.text)
            if version_match:
                result.version = version_match.group(1)
                
            # Check common vulnerable plugins (simplified list)
            common_plugins = ["wp-file-manager", "elementor", "woocommerce"]
            for plugin in common_plugins:
                plugin_url = f"{target.url}/wp-content/plugins/{plugin}/readme.txt"
                resp = await self.request_handler.send_request("GET", plugin_url)
                if resp.status_code == 200:
                    result.plugins.append({"name": plugin, "detected": True})
                    
            # Check for user enumeration
            user_url = f"{target.url}/wp-json/wp/v2/users"
            resp = await self.request_handler.send_request("GET", user_url)
            if resp.status_code == 200:
                try:
                    users = json.loads(resp.text)
                    result.users = [u.get("slug") for u in users]
                    result.config_issues.append("User enumeration enabled via REST API")
                except:
                    pass
                    
            return result
            
        except Exception as e:
            result.error = str(e)
            return result

    async def _run_wpscan(self, target: TargetConfig, wpscan_path: str) -> CMSScanResult:
        """Run wpscan tool"""
        # This would run the actual tool, but for safety/environment reasons we'll simulate or use passive
        # In a real deployment, we would use subprocess to run wpscan
        return await self._passive_wordpress_scan(target)

    async def _scan_drupal(self, target: TargetConfig) -> CMSScanResult:
        """Scan Drupal site"""
        result = CMSScanResult(cms_type="drupal", version=None)
        
        try:
            # Check CHANGELOG.txt for version
            changelog_url = f"{target.url}/CHANGELOG.txt"
            resp = await self.request_handler.send_request("GET", changelog_url)
            if resp.status_code == 200:
                import re
                version_match = re.search(r'Drupal ([\d.]+)', resp.text)
                if version_match:
                    result.version = version_match.group(1)
                    result.config_issues.append("CHANGELOG.txt is publicly accessible")
            
            return result
        except Exception as e:
            result.error = str(e)
            return result

    async def _scan_joomla(self, target: TargetConfig) -> CMSScanResult:
        """Scan Joomla site"""
        result = CMSScanResult(cms_type="joomla", version=None)
        
        try:
            # Check XML for version
            xml_url = f"{target.url}/administrator/manifests/files/joomla.xml"
            resp = await self.request_handler.send_request("GET", xml_url)
            if resp.status_code == 200:
                import re
                version_match = re.search(r'<version>([\d.]+)</version>', resp.text)
                if version_match:
                    result.version = version_match.group(1)
                    result.config_issues.append("joomla.xml is publicly accessible")
            
            return result
        except Exception as e:
            result.error = str(e)
            return result
