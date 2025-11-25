"""Attack module execution API endpoints"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Optional, List, Any
from datetime import datetime
import uuid
from app.core.module_executor import ModuleExecutor
from app.api.targets import targets_db
from app.models.target import TargetConfig

router = APIRouter(prefix="/api/modules", tags=["modules"])


class ModuleExecuteRequest(BaseModel):
    """Request model for module execution"""
    target_id: str
    module_id: str
    parameters: Dict[str, Any] = {}


class ModuleExecutionResponse(BaseModel):
    """Response model for module execution"""
    execution_id: str
    module_id: str
    target_id: str
    status: str
    started_at: str
    progress: int = 0


class ModuleInfo(BaseModel):
    """Module information"""
    module_id: str
    name: str
    category: str
    description: str
    parameters: List[Dict[str, Any]]
    estimated_time: Optional[str] = None
    guide: Optional[str] = None


# In-memory storage
executions_db: Dict[str, Dict[str, Any]] = {}


@router.get("/", response_model=List[ModuleInfo])
async def list_modules():
    """
    List all available attack modules.
    
    Returns:
        List of module information
    """
    modules = [
        # Injection Attacks (15)
        {
            "module_id": "sqli-error",
            "name": "SQL Injection (Error-Based)",
            "category": "Injection",
            "description": "Exploit SQL injection via error messages",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "1-3 min",
            "guide": "Find a URL parameter that retrieves data (e.g., ?id=1, ?cat=electronics). Enter the parameter name (e.g., 'id') here."
        },
        {
            "module_id": "sqli-time",
            "name": "SQL Injection (Time-Based)",
            "category": "Injection",
            "description": "Exploit blind SQL injection via time delays",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "3-10 min",
            "guide": "Use this when the page doesn't show errors but might be vulnerable. Enter the parameter name (e.g., 'id' in ?id=1)."
        },
        {
            "module_id": "sqli-boolean",
            "name": "SQL Injection (Boolean-Based)",
            "category": "Injection",
            "description": "Exploit blind SQL injection via content changes",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "3-8 min",
            "guide": "Use this when the page content changes based on true/false conditions. Enter the parameter name (e.g., 'id')."
        },
        {
            "module_id": "sqli-union",
            "name": "SQL Injection (Union-Based)",
            "category": "Injection",
            "description": "Exploit SQL injection via UNION operator",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "1-3 min",
            "guide": "Best for retrieving data from other tables. Requires the result to be visible on the page. Enter the parameter name."
        },
        {
            "module_id": "xss-reflected",
            "name": "Reflected XSS",
            "category": "Injection",
            "description": "Test for reflected Cross-Site Scripting",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "1-3 min",
            "guide": "Look for inputs that are reflected back on the page (e.g., search bars, error messages). Enter the input name (e.g., 'q' or 'search')."
        },
        {
            "module_id": "xss-stored",
            "name": "Stored XSS",
            "category": "Injection",
            "description": "Test for stored Cross-Site Scripting",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "2-5 min",
            "guide": "Look for inputs that save data (e.g., comments, profile fields). Enter the field name."
        },
        {
            "module_id": "xss-dom",
            "name": "DOM XSS",
            "category": "Injection",
            "description": "Test for DOM-based Cross-Site Scripting",
            "parameters": [],
            "estimated_time": "2-4 min",
            "guide": "This module analyzes client-side JavaScript for unsafe data handling. No parameter needed."
        },
        {
            "module_id": "cmd-injection-basic",
            "name": "Command Injection (Basic)",
            "category": "Injection",
            "description": "Test for basic OS command injection",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "1-3 min",
            "guide": "Look for parameters that might interact with the OS (e.g., ?ip=1.1.1.1, ?file=report.pdf). Enter the parameter name."
        },
        {
            "module_id": "cmd-injection-blind",
            "name": "Command Injection (Blind)",
            "category": "Injection",
            "description": "Test for blind OS command injection (OOB)",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "2-5 min",
            "guide": "Use this when you don't see command output. It uses time delays or external callbacks. Enter the parameter name."
        },
        {
            "module_id": "nosql-injection",
            "name": "NoSQL Injection",
            "category": "Injection",
            "description": "Test for NoSQL injection (MongoDB, etc.)",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "2-4 min",
            "guide": "Target login forms or search filters in modern apps (Node.js/MongoDB). Enter the parameter name (e.g., 'username')."
        },
        {
            "module_id": "ssti",
            "name": "Server-Side Template Injection",
            "category": "Injection",
            "description": "Test for template injection (Jinja2, Twig, etc.)",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "2-5 min",
            "guide": "Look for inputs reflected in emails or generated pages. Enter the parameter name (e.g., 'name' in ?name=User)."
        },
        {
            "module_id": "xxe",
            "name": "XML External Entity (XXE)",
            "category": "Injection",
            "description": "Test for XXE in XML parsers",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "2-4 min",
            "guide": "Target endpoints that accept XML input. Enter the parameter name containing XML data."
        },
        {
            "module_id": "ssrf-basic",
            "name": "SSRF (Basic)",
            "category": "Injection",
            "description": "Test for Server-Side Request Forgery",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "2-4 min",
            "guide": "Look for parameters taking a URL (e.g., ?url=http://..., ?webhook=...). Enter the parameter name."
        },
        {
            "module_id": "ssrf-cloud",
            "name": "SSRF (Cloud Metadata)",
            "category": "Injection",
            "description": "Test for Cloud Metadata extraction via SSRF",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "2-5 min",
            "guide": "Target URL parameters to try extracting AWS/GCP/Azure credentials. Enter the parameter name."
        },
        
        # Authentication (8)
        {
            "module_id": "brute-force-login",
            "name": "Login Brute Force",
            "category": "Authentication",
            "description": "Brute force login credentials",
            "parameters": [
                {"name": "username_list", "type": "file", "required": True, "description": "Upload username list (.txt)"},
                {"name": "password_list", "type": "file", "required": True, "description": "Upload password list (.txt)"}
            ],
            "estimated_time": "5-30 min",
            "guide": "Upload lists of usernames and passwords to test. The module will try every combination against the login page."
        },
        {
            "module_id": "username-enum",
            "name": "Username Enumeration",
            "category": "Authentication",
            "description": "Enumerate valid usernames via timing/errors",
            "parameters": [{"name": "username_list", "type": "file", "required": True, "description": "Upload username list (.txt)"}],
            "estimated_time": "3-10 min",
            "guide": "Upload a list of usernames. The module analyzes response times and errors to identify valid accounts."
        },
        {
            "module_id": "jwt-none",
            "name": "JWT 'None' Algorithm",
            "category": "Authentication",
            "description": "Test JWT for 'None' algorithm vulnerability",
            "parameters": [],
            "estimated_time": "1 min",
            "guide": "Automatically tests if the application accepts unsigned JWTs (alg: none). No parameters needed."
        },
        {
            "module_id": "jwt-weak-key",
            "name": "JWT Weak Key",
            "category": "Authentication",
            "description": "Test JWT for weak signing keys",
            "parameters": [],
            "estimated_time": "2-5 min",
            "guide": "Attempts to crack the JWT signature using common weak secrets. No parameters needed."
        },
        {
            "module_id": "oauth-redirect",
            "name": "OAuth Redirect Hijack",
            "category": "Authentication",
            "description": "Test OAuth redirect_uri validation",
            "parameters": [],
            "estimated_time": "2-4 min",
            "guide": "Tests if the OAuth flow allows redirecting to arbitrary URLs. No parameters needed."
        },
        {
            "module_id": "saml-signature",
            "name": "SAML Signature Bypass",
            "category": "Authentication",
            "description": "Test SAML XML signature wrapping/stripping",
            "parameters": [],
            "estimated_time": "2-5 min",
            "guide": "Tests for XML Signature Wrapping attacks in SAML authentication. No parameters needed."
        },
        {
            "module_id": "auth-bypass",
            "name": "API Auth Bypass",
            "category": "Authentication",
            "description": "Test for broken authentication in APIs",
            "parameters": [],
            "estimated_time": "2-5 min",
            "guide": "Checks if API endpoints can be accessed without authentication or with invalid tokens."
        },
        {
            "module_id": "csrf",
            "name": "CSRF",
            "category": "Authentication",
            "description": "Test for Cross-Site Request Forgery",
            "parameters": [],
            "estimated_time": "1-3 min",
            "guide": "Checks if state-changing requests (POST/PUT) are protected by anti-CSRF tokens."
        },

        # API & Logic (10)
        {
            "module_id": "api-discovery",
            "name": "REST API Discovery",
            "category": "API",
            "description": "Discover OpenAPI/Swagger documentation",
            "parameters": [],
            "estimated_time": "2-5 min",
            "guide": "Scans for common API documentation paths (e.g., /swagger.json, /api-docs)."
        },
        {
            "module_id": "graphql-introspection",
            "name": "GraphQL Introspection",
            "category": "API",
            "description": "Test for enabled GraphQL introspection",
            "parameters": [],
            "estimated_time": "1-2 min",
            "guide": "Checks if the GraphQL schema is publicly accessible via introspection queries."
        },
        {
            "module_id": "graphql-depth",
            "name": "GraphQL Depth Limit",
            "category": "API",
            "description": "Test GraphQL query depth limits",
            "parameters": [],
            "estimated_time": "1-3 min",
            "guide": "Tests if the GraphQL server allows deeply nested queries (potential DoS)."
        },
        {
            "module_id": "api-idor",
            "name": "API IDOR",
            "category": "API",
            "description": "Test for Insecure Direct Object Reference",
            "parameters": [],
            "estimated_time": "3-8 min",
            "guide": "Tests if accessing resources with different IDs (e.g., /users/1 vs /users/2) is allowed."
        },
        {
            "module_id": "api-mass-assignment",
            "name": "API Mass Assignment",
            "category": "API",
            "description": "Test for Mass Assignment vulnerabilities",
            "parameters": [],
            "estimated_time": "2-5 min",
            "guide": "Tests if sensitive fields (like 'isAdmin') can be modified by including them in the request."
        },
        {
            "module_id": "race-condition",
            "name": "Race Condition",
            "category": "Logic",
            "description": "Test for race conditions",
            "parameters": [{"name": "threads", "type": "number", "default": 10}],
            "estimated_time": "1-3 min",
            "guide": "Sends parallel requests to test for concurrency issues. Adjust 'threads' for intensity."
        },
        {
            "module_id": "cache-poisoning",
            "name": "Cache Poisoning",
            "category": "Logic",
            "description": "Test for Web Cache Poisoning",
            "parameters": [],
            "estimated_time": "2-5 min",
            "guide": "Tests if the cache can be poisoned using unkeyed headers (e.g., X-Forwarded-Host)."
        },
        {
            "module_id": "websocket-hijack",
            "name": "WebSocket Hijacking",
            "category": "Logic",
            "description": "Test for Cross-Site WebSocket Hijacking",
            "parameters": [],
            "estimated_time": "2-4 min",
            "guide": "Checks if WebSocket connections are protected against CSWSH (Origin validation)."
        },
        {
            "module_id": "websocket-sse",
            "name": "WebSocket SSE",
            "category": "Logic",
            "description": "Test for Server-Sent Events vulnerabilities",
            "parameters": [],
            "estimated_time": "2-4 min",
            "guide": "Tests for vulnerabilities in Server-Sent Events implementations."
        },
        {
            "module_id": "cors-misconfig",
            "name": "CORS Misconfiguration",
            "category": "Logic",
            "description": "Test for insecure CORS configuration",
            "parameters": [],
            "estimated_time": "1-2 min",
            "guide": "Checks for overly permissive CORS policies (e.g., Access-Control-Allow-Origin: *)."
        },
        {
            "module_id": "business-logic",
            "name": "Business Logic Flaws",
            "category": "Logic",
            "description": "Generic business logic testing",
            "parameters": [],
            "estimated_time": "5-10 min",
            "guide": "Performs heuristic checks for common logic flaws."
        },

        # File & System (7)
        {
            "module_id": "path-traversal",
            "name": "Path Traversal",
            "category": "File Access",
            "description": "Test for directory traversal",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "1-3 min",
            "guide": "Look for parameters that specify file paths (e.g., ?file=report.pdf). Enter the parameter name."
        },
        {
            "module_id": "lfi",
            "name": "Local File Inclusion (LFI)",
            "category": "File Access",
            "description": "Test for LFI vulnerabilities",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "2-4 min",
            "guide": "Similar to Path Traversal, but tests if the application executes/includes the file. Enter the parameter name."
        },
        {
            "module_id": "rfi",
            "name": "Remote File Inclusion (RFI)",
            "category": "File Access",
            "description": "Test for RFI vulnerabilities",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "2-4 min",
            "guide": "Tests if the application includes remote files (e.g., ?page=http://evil.com/shell.php). Enter the parameter name."
        },
        {
            "module_id": "file-upload-ext",
            "name": "File Upload (Extension)",
            "category": "File Access",
            "description": "Test file upload extension bypass",
            "parameters": [{"name": "endpoint", "type": "string", "required": True}],
            "estimated_time": "2-5 min",
            "guide": "Enter the URL path where files are uploaded (e.g., /upload). The module will try to bypass extension filters."
        },
        {
            "module_id": "file-upload-mime",
            "name": "File Upload (MIME)",
            "category": "File Access",
            "description": "Test file upload MIME type bypass",
            "parameters": [{"name": "endpoint", "type": "string", "required": True}],
            "estimated_time": "2-5 min",
            "guide": "Enter the upload endpoint. The module will try to bypass MIME type checks."
        },
        {
            "module_id": "deserialization",
            "name": "Insecure Deserialization",
            "category": "File Access",
            "description": "Test for unsafe object deserialization",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "2-5 min",
            "guide": "Look for base64 encoded objects in cookies or parameters. Enter the parameter/cookie name."
        },
        {
            "module_id": "prototype-pollution",
            "name": "Prototype Pollution",
            "category": "File Access",
            "description": "Test for JS prototype pollution",
            "parameters": [{"name": "parameter", "type": "string", "required": True}],
            "estimated_time": "2-4 min",
            "guide": "Tests if JSON input can modify the Object prototype. Enter the parameter name."
        },

        # Discovery & Recon (6)
        {
            "module_id": "port-scan",
            "name": "Port Scanning",
            "category": "Discovery",
            "description": "Scan for open ports",
            "parameters": [],
            "estimated_time": "2-10 min",
            "guide": "Scans the target host for open ports (top 100 common ports)."
        },
        {
            "module_id": "subdomain-enum",
            "name": "Subdomain Enumeration",
            "category": "Discovery",
            "description": "Enumerate subdomains",
            "parameters": [],
            "estimated_time": "5-15 min",
            "guide": "Finds subdomains of the target domain using passive sources and brute force."
        },
        {
            "module_id": "tech-fingerprint",
            "name": "Tech Fingerprinting",
            "category": "Discovery",
            "description": "Identify technologies used",
            "parameters": [],
            "estimated_time": "1-3 min",
            "guide": "Identifies the tech stack (CMS, Frameworks, Servers) used by the target."
        },
        {
            "module_id": "directory-fuzz",
            "name": "Directory Fuzzing",
            "category": "Discovery",
            "description": "Fuzz for hidden directories/files",
            "parameters": [],
            "estimated_time": "5-20 min",
            "guide": "Brute-forces common directory and file names to find hidden content."
        },
        {
            "module_id": "js-analysis",
            "name": "JavaScript Analysis",
            "category": "Discovery",
            "description": "Analyze JS files for secrets/endpoints",
            "parameters": [],
            "estimated_time": "2-5 min",
            "guide": "Scans client-side JavaScript files for API keys, secrets, and hidden endpoints."
        },
        {
            "module_id": "cms-scanner",
            "name": "CMS Scanner",
            "category": "Discovery",
            "description": "Scan for CMS vulnerabilities",
            "parameters": [],
            "estimated_time": "1-3 min",
            "guide": "Detects CMS (WordPress, Joomla, etc.) and scans for known vulnerabilities."
        },

        # Advanced & AI (6)
        {
            "module_id": "headless-browser",
            "name": "Headless Browser",
            "category": "Advanced",
            "description": "Automated browser testing",
            "parameters": [{"name": "scenario", "type": "string", "required": True}],
            "estimated_time": "3-10 min",
            "guide": "Define a navigation scenario (e.g., 'login -> click button')."
        },
        {
            "module_id": "ml-prompt-injection",
            "name": "ML Prompt Injection",
            "category": "Advanced",
            "description": "Test for LLM prompt injection",
            "parameters": [{"name": "endpoint", "type": "string", "required": True}],
            "estimated_time": "2-5 min",
            "guide": "Enter the API endpoint that interacts with an LLM. Tests for prompt injection."
        },
        {
            "module_id": "ml-jailbreak",
            "name": "ML Jailbreak",
            "category": "Advanced",
            "description": "Test for LLM jailbreaks",
            "parameters": [{"name": "endpoint", "type": "string", "required": True}],
            "estimated_time": "2-5 min",
            "guide": "Tests if the LLM can be tricked into generating harmful content."
        },
        {
            "module_id": "ml-model-inversion",
            "name": "ML Model Inversion",
            "category": "Advanced",
            "description": "Test for training data extraction",
            "parameters": [{"name": "endpoint", "type": "string", "required": True}],
            "estimated_time": "3-8 min",
            "guide": "Attempts to extract training data from the ML model."
        },
        {
            "module_id": "ml-adversarial",
            "name": "ML Adversarial Input",
            "category": "Advanced",
            "description": "Test for adversarial examples",
            "parameters": [{"name": "endpoint", "type": "string", "required": True}],
            "estimated_time": "3-8 min",
            "guide": "Tests if the model can be fooled by subtly modified inputs."
        },
        {
            "module_id": "ml-indirect",
            "name": "ML Indirect Injection",
            "category": "Advanced",
            "description": "Test for indirect prompt injection",
            "parameters": [{"name": "endpoint", "type": "string", "required": True}],
            "estimated_time": "2-5 min",
            "guide": "Tests if the LLM can be compromised by processing malicious external content."
        }
    ]
    
    return modules


@router.post("/execute", response_model=ModuleExecutionResponse)
async def execute_module(request: ModuleExecuteRequest, background_tasks: BackgroundTasks):
    """
    Execute an attack module.
    
    Args:
        request: Execution request details
        background_tasks: FastAPI background tasks
        
    Returns:
        Execution status and ID
    """
    if request.target_id not in targets_db:
        raise HTTPException(status_code=404, detail="Target not found")
        
    target = targets_db[request.target_id]
    execution_id = str(uuid.uuid4())
    
    # Create execution record
    execution_record = {
        "execution_id": execution_id,
        "module_id": request.module_id,
        "target_id": request.target_id,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "progress": 0,
        "findings": []
    }
    
    executions_db[execution_id] = execution_record
    
    # Run in background
    background_tasks.add_task(
        _run_module_task,
        execution_id,
        request.module_id,
        target,
        request.parameters
    )
    
    return ModuleExecutionResponse(
        execution_id=execution_id,
        module_id=request.module_id,
        target_id=request.target_id,
        status="running",
        started_at=execution_record["started_at"],
        progress=0
    )


async def _run_module_task(execution_id: str, module_id: str, target: TargetConfig, parameters: Dict[str, Any]):
    """Background task for running module"""
    executor = ModuleExecutor()
    try:
        result = await executor.execute_module(module_id, target, parameters)
        
        # Update record
        if execution_id in executions_db:
            executions_db[execution_id]["status"] = "completed"
            executions_db[execution_id]["progress"] = 100
            executions_db[execution_id]["result"] = result
            if "findings" in result:
                executions_db[execution_id]["findings"] = result["findings"]
                
    except Exception as e:
        if execution_id in executions_db:
            executions_db[execution_id]["status"] = "failed"
            executions_db[execution_id]["error"] = str(e)
    finally:
        await executor.close()


@router.get("/executions/{execution_id}", response_model=Dict[str, Any])
async def get_execution_status(execution_id: str):
    """
    Get status of a module execution.
    
    Args:
        execution_id: Execution ID
        
    Returns:
        Execution details
    """
    if execution_id not in executions_db:
        raise HTTPException(status_code=404, detail="Execution not found")
        
    return executions_db[execution_id]
