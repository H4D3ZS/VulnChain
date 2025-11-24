"""Tests for FastAPI backend API endpoints"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


class TestHealthEndpoints:
    """Test health check endpoints"""
    
    def test_root_endpoint(self):
        """Test root endpoint returns app info"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "version" in data
        assert "status" in data
        assert data["status"] == "running"
    
    def test_health_check(self):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data


class TestTargetEndpoints:
    """Test target configuration endpoints"""
    
    def test_create_target(self):
        """Test creating a target"""
        target_data = {
            "url": "https://example.com",
            "custom_headers": {"X-Test": "value"},
            "name": "Test Target"
        }
        response = client.post("/api/targets/", json=target_data)
        assert response.status_code == 200
        data = response.json()
        assert "target_id" in data
        assert data["url"] == target_data["url"]
        assert data["name"] == target_data["name"]
    
    def test_list_targets(self):
        """Test listing targets"""
        response = client.get("/api/targets/")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    def test_create_target_invalid_url(self):
        """Test creating target with invalid URL"""
        target_data = {
            "url": "not-a-valid-url",
            "name": "Invalid Target"
        }
        response = client.post("/api/targets/", json=target_data)
        assert response.status_code == 422  # Validation error


class TestModuleEndpoints:
    """Test attack module endpoints"""
    
    def test_list_modules(self):
        """Test listing available modules"""
        response = client.get("/api/modules/")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        
        # Check module structure
        module = data[0]
        assert "module_id" in module
        assert "name" in module
        assert "category" in module
        assert "description" in module
    
    def test_execute_module(self):
        """Test executing a module"""
        # First create a target
        target_data = {
            "url": "https://example.com",
            "name": "Test Target"
        }
        target_response = client.post("/api/targets/", json=target_data)
        target_id = target_response.json()["target_id"]
        
        # Execute module
        execution_data = {
            "target_id": target_id,
            "module_id": "sql-injection",
            "parameters": {"parameter": "id"}
        }
        response = client.post("/api/modules/execute", json=execution_data)
        assert response.status_code == 200
        data = response.json()
        assert "execution_id" in data
        assert data["status"] == "running"
    
    def test_get_execution_status(self):
        """Test getting execution status"""
        # Create target and execute module
        target_data = {"url": "https://example.com", "name": "Test"}
        target_response = client.post("/api/targets/", json=target_data)
        target_id = target_response.json()["target_id"]
        
        execution_data = {
            "target_id": target_id,
            "module_id": "xss",
            "parameters": {}
        }
        exec_response = client.post("/api/modules/execute", json=execution_data)
        execution_id = exec_response.json()["execution_id"]
        
        # Get status
        response = client.get(f"/api/modules/executions/{execution_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["execution_id"] == execution_id


class TestWorkspaceEndpoints:
    """Test workspace management endpoints"""
    
    def test_create_workspace(self):
        """Test creating a workspace"""
        workspace_data = {
            "name": "Test Workspace",
            "description": "A test workspace",
            "target_url": "https://example.com"
        }
        response = client.post("/api/workspaces/", json=workspace_data)
        assert response.status_code == 200
        data = response.json()
        assert "workspace_id" in data
        assert data["name"] == workspace_data["name"]
        assert data["findings_count"] == 0
    
    def test_list_workspaces(self):
        """Test listing workspaces"""
        response = client.get("/api/workspaces/")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    def test_get_workspace(self):
        """Test getting a specific workspace"""
        # Create workspace
        workspace_data = {"name": "Test", "description": "Test"}
        create_response = client.post("/api/workspaces/", json=workspace_data)
        workspace_id = create_response.json()["workspace_id"]
        
        # Get workspace
        response = client.get(f"/api/workspaces/{workspace_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["workspace_id"] == workspace_id
    
    def test_update_workspace(self):
        """Test updating a workspace"""
        # Create workspace
        workspace_data = {"name": "Original", "description": "Original"}
        create_response = client.post("/api/workspaces/", json=workspace_data)
        workspace_id = create_response.json()["workspace_id"]
        
        # Update workspace
        update_data = {"name": "Updated", "description": "Updated description"}
        response = client.put(f"/api/workspaces/{workspace_id}", json=update_data)
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated"
        assert data["description"] == "Updated description"
    
    def test_delete_workspace(self):
        """Test deleting a workspace"""
        # Create workspace
        workspace_data = {"name": "To Delete"}
        create_response = client.post("/api/workspaces/", json=workspace_data)
        workspace_id = create_response.json()["workspace_id"]
        
        # Delete workspace
        response = client.delete(f"/api/workspaces/{workspace_id}")
        assert response.status_code == 200
        
        # Verify deleted
        get_response = client.get(f"/api/workspaces/{workspace_id}")
        assert get_response.status_code == 404


class TestFindingEndpoints:
    """Test security findings endpoints"""
    
    def test_create_finding(self):
        """Test creating a finding"""
        # Create workspace first
        workspace_data = {"name": "Test Workspace"}
        workspace_response = client.post("/api/workspaces/", json=workspace_data)
        workspace_id = workspace_response.json()["workspace_id"]
        
        # Create finding
        finding_data = {
            "workspace_id": workspace_id,
            "vulnerability_type": "SQL Injection",
            "severity": "high",
            "title": "SQL Injection in login form",
            "description": "The login form is vulnerable to SQL injection",
            "affected_url": "https://example.com/login",
            "proof_of_concept": "' OR '1'='1",
            "flags": ["FLAG{test123}"]
        }
        response = client.post("/api/findings/", json=finding_data)
        assert response.status_code == 200
        data = response.json()
        assert "finding_id" in data
        assert data["severity"] == "high"
        assert len(data["flags"]) == 1
    
    def test_list_findings(self):
        """Test listing findings"""
        response = client.get("/api/findings/")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    def test_filter_findings_by_severity(self):
        """Test filtering findings by severity"""
        response = client.get("/api/findings/?severity=high")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # All returned findings should be high severity
        for finding in data:
            assert finding["severity"] == "high"


class TestSessionEndpoints:
    """Test session management endpoints"""
    
    def test_create_session(self):
        """Test creating a session"""
        session_data = {
            "domain": "example.com",
            "cookies": {"session": "abc123"},
            "headers": {"Authorization": "Bearer token"},
            "name": "Test Session"
        }
        response = client.post("/api/sessions/", json=session_data)
        assert response.status_code == 200
        data = response.json()
        assert "session_id" in data
        assert data["domain"] == session_data["domain"]
        assert data["cookies"] == session_data["cookies"]
    
    def test_list_sessions(self):
        """Test listing sessions"""
        response = client.get("/api/sessions/")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    def test_filter_sessions_by_domain(self):
        """Test filtering sessions by domain"""
        # Create session
        session_data = {
            "domain": "test.example.com",
            "cookies": {"session": "xyz789"}
        }
        client.post("/api/sessions/", json=session_data)
        
        # Filter by domain
        response = client.get("/api/sessions/?domain=test.example.com")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        for session in data:
            assert session["domain"] == "test.example.com"


class TestAuthEndpoints:
    """Test authentication endpoints"""
    
    def test_register_user(self):
        """Test user registration"""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "securepassword123"
        }
        response = client.post("/api/auth/register", json=user_data)
        assert response.status_code == 200
        data = response.json()
        assert "user_id" in data
        assert data["username"] == user_data["username"]
        assert data["email"] == user_data["email"]
        assert "password" not in data  # Password should not be returned
    
    def test_register_duplicate_username(self):
        """Test registering with duplicate username"""
        user_data = {
            "username": "duplicate",
            "email": "user1@example.com",
            "password": "password123"
        }
        # First registration
        client.post("/api/auth/register", json=user_data)
        
        # Second registration with same username
        user_data2 = {
            "username": "duplicate",
            "email": "user2@example.com",
            "password": "password456"
        }
        response = client.post("/api/auth/register", json=user_data2)
        assert response.status_code == 400
    
    def test_login(self):
        """Test user login"""
        # Register user
        user_data = {
            "username": "logintest",
            "email": "login@example.com",
            "password": "testpass123"
        }
        client.post("/api/auth/register", json=user_data)
        
        # Login
        login_data = {
            "username": "logintest",
            "password": "testpass123"
        }
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
    
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        login_data = {
            "username": "nonexistent",
            "password": "wrongpassword"
        }
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 401
    
    def test_get_current_user(self):
        """Test getting current user info"""
        # Register and login
        user_data = {
            "username": "currentuser",
            "email": "current@example.com",
            "password": "pass123"
        }
        client.post("/api/auth/register", json=user_data)
        
        login_response = client.post("/api/auth/login", json={
            "username": "currentuser",
            "password": "pass123"
        })
        token = login_response.json()["access_token"]
        
        # Get current user
        response = client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "currentuser"


class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def test_rate_limit_headers(self):
        """Test that rate limit headers are present"""
        response = client.get("/")
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
        assert "X-RateLimit-Reset" in response.headers
    
    def test_rate_limit_enforcement(self):
        """Test that rate limits are enforced"""
        # This test would need to make many requests quickly
        # For now, just verify the mechanism is in place
        response = client.get("/")
        limit = int(response.headers["X-RateLimit-Limit"])
        assert limit > 0
