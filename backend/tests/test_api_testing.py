"""Tests for API testing module"""

import pytest
import json
from unittest.mock import AsyncMock, Mock, patch

from app.modules.api_testing import (
    APITestingModule,
    RESTAPIDiscovery,
    GraphQLTesting,
    APIVulnerabilityDetector,
    APIEndpoint,
    OpenAPISpec,
    GraphQLSchema,
    APIVulnerability,
)
from app.core.request_handler import RequestHandler
from app.core.http_models import Response
from app.models.target import TargetConfig


# Test fixtures

@pytest.fixture
def request_handler():
    """Create test request handler"""
    return RequestHandler()


@pytest.fixture
def rest_discovery(request_handler):
    """Create REST API discovery"""
    return RESTAPIDiscovery(request_handler)


@pytest.fixture
def graphql_testing(request_handler):
    """Create GraphQL testing"""
    return GraphQLTesting(request_handler)


@pytest.fixture
def vulnerability_detector(request_handler):
    """Create API vulnerability detector"""
    return APIVulnerabilityDetector(request_handler)


@pytest.fixture
def api_module(request_handler):
    """Create API testing module"""
    return APITestingModule(request_handler)


@pytest.fixture
def target_config():
    """Create test target configuration"""
    return TargetConfig(
        url="https://api.example.com",
        custom_headers={"Authorization": "Bearer test_token"}
    )


@pytest.fixture
def sample_openapi_spec():
    """Sample OpenAPI 3.0 specification"""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "description": "A test API",
            "version": "1.0.0"
        },
        "servers": [
            {"url": "https://api.example.com/v1"}
        ],
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get all users",
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"type": "object"}
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "summary": "Create user",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {"description": "Created"}
                    }
                }
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user by ID",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"}
                        }
                    ],
                    "responses": {
                        "200": {"description": "Success"}
                    }
                }
            }
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer"
                }
            }
        }
    }


# REST API Discovery Tests

class TestRESTAPIDiscovery:
    """Tests for RESTAPIDiscovery class"""
    
    @pytest.mark.asyncio
    async def test_discover_openapi_spec_found(self, rest_discovery, target_config, sample_openapi_spec):
        """Test discovering OpenAPI spec when it exists"""
        # Mock response
        mock_response = Response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(sample_openapi_spec).encode(),
            text=json.dumps(sample_openapi_spec),
            elapsed_time=0.1,
            request=Mock()
        )
        
        with patch.object(rest_discovery.request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response
            
            spec = await rest_discovery.discover_openapi_spec(target_config)
            
            assert spec is not None
            assert spec.version == "3.0.0"
            assert spec.title == "Test API"
            assert spec.description == "A test API"
            assert len(spec.endpoints) == 3  # GET /users, POST /users, GET /users/{id}
    
    @pytest.mark.asyncio
    async def test_discover_openapi_spec_not_found(self, rest_discovery, target_config):
        """Test when OpenAPI spec is not found"""
        # Mock 404 response
        mock_response = Response(
            status_code=404,
            headers={},
            body=b"Not Found",
            text="Not Found",
            elapsed_time=0.1,
            request=Mock()
        )
        
        with patch.object(rest_discovery.request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response
            
            spec = await rest_discovery.discover_openapi_spec(target_config)
            
            assert spec is None
    
    def test_is_valid_openapi_spec_v3(self, rest_discovery):
        """Test validation of OpenAPI 3.x spec"""
        spec_data = {"openapi": "3.0.0", "info": {}, "paths": {}}
        assert rest_discovery._is_valid_openapi_spec(spec_data) is True
    
    def test_is_valid_openapi_spec_v2(self, rest_discovery):
        """Test validation of Swagger 2.0 spec"""
        spec_data = {"swagger": "2.0", "info": {}, "paths": {}}
        assert rest_discovery._is_valid_openapi_spec(spec_data) is True
    
    def test_is_valid_openapi_spec_invalid(self, rest_discovery):
        """Test validation of invalid spec"""
        spec_data = {"version": "1.0", "info": {}}
        assert rest_discovery._is_valid_openapi_spec(spec_data) is False

    
    def test_parse_openapi_spec(self, rest_discovery, sample_openapi_spec):
        """Test parsing OpenAPI specification"""
        spec = rest_discovery._parse_openapi_spec("https://api.example.com/openapi.json", sample_openapi_spec)
        
        assert spec.version == "3.0.0"
        assert spec.title == "Test API"
        assert spec.base_path == "https://api.example.com/v1"
        assert len(spec.endpoints) == 3
        
        # Check endpoints
        get_users = next((e for e in spec.endpoints if e.path == "/users" and e.method == "GET"), None)
        assert get_users is not None
        assert get_users.description == "Get all users"
        assert get_users.requires_auth is False
        
        post_users = next((e for e in spec.endpoints if e.path == "/users" and e.method == "POST"), None)
        assert post_users is not None
        assert post_users.requires_auth is True
    
    @pytest.mark.asyncio
    async def test_test_unauthenticated_access_vulnerable(self, rest_discovery, target_config):
        """Test detecting unauthenticated access vulnerability"""
        # Mock successful response without auth
        mock_response = Response(
            status_code=200,
            headers={},
            body=b'{"data": "success"}',
            text='{"data": "success"}',
            elapsed_time=0.1,
            request=Mock()
        )
        
        with patch.object(rest_discovery.request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response
            
            vuln = await rest_discovery._test_unauthenticated_access(
                "https://api.example.com/users",
                "GET",
                target_config
            )
            
            assert vuln is not None
            assert vuln.vulnerability_type == "authentication_bypass"
            assert vuln.severity == "high"
    
    @pytest.mark.asyncio
    async def test_test_unauthenticated_access_secure(self, rest_discovery, target_config):
        """Test when endpoint properly requires authentication"""
        # Mock 401 response
        mock_response = Response(
            status_code=401,
            headers={},
            body=b'{"error": "Unauthorized"}',
            text='{"error": "Unauthorized"}',
            elapsed_time=0.1,
            request=Mock()
        )
        
        with patch.object(rest_discovery.request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response
            
            vuln = await rest_discovery._test_unauthenticated_access(
                "https://api.example.com/users",
                "GET",
                target_config
            )
            
            assert vuln is None
    
    def test_has_id_parameter_in_path(self, rest_discovery):
        """Test detecting ID parameter in path"""
        endpoint = APIEndpoint(path="/users/{id}", method="GET")
        assert rest_discovery._has_id_parameter(endpoint) is True
        
        endpoint = APIEndpoint(path="/users/{user_id}", method="GET")
        assert rest_discovery._has_id_parameter(endpoint) is True
        
        endpoint = APIEndpoint(path="/users", method="GET")
        assert rest_discovery._has_id_parameter(endpoint) is False


# GraphQL Testing Tests

class TestGraphQLTesting:
    """Tests for GraphQLTesting class"""
    
    @pytest.mark.asyncio
    async def test_detect_graphql_endpoint_found(self, graphql_testing, target_config):
        """Test detecting GraphQL endpoint"""
        # Mock GraphQL response
        mock_response = Response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=b'{"data": {"__typename": "Query"}}',
            text='{"data": {"__typename": "Query"}}',
            elapsed_time=0.1,
            request=Mock()
        )
        
        with patch.object(graphql_testing.request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response
            
            endpoint = await graphql_testing.detect_graphql_endpoint(target_config)
            
            assert endpoint is not None
            assert "/graphql" in endpoint
    
    @pytest.mark.asyncio
    async def test_detect_graphql_endpoint_not_found(self, graphql_testing, target_config):
        """Test when GraphQL endpoint is not found"""
        # Mock 404 response
        mock_response = Response(
            status_code=404,
            headers={},
            body=b"Not Found",
            text="Not Found",
            elapsed_time=0.1,
            request=Mock()
        )
        
        with patch.object(graphql_testing.request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response
            
            endpoint = await graphql_testing.detect_graphql_endpoint(target_config)
            
            assert endpoint is None

    
    @pytest.mark.asyncio
    async def test_execute_introspection_success(self, graphql_testing, target_config):
        """Test successful GraphQL introspection"""
        # Mock introspection response
        introspection_result = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "fields": [
                                {"name": "user", "description": "Get user"}
                            ]
                        },
                        {
                            "name": "Mutation",
                            "kind": "OBJECT",
                            "fields": [
                                {"name": "createUser", "description": "Create user"}
                            ]
                        }
                    ]
                }
            }
        }
        
        mock_response = Response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps(introspection_result).encode(),
            text=json.dumps(introspection_result),
            elapsed_time=0.1,
            request=Mock()
        )
        
        with patch.object(graphql_testing.request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response
            
            schema = await graphql_testing.execute_introspection(
                target_config,
                "https://api.example.com/graphql"
            )
            
            assert schema is not None
            assert len(schema.types) == 2
            assert len(schema.queries) == 1
            assert len(schema.mutations) == 1
    
    @pytest.mark.asyncio
    async def test_test_query_depth_limits_vulnerable(self, graphql_testing, target_config):
        """Test detecting missing query depth limits"""
        # Create mock schema
        schema = GraphQLSchema(
            url="https://api.example.com/graphql",
            queries=[{"name": "user"}]
        )
        
        # Mock successful response to deep query
        mock_response = Response(
            status_code=200,
            headers={},
            body=b'{"data": {}}',
            text='{"data": {}}',
            elapsed_time=0.1,
            request=Mock()
        )
        
        with patch.object(graphql_testing.request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response
            
            vulns = await graphql_testing.test_query_depth_limits(
                target_config,
                "https://api.example.com/graphql",
                schema
            )
            
            assert len(vulns) == 1
            assert vulns[0].vulnerability_type == "graphql_depth_limit"
    
    @pytest.mark.asyncio
    async def test_test_query_batching_vulnerable(self, graphql_testing, target_config):
        """Test detecting unlimited query batching"""
        schema = GraphQLSchema(
            url="https://api.example.com/graphql",
            queries=[{"name": "user"}]
        )
        
        # Mock successful batch response
        mock_response = Response(
            status_code=200,
            headers={},
            body=b'[{"data": {}}]',
            text='[{"data": {}}]',
            elapsed_time=0.1,
            request=Mock()
        )
        
        with patch.object(graphql_testing.request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response
            
            vulns = await graphql_testing.test_query_batching(
                target_config,
                "https://api.example.com/graphql",
                schema
            )
            
            assert len(vulns) == 1
            assert vulns[0].vulnerability_type == "graphql_batch_attack"


# API Vulnerability Detector Tests

class TestAPIVulnerabilityDetector:
    """Tests for APIVulnerabilityDetector class"""
    
    @pytest.mark.asyncio
    async def test_detect_excessive_data_exposure(self, vulnerability_detector, target_config):
        """Test detecting excessive data exposure"""
        endpoint = APIEndpoint(path="/users/1", method="GET")
        
        # Mock response with sensitive data
        mock_response = Response(
            status_code=200,
            headers={},
            body=b'{"id": 1, "name": "John", "password": "secret123", "api_key": "key123"}',
            text='{"id": 1, "name": "John", "password": "secret123", "api_key": "key123"}',
            elapsed_time=0.1,
            request=Mock()
        )
        
        with patch.object(vulnerability_detector.request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response
            
            vuln = await vulnerability_detector.detect_excessive_data_exposure(
                target_config,
                endpoint
            )
            
            assert vuln is not None
            assert vuln.vulnerability_type == "excessive_data_exposure"
            assert "password" in vuln.metadata["sensitive_fields"]
            assert "api_key" in vuln.metadata["sensitive_fields"]
    
    @pytest.mark.asyncio
    async def test_detect_mass_assignment(self, vulnerability_detector, target_config):
        """Test detecting mass assignment vulnerability"""
        endpoint = APIEndpoint(path="/users", method="POST")
        
        # Mock response that echoes back privileged fields
        mock_response = Response(
            status_code=201,
            headers={},
            body=b'{"id": 1, "name": "test", "is_admin": true, "role": "admin"}',
            text='{"id": 1, "name": "test", "is_admin": true, "role": "admin"}',
            elapsed_time=0.1,
            request=Mock()
        )
        
        with patch.object(vulnerability_detector.request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response
            
            vuln = await vulnerability_detector.detect_mass_assignment(
                target_config,
                endpoint
            )
            
            assert vuln is not None
            assert vuln.vulnerability_type == "mass_assignment"
            assert "is_admin" in vuln.metadata["accepted_fields"]

    
    @pytest.mark.asyncio
    async def test_detect_rate_limiting_missing(self, vulnerability_detector, target_config):
        """Test detecting missing rate limiting"""
        endpoint = APIEndpoint(path="/api/login", method="POST")
        
        # Mock successful responses for all requests
        mock_response = Response(
            status_code=200,
            headers={},
            body=b'{"success": true}',
            text='{"success": true}',
            elapsed_time=0.1,
            request=Mock()
        )
        
        with patch.object(vulnerability_detector.request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response
            
            vuln = await vulnerability_detector.detect_rate_limiting(
                target_config,
                endpoint,
                num_requests=20
            )
            
            assert vuln is not None
            assert vuln.vulnerability_type == "missing_rate_limiting"
            assert vuln.metadata["successful_requests"] >= 16  # 80% of 20
    
    @pytest.mark.asyncio
    async def test_detect_rate_limiting_present(self, vulnerability_detector, target_config):
        """Test when rate limiting is properly implemented"""
        endpoint = APIEndpoint(path="/api/login", method="POST")
        
        # Mock 429 responses (rate limited)
        mock_response = Response(
            status_code=429,
            headers={},
            body=b'{"error": "Too many requests"}',
            text='{"error": "Too many requests"}',
            elapsed_time=0.1,
            request=Mock()
        )
        
        with patch.object(vulnerability_detector.request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_response
            
            vuln = await vulnerability_detector.detect_rate_limiting(
                target_config,
                endpoint,
                num_requests=20
            )
            
            assert vuln is None


# API Testing Module Integration Tests

class TestAPITestingModule:
    """Tests for APITestingModule class"""
    
    @pytest.mark.asyncio
    async def test_test_rest_api(self, api_module, target_config, sample_openapi_spec):
        """Test comprehensive REST API testing"""
        # Mock OpenAPI spec discovery
        mock_spec_response = Response(
            status_code=200,
            headers={},
            body=json.dumps(sample_openapi_spec).encode(),
            text=json.dumps(sample_openapi_spec),
            elapsed_time=0.1,
            request=Mock()
        )
        
        # Mock endpoint testing responses
        mock_endpoint_response = Response(
            status_code=200,
            headers={},
            body=b'{"data": []}',
            text='{"data": []}',
            elapsed_time=0.1,
            request=Mock()
        )
        
        with patch.object(api_module.request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.return_value = mock_spec_response
            
            # First call returns spec, subsequent calls return endpoint responses
            mock_send.side_effect = [mock_spec_response] + [mock_endpoint_response] * 20
            
            results = await api_module.test_rest_api(target_config)
            
            assert results['openapi_spec'] is not None
            assert results['openapi_spec']['title'] == "Test API"
            assert len(results['endpoints']) == 3
    
    @pytest.mark.asyncio
    async def test_test_graphql_api(self, api_module, target_config):
        """Test comprehensive GraphQL API testing"""
        # Mock GraphQL detection
        mock_detect_response = Response(
            status_code=200,
            headers={},
            body=b'{"data": {"__typename": "Query"}}',
            text='{"data": {"__typename": "Query"}}',
            elapsed_time=0.1,
            request=Mock()
        )
        
        # Mock introspection response
        introspection_result = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": [
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "fields": [{"name": "user"}]
                        }
                    ]
                }
            }
        }
        
        mock_introspection_response = Response(
            status_code=200,
            headers={},
            body=json.dumps(introspection_result).encode(),
            text=json.dumps(introspection_result),
            elapsed_time=0.1,
            request=Mock()
        )
        
        with patch.object(api_module.request_handler, 'send_request', new_callable=AsyncMock) as mock_send:
            mock_send.side_effect = [mock_detect_response, mock_introspection_response] + [mock_detect_response] * 10
            
            results = await api_module.test_graphql_api(target_config)
            
            assert results['graphql_endpoint'] is not None
            assert results['schema'] is not None


# Data Model Tests

class TestDataModels:
    """Tests for data models"""
    
    def test_api_endpoint_creation(self):
        """Test APIEndpoint creation"""
        endpoint = APIEndpoint(
            path="/users",
            method="GET",
            description="Get all users",
            requires_auth=True
        )
        
        assert endpoint.path == "/users"
        assert endpoint.method == "GET"
        assert endpoint.requires_auth is True
    
    def test_openapi_spec_creation(self):
        """Test OpenAPISpec creation"""
        spec = OpenAPISpec(
            url="https://api.example.com/openapi.json",
            version="3.0.0",
            title="Test API"
        )
        
        assert spec.url == "https://api.example.com/openapi.json"
        assert spec.version == "3.0.0"
        assert spec.title == "Test API"
    
    def test_graphql_schema_creation(self):
        """Test GraphQLSchema creation"""
        schema = GraphQLSchema(
            url="https://api.example.com/graphql"
        )
        
        assert schema.url == "https://api.example.com/graphql"
        assert len(schema.types) == 0
        assert len(schema.queries) == 0
    
    def test_api_vulnerability_creation(self):
        """Test APIVulnerability creation"""
        vuln = APIVulnerability(
            vulnerability_type="authentication_bypass",
            severity="high",
            endpoint="https://api.example.com/users",
            method="GET",
            description="Endpoint accessible without authentication"
        )
        
        assert vuln.vulnerability_type == "authentication_bypass"
        assert vuln.severity == "high"
        assert vuln.endpoint == "https://api.example.com/users"
