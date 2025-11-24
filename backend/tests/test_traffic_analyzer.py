"""Tests for Traffic Analyzer Module

Tests behavioral modeling, anomaly detection, and attack optimization.
"""

import pytest
from datetime import datetime, timedelta
from app.core.traffic_analyzer import (
    TrafficAnalyzer,
    BehavioralModel,
    TrafficAnomaly,
    AttackOptimization,
    EndpointType
)
from app.core.http_models import Request, Response


@pytest.fixture
def analyzer():
    """Create a TrafficAnalyzer instance"""
    return TrafficAnalyzer(learning_window=50)


@pytest.fixture
def sample_traffic():
    """Generate sample traffic data"""
    traffic = []
    
    # Normal traffic pattern
    endpoints = [
        "/",
        "/api/users",
        "/api/products",
        "/login",
        "/api/cart"
    ]
    
    for i in range(100):
        endpoint = endpoints[i % len(endpoints)]
        
        request = Request(
            method="GET",
            url=f"https://example.com{endpoint}",
            headers={"User-Agent": "TestClient"},
            data=None,
            cookies={}
        )
        
        response = Response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=b'{"status": "ok"}',
            text='{"status": "ok"}',
            elapsed_time=0.1 + (i % 3) * 0.05,
            request=request,
            history=[]
        )
        
        traffic.append((request, response))
    
    return traffic


@pytest.fixture
def auth_traffic():
    """Generate traffic with authentication flow"""
    traffic = []
    
    # Authentication flow: login -> get token -> access resource
    auth_sequence = [
        ("/login", 200, 0.15),
        ("/api/auth/token", 200, 0.12),
        ("/api/user/profile", 200, 0.10)
    ]
    
    # Repeat the sequence multiple times
    for _ in range(10):
        for endpoint, status, timing in auth_sequence:
            request = Request(
                method="POST" if "login" in endpoint or "token" in endpoint else "GET",
                url=f"https://example.com{endpoint}",
                headers={"User-Agent": "TestClient"},
                data=None,
                cookies={}
            )
            
            response = Response(
                status_code=status,
                headers={"Content-Type": "application/json"},
                body=b'{"status": "ok"}',
                text='{"status": "ok"}',
                elapsed_time=timing,
                request=request,
                history=[]
            )
            
            traffic.append((request, response))
    
    return traffic


class TestTrafficObservation:
    """Test traffic observation and recording"""
    
    def test_observe_traffic(self, analyzer):
        """Test observing a single request-response pair"""
        request = Request(
            method="GET",
            url="https://example.com/api/test",
            headers={},
            data=None,
            cookies={}
        )
        
        response = Response(
            status_code=200,
            headers={},
            body=b"test",
            text="test",
            elapsed_time=0.1,
            request=request,
            history=[]
        )
        
        analyzer.observe_traffic(request, response)
        
        assert len(analyzer.traffic_history) == 1
        assert analyzer.traffic_history[0] == (request, response)
    
    def test_observe_multiple_traffic(self, analyzer, sample_traffic):
        """Test observing multiple request-response pairs"""
        for req, resp in sample_traffic:
            analyzer.observe_traffic(req, resp)
        
        assert len(analyzer.traffic_history) == len(sample_traffic)
    
    def test_endpoint_stats_updated(self, analyzer):
        """Test that endpoint statistics are updated"""
        request = Request(
            method="GET",
            url="https://example.com/api/test",
            headers={},
            data=None,
            cookies={}
        )
        
        response = Response(
            status_code=200,
            headers={},
            body=b"test",
            text="test",
            elapsed_time=0.15,
            request=request,
            history=[]
        )
        
        analyzer.observe_traffic(request, response)
        
        stats = analyzer.endpoint_stats["/api/test"]
        assert stats["count"] == 1
        assert len(stats["timings"]) == 1
        assert stats["timings"][0] == 0.15
        assert stats["status_codes"][200] == 1
        assert "GET" in stats["methods"]


class TestBehavioralModeling:
    """Test behavioral model building - Requirement 49.1"""
    
    def test_build_model_requires_traffic(self, analyzer):
        """Test that building model requires traffic history"""
        with pytest.raises(ValueError, match="No traffic history"):
            analyzer.build_behavioral_model()
    
    def test_build_basic_model(self, analyzer, sample_traffic):
        """Test building a basic behavioral model"""
        for req, resp in sample_traffic:
            analyzer.observe_traffic(req, resp)
        
        model = analyzer.build_behavioral_model()
        
        assert isinstance(model, BehavioralModel)
        assert model.model_id is not None
        assert len(model.known_endpoints) > 0
        assert model.total_requests == len(sample_traffic)
    
    def test_model_identifies_endpoints(self, analyzer, sample_traffic):
        """Test that model identifies all unique endpoints"""
        for req, resp in sample_traffic:
            analyzer.observe_traffic(req, resp)
        
        model = analyzer.build_behavioral_model()
        
        # Should identify 5 unique endpoints
        assert len(model.known_endpoints) == 5
        assert "/" in model.known_endpoints
        assert "/api/users" in model.known_endpoints
        assert "/login" in model.known_endpoints
    
    def test_model_classifies_endpoints(self, analyzer, sample_traffic):
        """Test that model classifies endpoint types"""
        for req, resp in sample_traffic:
            analyzer.observe_traffic(req, resp)
        
        model = analyzer.build_behavioral_model()
        
        # Check endpoint classifications
        assert model.endpoint_types["/login"] == EndpointType.AUTHENTICATION
        assert model.endpoint_types["/api/users"] == EndpointType.API
    
    def test_model_calculates_timings(self, analyzer, sample_traffic):
        """Test that model calculates typical response times"""
        for req, resp in sample_traffic:
            analyzer.observe_traffic(req, resp)
        
        model = analyzer.build_behavioral_model()
        
        # Should have timing data for endpoints
        assert len(model.typical_response_times) > 0
        
        # Check that timings are tuples of (mean, stddev)
        for endpoint, (mean, stddev) in model.typical_response_times.items():
            assert isinstance(mean, float)
            assert isinstance(stddev, float)
            assert mean > 0
            assert stddev >= 0
    
    def test_model_identifies_auth_flows(self, analyzer, auth_traffic):
        """Test that model identifies authentication flows"""
        for req, resp in auth_traffic:
            analyzer.observe_traffic(req, resp)
        
        model = analyzer.build_behavioral_model()
        
        # Should identify the authentication flow
        assert len(model.auth_flows) > 0
        
        # Check that login endpoint is in auth flows
        auth_flow_endpoints = [ep for flow in model.auth_flows for ep in flow]
        assert any("/login" in ep for ep in auth_flow_endpoints)


class TestHiddenEndpointDetection:
    """Test hidden endpoint detection - Requirement 49.2"""
    
    def test_identify_hidden_endpoints(self, analyzer, sample_traffic):
        """Test identifying hidden endpoints"""
        # Add normal traffic
        for req, resp in sample_traffic[:50]:
            analyzer.observe_traffic(req, resp)
        
        # Add a hidden endpoint accessed only once
        hidden_request = Request(
            method="GET",
            url="https://example.com/admin/debug",
            headers={},
            data=None,
            cookies={}
        )
        
        hidden_response = Response(
            status_code=200,
            headers={},
            body=b"debug info",
            text="debug info",
            elapsed_time=0.1,
            request=hidden_request,
            history=[]
        )
        
        analyzer.observe_traffic(hidden_request, hidden_response)
        
        # Build model
        analyzer.build_behavioral_model()
        
        # Identify hidden endpoints
        hidden = analyzer.identify_hidden_endpoints()
        
        assert "/admin/debug" in hidden
    
    def test_identify_debug_endpoints(self, analyzer):
        """Test identifying debug/admin endpoints"""
        # Add request to debug endpoint
        request = Request(
            method="GET",
            url="https://example.com/debug/info",
            headers={},
            data=None,
            cookies={}
        )
        
        response = Response(
            status_code=200,
            headers={},
            body=b"",
            text="",
            elapsed_time=0.1,
            request=request,
            history=[]
        )
        
        analyzer.observe_traffic(request, response)
        analyzer.build_behavioral_model()
        
        hidden = analyzer.identify_hidden_endpoints()
        assert "/debug/info" in hidden


class TestRateLimitDetection:
    """Test rate limit detection - Requirement 49.2"""
    
    def test_detect_rate_limiting(self, analyzer):
        """Test detecting rate limiting from 429 responses"""
        # Add normal requests
        for i in range(10):
            request = Request(
                method="GET",
                url="https://example.com/api/data",
                headers={},
                data=None,
                cookies={}
            )
            
            # Last few requests hit rate limit
            if i >= 7:
                response = Response(
                    status_code=429,
                    headers={
                        "Retry-After": "60",
                        "X-RateLimit-Limit": "10",
                        "X-RateLimit-Remaining": "0"
                    },
                    body=b"Rate limit exceeded",
                    text="Rate limit exceeded",
                    elapsed_time=0.05,
                    request=request,
                    history=[]
                )
            else:
                response = Response(
                    status_code=200,
                    headers={},
                    body=b"data",
                    text="data",
                    elapsed_time=0.1,
                    request=request,
                    history=[]
                )
            
            analyzer.observe_traffic(request, response)
        
        rate_limits = analyzer.detect_rate_limiting()
        
        assert "/api/data" in rate_limits
        assert rate_limits["/api/data"]["detected"] is True
        assert rate_limits["/api/data"]["retry_after"] == "60"
        assert rate_limits["/api/data"]["limit_info"]["limit"] == "10"
    
    def test_identify_anti_automation(self, analyzer):
        """Test identifying anti-automation measures"""
        # Add request with CAPTCHA
        request = Request(
            method="GET",
            url="https://example.com/login",
            headers={},
            data=None,
            cookies={}
        )
        
        response = Response(
            status_code=200,
            headers={},
            body=b"<html><div class='g-recaptcha'></div></html>",
            text="<html><div class='g-recaptcha'></div></html>",
            elapsed_time=0.1,
            request=request,
            history=[]
        )
        
        analyzer.observe_traffic(request, response)
        
        indicators = analyzer.identify_anti_automation()
        assert "CAPTCHA detected" in indicators


class TestAnomalyDetection:
    """Test anomaly detection - Requirement 49.3"""
    
    def test_detect_anomalies_requires_model(self, analyzer, sample_traffic):
        """Test that anomaly detection requires a behavioral model"""
        for req, resp in sample_traffic:
            analyzer.observe_traffic(req, resp)
        
        with pytest.raises(ValueError, match="Behavioral model must be built"):
            analyzer.detect_anomalies()
    
    def test_detect_unknown_endpoint(self, analyzer, sample_traffic):
        """Test detecting requests to unknown endpoints"""
        # Build model with normal traffic
        for req, resp in sample_traffic:
            analyzer.observe_traffic(req, resp)
        
        analyzer.build_behavioral_model()
        
        # Add request to unknown endpoint
        unknown_request = Request(
            method="GET",
            url="https://example.com/unknown/endpoint",
            headers={},
            data=None,
            cookies={}
        )
        
        unknown_response = Response(
            status_code=200,
            headers={},
            body=b"",
            text="",
            elapsed_time=0.1,
            request=unknown_request,
            history=[]
        )
        
        analyzer.observe_traffic(unknown_request, unknown_response)
        
        # Detect anomalies
        anomalies = analyzer.detect_anomalies(recent_window=1)
        
        assert len(anomalies) > 0
        assert any(a.anomaly_type == "unknown_endpoint" for a in anomalies)
    
    def test_detect_timing_anomaly(self, analyzer, sample_traffic):
        """Test detecting timing anomalies"""
        # Build model with normal traffic
        for req, resp in sample_traffic:
            analyzer.observe_traffic(req, resp)
        
        analyzer.build_behavioral_model()
        
        # Add request with unusual timing
        slow_request = Request(
            method="GET",
            url="https://example.com/api/users",
            headers={},
            data=None,
            cookies={}
        )
        
        slow_response = Response(
            status_code=200,
            headers={},
            body=b"",
            text="",
            elapsed_time=5.0,  # Much slower than normal
            request=slow_request,
            history=[]
        )
        
        analyzer.observe_traffic(slow_request, slow_response)
        
        # Detect anomalies
        anomalies = analyzer.detect_anomalies(recent_window=1)
        
        assert len(anomalies) > 0
        assert any(a.anomaly_type == "timing_anomaly" for a in anomalies)
    
    def test_detect_status_code_anomaly(self, analyzer, sample_traffic):
        """Test detecting unusual status codes"""
        # Build model with normal traffic (all 200s)
        for req, resp in sample_traffic:
            analyzer.observe_traffic(req, resp)
        
        analyzer.build_behavioral_model()
        
        # Add request with unusual status code
        error_request = Request(
            method="GET",
            url="https://example.com/api/users",
            headers={},
            data=None,
            cookies={}
        )
        
        error_response = Response(
            status_code=500,  # Unusual for this endpoint
            headers={},
            body=b"",
            text="",
            elapsed_time=0.1,
            request=error_request,
            history=[]
        )
        
        analyzer.observe_traffic(error_request, error_response)
        
        # Detect anomalies
        anomalies = analyzer.detect_anomalies(recent_window=1)
        
        assert len(anomalies) > 0
        assert any(a.anomaly_type == "status_code_anomaly" for a in anomalies)


class TestAttackOptimization:
    """Test attack optimization - Requirements 49.4, 49.5"""
    
    def test_optimize_requires_model(self, analyzer, sample_traffic):
        """Test that optimization requires a behavioral model"""
        for req, resp in sample_traffic:
            analyzer.observe_traffic(req, resp)
        
        with pytest.raises(ValueError, match="Behavioral model must be built"):
            analyzer.optimize_attack_strategy()
    
    def test_optimize_attack_strategy(self, analyzer, sample_traffic):
        """Test optimizing attack strategy"""
        for req, resp in sample_traffic:
            analyzer.observe_traffic(req, resp)
        
        analyzer.build_behavioral_model()
        
        optimization = analyzer.optimize_attack_strategy()
        
        assert isinstance(optimization, AttackOptimization)
        assert "recommended_delay" in optimization.optimal_timing
        assert "burst_size" in optimization.optimal_timing
        assert isinstance(optimization.request_ordering, list)
        assert isinstance(optimization.bypass_opportunities, list)
        assert 0.0 <= optimization.confidence <= 1.0
    
    def test_optimal_timing_with_rate_limits(self, analyzer):
        """Test that optimal timing accounts for rate limits"""
        # Add traffic with rate limiting
        for i in range(20):
            request = Request(
                method="GET",
                url="https://example.com/api/data",
                headers={},
                data=None,
                cookies={}
            )
            
            if i >= 15:
                response = Response(
                    status_code=429,
                    headers={"Retry-After": "60"},
            body=b"",
            text="",
                    elapsed_time=0.05,
                    request=request,
                    history=[]
                )
            else:
                response = Response(
                    status_code=200,
                    headers={},
            body=b"",
            text="",
                    elapsed_time=0.1,
                    request=request,
                    history=[]
                )
            
            analyzer.observe_traffic(request, response)
        
        analyzer.build_behavioral_model()
        optimization = analyzer.optimize_attack_strategy()
        
        # Should recommend slower timing due to rate limiting
        assert optimization.optimal_timing["recommended_delay"] >= 1.0
    
    def test_identify_bypass_opportunities(self, analyzer, auth_traffic):
        """Test identifying bypass opportunities"""
        for req, resp in auth_traffic:
            analyzer.observe_traffic(req, resp)
        
        analyzer.build_behavioral_model()
        optimization = analyzer.optimize_attack_strategy()
        
        # Should identify bypass opportunities in auth flow
        assert len(optimization.bypass_opportunities) > 0
    
    def test_map_authentication_flows(self, analyzer, auth_traffic):
        """Test mapping authentication flows"""
        for req, resp in auth_traffic:
            analyzer.observe_traffic(req, resp)
        
        auth_flows = analyzer.map_authentication_flows()
        
        assert len(auth_flows) > 0
        # Should contain login endpoint
        assert any("/login" in flow for flow in auth_flows for endpoint in flow if "/login" in endpoint)


class TestUtilityMethods:
    """Test utility methods"""
    
    def test_normalize_endpoint(self, analyzer):
        """Test endpoint normalization"""
        # Test ID normalization
        assert analyzer._normalize_endpoint("https://example.com/users/123") == "/users/{id}"
        assert analyzer._normalize_endpoint("https://example.com/posts/456/comments") == "/posts/{id}/comments"
        
        # Test UUID normalization
        uuid_url = "https://example.com/items/550e8400-e29b-41d4-a716-446655440000"
        assert analyzer._normalize_endpoint(uuid_url) == "/items/{uuid}"
        
        # Test trailing slash removal
        assert analyzer._normalize_endpoint("https://example.com/api/users/") == "/api/users"
    
    def test_classify_endpoint(self, analyzer):
        """Test endpoint classification"""
        # Authentication endpoint
        auth_req = Request(method="POST", url="https://example.com/login", headers={}, data=None, cookies={})
        auth_resp = Response(status_code=200, headers={}, body=b"", text="", elapsed_time=0.1, request=auth_req, history=[])
        assert analyzer._classify_endpoint(auth_req, auth_resp) == EndpointType.AUTHENTICATION
        
        # API endpoint
        api_req = Request(method="GET", url="https://example.com/api/users", headers={}, data=None, cookies={})
        api_resp = Response(status_code=200, headers={}, body=b"", text="", elapsed_time=0.1, request=api_req, history=[])
        assert analyzer._classify_endpoint(api_req, api_resp) == EndpointType.API
        
        # Static resource
        static_req = Request(method="GET", url="https://example.com/static/app.js", headers={}, data=None, cookies={})
        static_resp = Response(status_code=200, headers={}, body=b"", text="", elapsed_time=0.1, request=static_req, history=[])
        assert analyzer._classify_endpoint(static_req, static_resp) == EndpointType.STATIC
        
        # Hidden endpoint
        hidden_req = Request(method="GET", url="https://example.com/admin/debug", headers={}, data=None, cookies={})
        hidden_resp = Response(status_code=200, headers={}, body=b"", text="", elapsed_time=0.1, request=hidden_req, history=[])
        assert analyzer._classify_endpoint(hidden_req, hidden_resp) == EndpointType.HIDDEN
    
    def test_get_traffic_summary(self, analyzer, sample_traffic):
        """Test getting traffic summary"""
        for req, resp in sample_traffic[:20]:
            analyzer.observe_traffic(req, resp)
        
        summary = analyzer.get_traffic_summary()
        
        assert summary["total_requests"] == 20
        assert summary["unique_endpoints"] > 0
        assert "endpoint_stats" in summary
    
    def test_clear_history(self, analyzer, sample_traffic):
        """Test clearing traffic history"""
        for req, resp in sample_traffic[:10]:
            analyzer.observe_traffic(req, resp)
        
        assert len(analyzer.traffic_history) == 10
        
        analyzer.clear_history()
        
        assert len(analyzer.traffic_history) == 0
        assert analyzer.behavioral_model is None
