"""Pytest configuration and fixtures"""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client() -> TestClient:
    """Create a test client for the FastAPI application"""
    return TestClient(app)


@pytest.fixture
def sample_target() -> dict:
    """Sample target configuration for testing"""
    return {
        "url": "https://example.com",
        "custom_headers": {"User-Agent": "VulnChain/0.1.0"},
        "proxy": None,
        "waf_bypass_profile": None,
    }
