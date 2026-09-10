"""Unit tests for Streamlit UI API Client and frontend integration."""

import pytest
from app.streamlit_client import FIMApiClient, FIMAPIError


def test_api_client_initialization():
    client = FIMApiClient(base_url="http://127.0.0.1:8000")
    assert client.base_url == "http://127.0.0.1:8000"
    assert client.timeout == 10.0


def test_api_client_offline_graceful():
    # Use a dummy non-existent port
    client = FIMApiClient(base_url="http://127.0.0.1:59999", timeout=1.0)
    is_online, msg = client.get_health()
    assert is_online is False
    assert msg is not None


def test_api_client_url_construction():
    client = FIMApiClient(base_url="http://localhost:8000/")
    assert client._url("/health") == "http://localhost:8000/health"
    assert client._url("config") == "http://localhost:8000/config"
    assert client._url("/changes/scan-123") == "http://localhost:8000/changes/scan-123"
