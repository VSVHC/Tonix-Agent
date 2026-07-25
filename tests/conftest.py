"""
conftest.py
───────────
Shared fixtures for all unit tests.

Key fixtures:
  scope        — ScopeEnforcer for http://testsite.local
  scan_id      — fixed UUID string
  mock_client  — httpx.AsyncClient backed by respx router (no real network)
"""

import pytest
import httpx
import respx

SCAN_ID    = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
TARGET_URL = "http://testsite.local"


@pytest.fixture
def scan_id() -> str:
    return SCAN_ID


@pytest.fixture
def scope():
    from backend.scope import ScopeEnforcer
    return ScopeEnforcer(TARGET_URL)


@pytest.fixture
def mock_client() -> httpx.AsyncClient:
    """Return a real AsyncClient that uses respx for routing — call respx.mock() in each test."""
    return httpx.AsyncClient(base_url=TARGET_URL)
