"""
Unit tests for ScopeEnforcer.

Tests the scope enforcement logic independently — no HTTP needed.
"""

import pytest
from backend.config import settings
from backend.scope import ScopeEnforcer, ScopeViolationError


def test_same_host_in_scope():
    s = ScopeEnforcer("http://example.com")
    assert s.is_in_scope("http://example.com/path/to/page") is True


def test_subpath_in_scope():
    s = ScopeEnforcer("http://example.com")
    assert s.is_in_scope("http://example.com/admin/login") is True


def test_different_host_out_of_scope():
    s = ScopeEnforcer("http://example.com")
    assert s.is_in_scope("http://evil.com/steal") is False


def test_subdomain_out_of_scope(monkeypatch):
    # With subdomain expansion disabled, an arbitrary subdomain is out of scope.
    monkeypatch.setattr(settings, "SCOPE_ALLOW_SUBDOMAINS", False, raising=False)
    monkeypatch.setattr(settings, "SCOPE_ALLOW_API_SUBDOMAIN", False, raising=False)
    s = ScopeEnforcer("http://example.com")
    assert s.is_in_scope("http://sub.example.com/path") is False


def test_subdomain_in_scope_when_enabled(monkeypatch):
    # When subdomain expansion is enabled, subdomains of the registered domain
    # are treated as in scope (where SPA asset/JS bundles typically live).
    monkeypatch.setattr(settings, "SCOPE_ALLOW_SUBDOMAINS", True, raising=False)
    s = ScopeEnforcer("http://example.com")
    assert s.is_in_scope("http://static.example.com/app.js") is True


def test_www_variant_in_scope():
    s = ScopeEnforcer("http://example.com")
    assert s.is_in_scope("http://www.example.com/path") is True


def test_www_to_bare_in_scope():
    s = ScopeEnforcer("http://www.example.com")
    assert s.is_in_scope("http://example.com/path") is True


def test_enforce_raises_on_out_of_scope():
    s = ScopeEnforcer("http://example.com")
    with pytest.raises(ScopeViolationError):
        s.enforce("http://attacker.com/payload")


def test_enforce_returns_url_on_in_scope():
    s = ScopeEnforcer("http://example.com")
    url = s.enforce("http://example.com/api/data")
    assert url == "http://example.com/api/data"


def test_build_url_prepends_base():
    s = ScopeEnforcer("http://example.com")
    assert s.build_url("/login") == "http://example.com/login"


def test_build_url_without_leading_slash():
    s = ScopeEnforcer("http://example.com")
    assert s.build_url("login") == "http://example.com/login"


def test_build_url_with_port():
    s = ScopeEnforcer("http://example.com:8080")
    assert s.build_url("/api") == "http://example.com:8080/api"


def test_violations_recorded():
    s = ScopeEnforcer("http://example.com")
    s.is_in_scope("http://evil.com/a")
    s.is_in_scope("http://evil.com/b")
    assert len(s.violations) == 2


def test_base_url_no_path():
    s = ScopeEnforcer("http://example.com/some/path")
    assert s.base_url == "http://example.com"


def test_https_scheme_preserved():
    s = ScopeEnforcer("https://secure.example.com")
    assert s.target_scheme == "https"
    assert s.build_url("/page").startswith("https://")
