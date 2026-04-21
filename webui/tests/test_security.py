"""Tests for core/security.py — user cache, login rate limiting, CSP nonce, MFA removal."""
import time
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _fresh_module():
    """Import a fresh copy of core.security with empty module-level state."""
    import core.security as mod
    mod._USER_CACHE.clear()
    mod._LOGIN_ATTEMPTS.clear()
    return mod


# ---------------------------------------------------------------------------
# User existence cache
# ---------------------------------------------------------------------------
class TestCheckUserActive:
    def test_active_user_returns_true(self):
        sec = _fresh_module()
        with patch("core.security.local_auth") as la:
            la.get_user.return_value = {"email": "a@b.com", "is_active": True}
            assert sec.check_user_active("a@b.com") is True

    def test_inactive_user_returns_false(self):
        sec = _fresh_module()
        with patch("core.security.local_auth") as la:
            la.get_user.return_value = {"email": "a@b.com", "is_active": False}
            assert sec.check_user_active("a@b.com") is False

    def test_missing_user_returns_false(self):
        sec = _fresh_module()
        with patch("core.security.local_auth") as la:
            la.get_user.return_value = None
            assert sec.check_user_active("missing@b.com") is False

    def test_result_is_cached(self):
        sec = _fresh_module()
        with patch("core.security.local_auth") as la:
            la.get_user.return_value = {"email": "a@b.com", "is_active": True}
            sec.check_user_active("a@b.com")
            sec.check_user_active("a@b.com")
            assert la.get_user.call_count == 1

    def test_cache_expires(self):
        sec = _fresh_module()
        with patch("core.security.local_auth") as la:
            la.get_user.return_value = {"email": "a@b.com", "is_active": True}
            sec.check_user_active("a@b.com")
            # Manually expire the cache entry
            sec._USER_CACHE["a@b.com"] = (True, time.monotonic() - 1)
            sec.check_user_active("a@b.com")
            assert la.get_user.call_count == 2

    def test_invalidate_clears_cache(self):
        sec = _fresh_module()
        with patch("core.security.local_auth") as la:
            la.get_user.return_value = {"email": "a@b.com", "is_active": True}
            sec.check_user_active("a@b.com")
            sec.invalidate_user_cache("a@b.com")
            assert "a@b.com" not in sec._USER_CACHE

    def test_invalidate_nonexistent_is_noop(self):
        sec = _fresh_module()
        sec.invalidate_user_cache("ghost@b.com")  # should not raise


# ---------------------------------------------------------------------------
# Login rate limiting
# ---------------------------------------------------------------------------
class TestLoginRateLimiting:
    def test_fresh_ip_is_allowed(self):
        sec = _fresh_module()
        assert sec.login_allowed("1.2.3.4") is True

    def test_allowed_after_some_failures(self):
        sec = _fresh_module()
        for _ in range(5):
            sec.record_login_failure("1.2.3.4")
        assert sec.login_allowed("1.2.3.4") is True

    def test_blocked_after_max_failures(self):
        sec = _fresh_module()
        for _ in range(10):
            sec.record_login_failure("1.2.3.4")
        assert sec.login_allowed("1.2.3.4") is False

    def test_clear_resets_ip(self):
        sec = _fresh_module()
        for _ in range(10):
            sec.record_login_failure("1.2.3.4")
        sec.clear_login_failures("1.2.3.4")
        assert sec.login_allowed("1.2.3.4") is True

    def test_expired_attempts_not_counted(self):
        sec = _fresh_module()
        old_ts = time.monotonic() - sec._LOGIN_WINDOW - 1
        sec._LOGIN_ATTEMPTS["1.2.3.4"] = [old_ts] * 10
        assert sec.login_allowed("1.2.3.4") is True

    def test_ips_are_independent(self):
        sec = _fresh_module()
        for _ in range(10):
            sec.record_login_failure("5.5.5.5")
        assert sec.login_allowed("6.6.6.6") is True


# ---------------------------------------------------------------------------
# CSP nonce middleware
# ---------------------------------------------------------------------------
class TestCSPNonce:
    def test_csp_header_contains_nonce(self, open_client):
        r = open_client.get("/healthz")
        csp = r.headers.get("content-security-policy", "")
        assert "nonce-" in csp

    def test_nonce_differs_per_request(self, open_client):
        r1 = open_client.get("/healthz")
        r2 = open_client.get("/healthz")
        nonce1 = [p for p in r1.headers["content-security-policy"].split() if "nonce-" in p]
        nonce2 = [p for p in r2.headers["content-security-policy"].split() if "nonce-" in p]
        assert nonce1 and nonce2
        assert nonce1[0] != nonce2[0]

    def test_script_src_has_no_unsafe_inline(self, open_client):
        r = open_client.get("/healthz")
        csp = r.headers.get("content-security-policy", "")
        parts = [d.strip() for d in csp.split(";") if d.strip()]
        directives = {d.split()[0]: d for d in parts}
        script_src = directives.get("script-src", "")
        assert "'unsafe-inline'" not in script_src

    def test_security_headers_present(self, open_client):
        r = open_client.get("/healthz")
        assert r.headers.get("x-content-type-options") == "nosniff"
        assert r.headers.get("x-frame-options") == "DENY"
        assert r.headers.get("referrer-policy") == "strict-origin-when-cross-origin"


# ---------------------------------------------------------------------------
# MFA routes removed
# ---------------------------------------------------------------------------
class TestMFARemoved:
    def test_mfa_verify_returns_404(self, open_client):
        r = open_client.get("/mfa-verify", follow_redirects=False)
        assert r.status_code == 404

    def test_mfa_api_setup_returns_404(self, open_client):
        r = open_client.get("/api/mfa/setup", follow_redirects=False)
        assert r.status_code == 404

    def test_mfa_api_verify_returns_404(self, open_client):
        r = open_client.post("/api/mfa/verify", follow_redirects=False)
        assert r.status_code == 404
