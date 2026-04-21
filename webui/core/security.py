"""
Per-request security helpers: login rate limiting and user existence cache.
Lives in core/ so routers can import it without depending on main.py.
"""

import time as _time
import local_auth

# ---------------------------------------------------------------------------
# User existence cache — avoids a DB hit on every authenticated request.
# TTL = 30s per entry.
# ---------------------------------------------------------------------------

_USER_CACHE: dict[str, tuple[bool, float]] = {}
_USER_CACHE_TTL = 30


def check_user_active(email: str) -> bool:
    """Return True if the user exists and is active. Result cached for 30s."""
    now = _time.monotonic()
    entry = _USER_CACHE.get(email)
    if entry and entry[1] > now:
        return entry[0]
    u = local_auth.get_user(email)
    active = bool(u and u.get("is_active", False))
    _USER_CACHE[email] = (active, now + _USER_CACHE_TTL)
    return active


def invalidate_user_cache(email: str) -> None:
    """Evict a user from the cache — call after deletion or deactivation."""
    _USER_CACHE.pop(email, None)


# ---------------------------------------------------------------------------
# Login rate limiting — 10 failures per IP within 15 minutes.
# ---------------------------------------------------------------------------

_LOGIN_ATTEMPTS: dict[str, list[float]] = {}
_LOGIN_MAX_ATTEMPTS = 10
_LOGIN_WINDOW = 900   # 15 minutes


def login_allowed(ip: str) -> bool:
    now = _time.monotonic()
    attempts = [t for t in _LOGIN_ATTEMPTS.get(ip, []) if now - t < _LOGIN_WINDOW]
    _LOGIN_ATTEMPTS[ip] = attempts
    return len(attempts) < _LOGIN_MAX_ATTEMPTS


def record_login_failure(ip: str) -> None:
    _LOGIN_ATTEMPTS.setdefault(ip, []).append(_time.monotonic())


def clear_login_failures(ip: str) -> None:
    _LOGIN_ATTEMPTS.pop(ip, None)
