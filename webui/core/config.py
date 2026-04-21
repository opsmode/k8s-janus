"""
Environment-variable configuration constants for K8s-Janus WebUI.
"""

import os
import logging
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from authlib.integrations.starlette_client import OAuth

# ---------------------------------------------------------------------------
# TTL / rate limit config
# ---------------------------------------------------------------------------
DEFAULT_TTL_SECONDS = int(os.environ.get("DEFAULT_TTL_SECONDS", "3600"))
MAX_TTL_SECONDS     = int(os.environ.get("MAX_TTL_SECONDS", "28800"))
_raw_ttl_opts = os.environ.get("APPROVAL_TTL_OPTIONS", "3600,7200,14400,28800")
APPROVAL_TTL_OPTIONS = [int(x) for x in _raw_ttl_opts.split(",") if x.strip().isdigit()]

_raw_admins  = os.environ.get("ADMIN_EMAILS", "")
ADMIN_EMAILS = set(
    e.strip().lower()
    for sep in (",", ";")
    for e in _raw_admins.replace(";", ",").split(",")
    if e.strip()
)

_tz_name = os.environ.get("DISPLAY_TIMEZONE", "UTC")
try:
    DISPLAY_TZ = ZoneInfo(_tz_name)
except ZoneInfoNotFoundError:
    _logger_pre = logging.getLogger("k8s-janus-webui")
    _logger_pre.warning(f"⚠️  Unknown DISPLAY_TIMEZONE '{_tz_name}', falling back to UTC")
    DISPLAY_TZ = ZoneInfo("UTC")

# AUTH_ENABLED: X-Forwarded-Email mode (oauth2-proxy / ingress SSO).
AUTH_ENABLED = os.environ.get("AUTH_ENABLED", "true").lower() not in ("false", "0", "no")
APP_VERSION  = os.environ.get("APP_VERSION", "dev")
BUILD_DATE   = os.environ.get("BUILD_DATE", "unknown")

# Rate limiting: max requests a user may submit within a rolling window
MAX_REQUESTS_PER_WINDOW = int(os.environ.get("MAX_REQUESTS_PER_WINDOW", "10"))
RATE_LIMIT_WINDOW_SECS  = int(os.environ.get("RATE_LIMIT_WINDOW_SECS",  "3600"))  # 1 hour
# Cap: max simultaneous Pending+Approved+Active requests per user (across all clusters)
MAX_ACTIVE_REQUESTS     = int(os.environ.get("MAX_ACTIVE_REQUESTS", "5"))

# ---------------------------------------------------------------------------
# Native OIDC configuration
# ---------------------------------------------------------------------------
OIDC_ENABLED         = os.environ.get("OIDC_ENABLED", "false").lower() == "true"
# LOCAL_AUTH_ENABLED: built-in username/password auth — active when neither OIDC nor
# X-Forwarded-Email proxy is configured. An admin@local account is auto-created on
# first startup with a random password printed to the application log.
LOCAL_AUTH_ENABLED   = not OIDC_ENABLED and not AUTH_ENABLED
OIDC_PROVIDER       = os.environ.get("OIDC_PROVIDER", "").lower()
OIDC_CLIENT_ID      = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET  = os.environ.get("OIDC_CLIENT_SECRET", "")
OIDC_SESSION_SECRET = os.environ.get("OIDC_SESSION_SECRET", "dev-secret-change-me")
OIDC_TENANT_ID      = os.environ.get("OIDC_TENANT_ID", "common")
OIDC_SCOPES         = os.environ.get("OIDC_SCOPES", "openid email profile")
OIDC_ALLOWED_DOMAINS: set[str] = {
    d.strip().lower()
    for d in os.environ.get("OIDC_ALLOWED_DOMAINS", "").split(",")
    if d.strip()
}

_PROVIDER_ISSUER: dict[str, str] = {
    "google": "https://accounts.google.com",
    "entra":  f"https://login.microsoftonline.com/{OIDC_TENANT_ID}/v2.0",
    "gitlab": "https://gitlab.com",
    # okta / custom: must supply OIDC_ISSUER_URL explicitly
}
OIDC_ISSUER_URL = (
    os.environ.get("OIDC_ISSUER_URL", "")
    or _PROVIDER_ISSUER.get(OIDC_PROVIDER, "")
)

_PROVIDER_DISPLAY: dict[str, str] = {
    "google": "Google",
    "github": "GitHub",
    "entra":  "Microsoft",
    "okta":   "Okta",
    "gitlab": "GitLab",
}

# ---------------------------------------------------------------------------
# OAuth client (authlib) — registered at module load when OIDC_ENABLED
# ---------------------------------------------------------------------------
_oauth = OAuth()
if OIDC_ENABLED:
    if OIDC_PROVIDER == "github":
        _oauth.register(
            "github",
            client_id=OIDC_CLIENT_ID,
            client_secret=OIDC_CLIENT_SECRET,
            authorize_url="https://github.com/login/oauth/authorize",
            access_token_url="https://github.com/login/oauth/access_token",
            userinfo_endpoint="https://api.github.com/user",
            client_kwargs={"scope": "read:user user:email"},
        )
    else:
        if not OIDC_ISSUER_URL:
            raise RuntimeError(
                f"OIDC_ISSUER_URL is required for provider '{OIDC_PROVIDER}' "
                "— set oidc.issuerUrl in values.yaml"
            )
        _oauth.register(
            "oidc",
            client_id=OIDC_CLIENT_ID,
            client_secret=OIDC_CLIENT_SECRET,
            server_metadata_url=f"{OIDC_ISSUER_URL}/.well-known/openid-configuration",
            client_kwargs={"scope": OIDC_SCOPES},
        )
