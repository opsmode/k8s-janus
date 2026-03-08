import asyncio
import os
import re
import logging
import uuid
from datetime import datetime, timezone, timedelta
from enum import Enum
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, Request, Form, WebSocket, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from kubernetes.client.rest import ApiException
from authlib.integrations.starlette_client import OAuth

from db import (
    init_db, upsert_request, log_audit, get_audit_log,
    get_recent_audit_logs, _now, db_enabled,
    get_user_quick_commands, create_user_quick_command,
    update_user_quick_command, delete_user_quick_command,
)
from k8s import (
    get_api_clients, get_cluster_config, get_allowed_namespaces,
    get_access_request, list_access_requests, read_token_secret,
    get_clusters, invalidate_clusters_cache,
    CRD_GROUP, CRD_VERSION, JANUS_NAMESPACE,
)
from terminal_ws import terminal_websocket_handler, notify_revoked

# ---------------------------------------------------------------------------
# Setup wizard — in-memory session state
# ---------------------------------------------------------------------------
_setup_kubeconfigs: dict[str, dict] = {}   # session_id → parsed kubeconfig dict
_setup_queues: dict[str, asyncio.Queue] = {}  # session_id → progress queue

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_TTL_SECONDS = int(os.environ.get("DEFAULT_TTL_SECONDS", "3600"))
MAX_TTL_SECONDS     = int(os.environ.get("MAX_TTL_SECONDS", "28800"))
_raw_ttl_opts = os.environ.get("APPROVAL_TTL_OPTIONS", "3600,7200,14400,28800")
APPROVAL_TTL_OPTIONS = [int(x) for x in _raw_ttl_opts.split(",") if x.strip().isdigit()]
_raw_admins  = os.environ.get("ADMIN_EMAILS", "")
# Support both comma and semicolon delimiters; strip whitespace
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
    logger_pre = logging.getLogger("k8s-janus-webui")
    logger_pre.warning(f"⚠️  Unknown DISPLAY_TIMEZONE '{_tz_name}', falling back to UTC")
    DISPLAY_TZ = ZoneInfo("UTC")

# AUTH_ENABLED controls whether X-Forwarded-Email headers are required.
# Set to "false" when running without an auth proxy (local dev, no ingress SSO).
# When false, all users are treated as admin (open mode).
AUTH_ENABLED = os.environ.get("AUTH_ENABLED", "true").lower() not in ("false", "0", "no")
APP_VERSION  = os.environ.get("APP_VERSION", "dev")

# ---------------------------------------------------------------------------
# Native OIDC configuration
# ---------------------------------------------------------------------------
OIDC_ENABLED        = os.environ.get("OIDC_ENABLED", "false").lower() == "true"
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

# OAuth client (authlib) — registered at module load when OIDC_ENABLED
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

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("k8s-janus-webui")
logger.setLevel(logging.INFO)


class _AccessLogFilter(logging.Filter):
    # High-frequency or low-signal paths — suppress from access log entirely
    _SUPPRESS = (
        "GET /healthz",
        "GET / ",
        "GET /admin",
        "GET /logs",
        "/api/terminal/",
        "/api/audit",
        "/api/status/",
        "/api/pods/",
        "/api/logs/",
        "/api/events/",
        "/api/system-logs/",
        "GET /namespaces/",
        "GET /static/",
        "GET /status/",
    )

    def filter(self, record):
        msg = record.getMessage()
        if any(s in msg for s in self._SUPPRESS):
            return False
        # Drop all 3xx/4xx/5xx scanner noise
        for code in (" 301 ", " 302 ", " 304 ", " 400 ", " 404 ", " 405 ", " 500 ", " 502 "):
            if code in msg:
                return False
        return True


logging.getLogger("uvicorn.access").addFilter(_AccessLogFilter())
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

# ---------------------------------------------------------------------------
# Phase enum
# ---------------------------------------------------------------------------


class Phase(str, Enum):
    PENDING   = "Pending"
    APPROVED  = "Approved"
    ACTIVE    = "Active"
    DENIED    = "Denied"
    EXPIRED   = "Expired"
    REVOKED   = "Revoked"
    CANCELLED = "Cancelled"
    FAILED    = "Failed"

# ---------------------------------------------------------------------------
# Path parameter validation
# ---------------------------------------------------------------------------
_NAME_RE    = re.compile(r'^[a-z0-9][a-z0-9\-]{0,252}$')
_NS_RE      = re.compile(r'^[a-z0-9][a-z0-9\-\.]{0,62}$')
# Cluster names can include underscores (e.g. GKE context names like
# gke_project_region_cluster) and are validated against known CLUSTERS only.
_CLUSTER_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_\-\.:/]{0,252}$')


def _valid_name(s: str) -> bool:
    return bool(s and _NAME_RE.match(s))


def _valid_ns(s: str) -> bool:
    return bool(s and _NS_RE.match(s))


def _valid_cluster(s: str) -> bool:
    return bool(s and _CLUSTER_RE.match(s))


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
_APP_DIR = os.environ.get("APP_DIR", "/app")
app = FastAPI(title="K8s-Janus", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=f"{_APP_DIR}/static"), name="static")
templates = Jinja2Templates(directory=f"{_APP_DIR}/templates")


_OIDC_PUBLIC_PATHS = {"/login", "/login/redirect", "/auth/callback", "/healthz", "/logout",
                      "/setup/upload", "/setup/upload-helper"}


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    _HEADERS = [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("content-security-policy", (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net https://unpkg.com 'unsafe-inline'; "
            "style-src 'self' https://cdn.jsdelivr.net https://unpkg.com https://fonts.googleapis.com 'unsafe-inline'; "
            "font-src 'self' https://cdn.jsdelivr.net https://unpkg.com https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self' wss: ws:;"
        )),
    ]

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for name, value in self._HEADERS:
            response.headers[name] = value
        return response


class _OIDCAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not OIDC_ENABLED:
            return await call_next(request)
        path = request.url.path
        if path in _OIDC_PUBLIC_PATHS or path.startswith("/static") or path.startswith("/setup"):
            return await call_next(request)
        if not request.session.get("user_email"):
            _json_prefixes = ("/api/", "/ws/", "/approve/", "/deny/", "/revoke/", "/cancel/", "/extend/")
            if path.startswith(_json_prefixes) or request.headers.get("accept", "").startswith("application/json"):
                return JSONResponse({"error": "unauthenticated"}, status_code=401)
            return RedirectResponse(f"/login?next={path}", status_code=302)
        return await call_next(request)


# Middleware stack — all via add_middleware (LIFO: last added = outermost = runs first).
# @app.middleware("http") decorators are always outermost and interfere with Set-Cookie
# propagation from SessionMiddleware, so none are used here.
#
#   1. SessionMiddleware         — outermost: decodes cookie → populates request.session
#   2. _OIDCAuthMiddleware       — reads session; returns early (no call_next) when unauthed
#   3. _SecurityHeadersMiddleware — innermost: adds security headers to every response
app.add_middleware(_OIDCAuthMiddleware)
app.add_middleware(_SecurityHeadersMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=OIDC_SESSION_SECRET,
    https_only=True,    # uvicorn --proxy-headers rewrites scheme to https; Secure flag required
    same_site="lax",
    max_age=86400,
)


@app.exception_handler(404)
async def _not_found(request: Request, exc):
    return templates.TemplateResponse("404.html", {"request": request, "path": request.url.path}, status_code=404)


@app.exception_handler(500)
async def _server_error(request: Request, exc):
    return templates.TemplateResponse("500.html", {"request": request, "detail": str(exc)}, status_code=500)


@app.on_event("startup")
async def on_startup():
    import asyncio
    init_db()
    if OIDC_ENABLED:
        pass  # logged after startup block
    elif AUTH_ENABLED:
        logger.info("🚀 K8s-Janus WebUI started — auth via ingress/oauth2-proxy (X-Forwarded-Email)")
    else:
        logger.warning("🔓 K8s-Janus WebUI started in OPEN MODE — AUTH_ENABLED=false, no authentication required")
    from k8s import EXCLUDED_NAMESPACES
    if EXCLUDED_NAMESPACES:
        logger.info(f"🚫 Excluded namespaces: {sorted(EXCLUDED_NAMESPACES)}")
    else:
        logger.info("ℹ️  No namespaces excluded (EXCLUDED_NAMESPACES not set)")
    # Schedule periodic DB cleanup every 24h

    async def _db_cleanup_loop():
        while True:
            await asyncio.sleep(86400)
            try:
                from db import purge_old_records
                purge_old_records(days=30)
            except Exception as e:
                logger.error(f"💥 DB cleanup failed: {e}")
    asyncio.ensure_future(_db_cleanup_loop())
    if OIDC_ENABLED:
        logger.info(f"🔐 OIDC auth enabled — provider: {OIDC_PROVIDER or 'custom'}")


# ---------------------------------------------------------------------------
# OIDC routes
# ---------------------------------------------------------------------------

@app.get("/login", include_in_schema=False)
async def oidc_login(request: Request, next: str = "/", error: str = ""):
    if not OIDC_ENABLED:
        return RedirectResponse("/")
    if request.session.get("user_email"):
        return RedirectResponse(next or "/")
    provider_name = _PROVIDER_DISPLAY.get(OIDC_PROVIDER, OIDC_PROVIDER or "SSO")
    return templates.TemplateResponse("login.html", {
        "request": request,
        "provider_name": provider_name,
        "provider": OIDC_PROVIDER,
        "next": next,
        "error": error,
    })


@app.get("/login/redirect", include_in_schema=False)
async def oidc_login_redirect(request: Request, next: str = "/"):
    """Kick off the OAuth2 redirect to the IdP."""
    # url_for uses the incoming request scheme which may be http behind ingress;
    # honour X-Forwarded-Proto so the redirect_uri sent to the IdP uses https.
    callback_url = request.url_for("oidc_callback")
    scheme = request.headers.get("x-forwarded-proto", callback_url.scheme)
    redirect_uri = str(callback_url).replace(f"{callback_url.scheme}://", f"{scheme}://")
    request.session["oidc_next"] = next
    if OIDC_PROVIDER == "github":
        client = _oauth.github
    else:
        client = _oauth.oidc
    return await client.authorize_redirect(request, redirect_uri)


@app.get("/auth/callback", include_in_schema=False)
async def oidc_callback(request: Request):
    """Handle IdP callback: exchange code for tokens, set session."""
    try:
        if OIDC_PROVIDER == "github":
            client = _oauth.github
            token = await client.authorize_access_token(request)
            # GitHub: primary verified email from /user/emails
            import httpx as _httpx
            async with _httpx.AsyncClient() as hc:
                r = await hc.get(
                    "https://api.github.com/user/emails",
                    headers={"Authorization": f"Bearer {token['access_token']}"},
                )
                emails = r.json()
            email = next(
                (e["email"] for e in emails if e.get("primary") and e.get("verified")),
                None,
            )
            if not email:
                return RedirectResponse("/login?error=No+verified+primary+email+on+GitHub+account", status_code=302)
            # name from /user
            async with _httpx.AsyncClient() as hc:
                r = await hc.get(
                    "https://api.github.com/user",
                    headers={"Authorization": f"Bearer {token['access_token']}"},
                )
                name = r.json().get("name") or r.json().get("login") or email
        else:
            client = _oauth.oidc
            token = await client.authorize_access_token(request)
            userinfo = token.get("userinfo") or await client.userinfo(token=token)
            email = userinfo.get("email", "")
            name  = (
                userinfo.get("name")
                or userinfo.get("preferred_username")
                or userinfo.get("given_name")
                or email
            )
    except Exception as exc:
        logger.error(f"OIDC callback error: {exc}")
        return RedirectResponse(f"/login?error={str(exc)[:120]}", status_code=302)

    if not email:
        return RedirectResponse("/login?error=No+email+returned+by+identity+provider", status_code=302)

    # Domain allowlist
    if OIDC_ALLOWED_DOMAINS:
        domain = email.split("@")[-1].lower()
        if domain not in OIDC_ALLOWED_DOMAINS:
            return templates.TemplateResponse(
                "403.html",
                {"request": request, "user_email": email, "reason": f"Email domain '{domain}' is not allowed."},
                status_code=403,
            )

    request.session["user_email"] = email.lower()
    request.session["user_name"]  = name
    next_url = request.session.pop("oidc_next", "/") or "/"
    logger.info(f"🔐 OIDC login: {email}")
    # Redirect admins to /admin unless a specific next URL was requested
    if next_url == "/" and _is_admin(email.lower()):
        next_url = "/admin"
    return RedirectResponse(next_url, status_code=302)


@app.get("/logout", include_in_schema=False)
async def oidc_logout(request: Request):
    logger.warning(f"🔐 /logout called — referer: {request.headers.get('referer', 'none')} "
                   f"user-agent: {request.headers.get('user-agent', 'none')[:60]}")
    request.session.clear()
    if OIDC_ENABLED:
        return templates.TemplateResponse("signedout.html", {"request": request})
    return RedirectResponse("/")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_berlin(iso_str: str) -> str:
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local_dt = dt.astimezone(DISPLAY_TZ)
        return local_dt.strftime("%Y-%m-%d %H:%M") + " " + local_dt.strftime("%Z")
    except Exception:
        return iso_str[:19].replace("T", " ")


templates.env.filters["to_berlin"] = _to_berlin
templates.env.globals["app_version"] = APP_VERSION


def _is_admin(email: str) -> bool:
    # Open mode (no auth of any kind) → everyone is admin
    if not AUTH_ENABLED and not OIDC_ENABLED:
        return True
    if not email:
        return False
    return email.lower() in ADMIN_EMAILS


def _get_user(request: Request) -> tuple[str, str]:
    """Return (email, name) from:
    1. OIDC session cookie (when OIDC_ENABLED=true)
    2. X-Forwarded-Email header from oauth2-proxy/ingress (legacy path)
    3. Empty strings when AUTH_ENABLED=false (open mode)
    """
    if OIDC_ENABLED:
        email = request.session.get("user_email", "")
        name  = request.session.get("user_name", email)
        return email, name
    email = request.headers.get("X-Forwarded-Email", "")
    name  = request.headers.get("X-Forwarded-Preferred-Username", email)
    return email, name


def _base_context(request: Request) -> dict:
    user_email, user_name = _get_user(request)
    return {
        "request": request,
        "clusters": get_clusters(),
        "user_email": user_email,
        "user_name": user_name,
        "is_devops": _is_admin(user_email),
        "is_admin": _is_admin(user_email),
        "oidc_enabled": OIDC_ENABLED,
        "default_ttl": DEFAULT_TTL_SECONDS // 3600,
        "max_ttl": MAX_TTL_SECONDS // 3600,
        "approval_ttl_options": APPROVAL_TTL_OPTIONS,
    }


def _require_admin(request: Request):
    """Return 403 if caller is not in ADMIN_EMAILS, else None.
    When both AUTH_ENABLED=false and OIDC_ENABLED=false, skip the check (open mode).
    """
    if not AUTH_ENABLED and not OIDC_ENABLED:
        return None
    user_email, _ = _get_user(request)
    if not _is_admin(user_email):
        return templates.TemplateResponse("403.html", {"request": request, "user_email": user_email}, status_code=403)
    return None


def _patch_status(name: str, body: dict) -> None:
    """Patch an AccessRequest CRD status on the central cluster."""
    custom_api, _ = get_api_clients(get_clusters()[0]["name"])
    custom_api.patch_cluster_custom_object_status(
        group=CRD_GROUP, version=CRD_VERSION, plural="accessrequests", name=name,
        body={"status": body},
    )


def _token_client(name: str, cluster: str, namespace: str = ""):
    """Return (core_v1_with_token, namespace) for the given AccessRequest.

    If namespace is given, uses the token secret for that specific namespace.
    Otherwise falls back to the first namespace in the spec.
    """
    from k8s import get_client_with_token
    ar = get_access_request(name, cluster)
    if not ar:
        return None, None
    if ar.get("status", {}).get("phase") != Phase.ACTIVE:
        return None, None

    # Resolve which namespace and which secret to use
    token_secrets = ar.get("status", {}).get("tokenSecrets", {})
    namespaces    = ar.get("spec", {}).get("namespaces") or []
    if not namespaces:
        ns = ar.get("spec", {}).get("namespace", "")
        namespaces = [ns] if ns else []

    if namespace and namespace in namespaces:
        resolved_ns = namespace
    elif namespaces:
        resolved_ns = namespaces[0]
    else:
        return None, None

    secret_name = token_secrets.get(resolved_ns) or ar.get("status", {}).get("tokenSecret", "")
    if not secret_name:
        return None, None
    try:
        token, server, ca = read_token_secret(secret_name)
    except Exception as e:
        logger.error(f"🔑 Failed to read token secret {secret_name}: {e}")
        return None, None
    core_v1 = get_client_with_token(cluster, token, server, ca)
    return core_v1, resolved_ns


# ---------------------------------------------------------------------------
# Setup wizard routes
# ---------------------------------------------------------------------------

@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    """Serve the setup wizard (always accessible from the admin page)."""
    return templates.TemplateResponse("setup.html", _base_context(request))


@app.get("/setup/upload-helper")
async def setup_upload_helper():
    """Serve the setup-upload.sh script for download."""
    from fastapi.responses import FileResponse
    script_path = os.path.join(_APP_DIR, "setup-upload.sh")
    if not os.path.isfile(script_path):
        return JSONResponse({"error": "Helper script not found."}, status_code=404)
    return FileResponse(
        script_path,
        media_type="text/x-shellscript",
        filename="setup-upload.sh",
        headers={"Content-Disposition": "attachment; filename=setup-upload.sh"},
    )


@app.post("/setup/upload")
async def setup_upload(kubeconfig: UploadFile = File(...)):
    """Parse an uploaded kubeconfig and return its contexts."""
    raw = await kubeconfig.read()
    if len(raw) > 1024 * 1024:
        return JSONResponse({"error": "File too large (max 1 MB)."}, status_code=400)
    try:
        from setup import parse_kubeconfig, list_contexts
        kc = parse_kubeconfig(raw)
        contexts = list_contexts(kc)
    except ValueError as e:
        return JSONResponse({"error": str(e)})

    session_id = str(uuid.uuid4())
    _setup_kubeconfigs[session_id] = kc
    return JSONResponse({"session_id": session_id, "contexts": contexts, "error": None})


@app.get("/setup/contexts/{session_id}")
async def setup_contexts(session_id: str):
    """Return contexts for an existing upload session (used by upload-helper redirect)."""
    if session_id not in _setup_kubeconfigs:
        return JSONResponse({"error": "Session not found or expired."}, status_code=404)
    from setup import list_contexts
    contexts = list_contexts(_setup_kubeconfigs[session_id])
    return JSONResponse({"session_id": session_id, "contexts": contexts, "error": None})


@app.post("/setup/run")
async def setup_run(request: Request):
    """Kick off the setup background task for a previously uploaded kubeconfig."""
    body = await request.json()
    session_id    = body.get("session_id", "")
    central       = body.get("central", "")
    central_name    = body.get("central_name", "")     # internal slug for central cluster
    central_display = body.get("central_display", "")  # display name for central cluster
    # remotes: list of {"context": str, "cluster_name": str, "display_name": str}
    remotes         = body.get("remotes", [])

    if not session_id or session_id not in _setup_kubeconfigs:
        return JSONResponse({"error": "Session not found. Please re-upload your kubeconfig."}, status_code=400)
    if not central:
        return JSONResponse({"error": "No central cluster selected."}, status_code=400)

    kc = _setup_kubeconfigs[session_id]
    q: asyncio.Queue = asyncio.Queue()
    _setup_queues[session_id] = q
    display = central_display or central_name or central
    asyncio.ensure_future(_run_setup_task(session_id, kc, central, display, remotes, JANUS_NAMESPACE, q))
    return JSONResponse({"ok": True})


@app.get("/api/clusters")
async def api_clusters():
    """Return the live cluster list (auto-discovered from kubeconfig Secrets)."""
    return JSONResponse(get_clusters())


@app.post("/setup/rename-cluster")
async def setup_rename_cluster(request: Request):
    """Patch the displayName annotation on a kubeconfig Secret."""
    body         = await request.json()
    cluster_name = body.get("cluster_name", "").strip()
    display_name = body.get("display_name", "").strip()
    if not cluster_name or not display_name:
        return JSONResponse({"error": "cluster_name and display_name are required."}, status_code=400)

    from kubernetes import client as k8s_client, config as k8s_config
    from k8s import _CENTRAL_NAME
    is_central  = (cluster_name == _CENTRAL_NAME)
    secret_name = "janus-central-display" if is_central else f"{cluster_name}-kubeconfig"

    try:
        k8s_config.load_incluster_config()
        core = k8s_client.CoreV1Api()
        if is_central:
            # Upsert the dedicated central display override secret
            body = k8s_client.V1Secret(
                metadata=k8s_client.V1ObjectMeta(
                    name=secret_name,
                    namespace=JANUS_NAMESPACE,
                    labels={"k8s-janus.infroware.com/managed": "true"},
                    annotations={"k8s-janus.infroware.com/displayName": display_name},
                ),
                type="Opaque",
            )
            try:
                core.create_namespaced_secret(namespace=JANUS_NAMESPACE, body=body)
            except k8s_client.exceptions.ApiException as e:
                if e.status == 409:
                    core.patch_namespaced_secret(name=secret_name, namespace=JANUS_NAMESPACE, body=body)
                else:
                    raise
        else:
            core.patch_namespaced_secret(
                name=secret_name,
                namespace=JANUS_NAMESPACE,
                body={"metadata": {"annotations": {"k8s-janus.infroware.com/displayName": display_name}}},
            )
        invalidate_clusters_cache()
        return JSONResponse({"ok": True})
    except Exception as e:
        logger.error(f"Failed to rename cluster {cluster_name!r}: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/setup/remove-cluster")
async def setup_remove_cluster(request: Request):
    """
    Remove a remote cluster: deletes its kubeconfig Secret and optionally
    cleans up RBAC on the remote if a session_id + context is provided.
    """
    body         = await request.json()
    cluster_name = body.get("cluster_name", "").strip()
    session_id   = body.get("session_id", "")
    context_name = body.get("context", "")

    if not cluster_name:
        return JSONResponse({"error": "cluster_name is required."}, status_code=400)

    loop = asyncio.get_event_loop()
    kubeconfig = _setup_kubeconfigs.get(session_id) if session_id else None

    from setup import remove_cluster, _rollout_restart_deployments
    lines = await loop.run_in_executor(
        None, remove_cluster, cluster_name, JANUS_NAMESPACE,
        kubeconfig, context_name or None
    )

    # Invalidate cluster cache after removal
    invalidate_clusters_cache()

    # Restart pods so controller/webui picks up the removed cluster
    had_error = any(line.startswith("[ERROR]") for line in lines)
    if not had_error:
        try:
            await loop.run_in_executor(None, _rollout_restart_deployments, JANUS_NAMESPACE)
            lines.append("[INFO] Restarting pods to apply changes...")
        except Exception as e:
            lines.append(f"[WARN]  Pod restart failed (non-fatal): {e}")

    return JSONResponse({"lines": lines, "ok": not had_error})


@app.post("/api/setup/restart-deployments")
async def setup_restart_deployments():
    """Manually trigger a rollout restart of controller + webui deployments."""
    from setup import _rollout_restart_deployments
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, _rollout_restart_deployments, JANUS_NAMESPACE)
        return JSONResponse({"ok": True, "message": "Deployments restarted."})
    except Exception as e:
        return JSONResponse({"ok": False, "message": str(e)}, status_code=500)


@app.get("/api/setup/redirect-url")
async def setup_redirect_url(request: Request):
    """
    Return the URL the setup wizard should redirect to on completion.
    Priority:
      1. WEBUI_BASE_URL env (explicitly configured — ingress or static LB hostname)
      2. LoadBalancer IP of the webui Service (auto-detected via in-cluster API)
      3. Request host fallback (port-forward / local dev)
    """
    base_url = os.environ.get("WEBUI_BASE_URL", "").rstrip("/")
    if not base_url:
        try:
            from k8s import _get_central_core_v1
            from kubernetes import client as _k8s_client
            core_v1 = _get_central_core_v1()

            # 1. Ingress hostname (highest priority — user-configured domain)
            try:
                net_v1 = _k8s_client.NetworkingV1Api(core_v1.api_client)
                for ing in net_v1.list_namespaced_ingress(namespace=JANUS_NAMESPACE).items:
                    for rule in (ing.spec.rules or []):
                        if rule.host:
                            tls_hosts = [h for tls in (ing.spec.tls or []) for h in (tls.hosts or [])]
                            scheme = "https" if rule.host in tls_hosts else "http"
                            base_url = f"{scheme}://{rule.host}"
                            break
                    if base_url:
                        break
            except Exception:
                pass

            # 2. LoadBalancer Service IP/hostname
            if not base_url:
                for svc in core_v1.list_namespaced_service(namespace=JANUS_NAMESPACE).items:
                    if svc.spec.type != "LoadBalancer":
                        continue
                    ingresses = (svc.status.load_balancer.ingress or []) if svc.status.load_balancer else []
                    if ingresses:
                        lb = ingresses[0]
                        host = lb.hostname or lb.ip
                        if host:
                            base_url = f"http://{host}"
                            break
        except Exception:
            pass
    if not base_url:
        # Final fallback: derive from request (works for port-forward)
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        host   = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost"))
        base_url = f"{scheme}://{host}"
    return JSONResponse({"url": f"{base_url}/"})


@app.websocket("/ws/setup/{session_id}")
async def setup_websocket(websocket: WebSocket, session_id: str):
    """Stream setup progress lines to the browser."""
    await websocket.accept()
    q = _setup_queues.get(session_id)
    if q is None:
        await websocket.send_json({"type": "error", "text": "Session not found."})
        await websocket.close()
        return
    try:
        while True:
            msg = await q.get()
            if msg is None:
                await websocket.send_json({"type": "done"})
                break
            await websocket.send_json({"type": "line", "text": msg})
    except Exception:
        pass
    finally:
        _setup_queues.pop(session_id, None)
        try:
            await websocket.close()
        except Exception:
            pass


async def _run_setup_task(
    session_id: str,
    kubeconfig: dict,
    central: str,
    central_name: str,
    remotes: list,
    janus_namespace: str,
    q: asyncio.Queue,
) -> None:
    """Background coroutine: runs the setup generator and pushes lines to the queue."""
    try:
        from setup import run_setup
        async for line in run_setup(kubeconfig, central, central_name, remotes, janus_namespace):
            await q.put(line)
        # Invalidate cluster cache so the UI picks up new clusters immediately
        invalidate_clusters_cache()
    except Exception as e:
        await q.put(f"[FATAL] Unexpected error: {e}")
    finally:
        _setup_kubeconfigs.pop(session_id, None)
        await q.put(None)  # sentinel → WebSocket handler closes


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    ctx = _base_context(request)
    all_requests = list_access_requests()
    ctx["access_requests"] = [
        ar for ar in all_requests
        if ar.get("spec", {}).get("requester", "").lower() == ctx["user_email"].lower()
    ]
    ctx["is_admin"] = False
    ctx["health_indicator"] = True
    return templates.TemplateResponse("index.html", ctx)


@app.get("/admin", response_class=HTMLResponse)
async def admin(request: Request):
    if (err := _require_admin(request)):
        return err
    ctx = _base_context(request)
    ctx["access_requests"] = list_access_requests()
    ctx["is_admin"] = True
    ctx["janus_namespace"] = JANUS_NAMESPACE
    # Find the webui LoadBalancer service name for the port-forward command
    webui_svc = "janus-webui"
    try:
        from k8s import _get_central_core_v1
        core_v1 = _get_central_core_v1()
        svcs = core_v1.list_namespaced_service(namespace=JANUS_NAMESPACE)
        for svc in svcs.items:
            if svc.spec.type == "LoadBalancer":
                webui_svc = svc.metadata.name
                break
    except Exception:
        pass
    ctx["janus_webui_svc"] = webui_svc
    ctx["health_indicator"] = True
    return templates.TemplateResponse("admin.html", ctx)


@app.get("/api/pods/{cluster}/{namespace}")
async def preview_pods(cluster: str, namespace: str):
    if not _valid_cluster(cluster) or not _valid_ns(namespace):
        return JSONResponse({"error": "Invalid cluster or namespace", "pods": []}, status_code=400)
    try:
        _, core_v1 = get_api_clients(cluster)
        pods = core_v1.list_namespaced_pod(namespace=namespace)
        pod_list = [
            {
                "name": p.metadata.name,
                "status": p.status.phase,
                "ready": sum(1 for c in (p.status.container_statuses or []) if c.ready),
                "total": len(p.spec.containers),
            }
            for p in pods.items
        ]
        return JSONResponse({"pods": pod_list, "error": None})
    except Exception as e:
        logger.error(f"💥 Failed to list pods in {cluster}/{namespace}: {e}")
        return JSONResponse({"error": "Failed to list pods", "pods": []})


# ---------------------------------------------------------------------------
# Profile API — server-side avatar/name store (in-memory, per-email)
# ---------------------------------------------------------------------------
_profiles: dict[str, dict] = {}  # email → {name, photo}


@app.post("/api/profile", include_in_schema=False)
async def save_profile(request: Request):
    user_email, user_name = _get_user(request)
    if not user_email:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)
    name  = str(body.get("name", ""))[:60]
    photo = str(body.get("photo", ""))
    # Validate photo is a data-URL (base64 image) or empty
    if photo and not photo.startswith("data:image/"):
        photo = ""
    _profiles[user_email.lower()] = {"name": name, "photo": photo}
    return JSONResponse({"ok": True})


@app.get("/api/avatar/{email}", include_in_schema=False)
async def get_avatar(email: str):
    p = _profiles.get(email.lower(), {})
    return JSONResponse({"name": p.get("name", ""), "photo": p.get("photo", "")})


@app.get("/namespaces/{cluster_name}", response_class=HTMLResponse)
async def namespaces(cluster_name: str):
    if not _valid_cluster(cluster_name):
        return JSONResponse([], status_code=400)
    logger.debug(f"📡 API request: GET /namespaces/{cluster_name}")
    ns_list = get_allowed_namespaces(cluster_name)  # returns [] on error
    logger.debug(f"📤 Returning {len(ns_list)} namespaces for cluster {cluster_name}")
    return JSONResponse(ns_list)


@app.post("/request")
async def submit_request(request: Request):
    """Accept a single-cluster multi-namespace access request as JSON.

    Body: {
      "requester": str,          # may be overridden by auth header
      "targets": [{"cluster": str, "namespace": str}, ...],
      "reason": str,
      "ttl_hours": int,
    }

    Creates one AccessRequest CRD with namespaces[] for all selected namespaces.
    Returns JSON: {"created": [str], "skipped": [str], "errors": [str]}
    """
    user_from_auth, _ = _get_user(request)

    body = await request.json()
    requester  = user_from_auth or body.get("requester", "").strip()
    reason     = body.get("reason", "").strip()[:500]
    ttl_hours  = int(body.get("ttl_hours", 1))
    targets    = body.get("targets", [])  # list of {"cluster": str, "namespace": str}

    if not requester:
        return JSONResponse({"error": "Unauthorized: no authenticated user found."}, status_code=401)
    if not targets:
        return JSONResponse({"error": "No targets specified."}, status_code=400)
    if not reason:
        return JSONResponse({"error": "Reason is required."}, status_code=400)
    if ttl_hours < 1:
        return JSONResponse({"error": "TTL must be at least 1 hour."}, status_code=400)

    ttl_seconds = min(ttl_hours * 3600, MAX_TTL_SECONDS)

    # All targets must be for the same cluster
    clusters_in_request = {t.get("cluster", "") for t in targets}
    if len(clusters_in_request) > 1:
        return JSONResponse({"error": "All namespaces must be on the same cluster."}, status_code=400)

    cluster = targets[0]["cluster"]
    if not _valid_cluster(cluster) or not get_cluster_config(cluster):
        return JSONResponse({"error": f"Unknown cluster: {cluster}"}, status_code=400)

    allowed = get_allowed_namespaces(cluster)
    skipped: list[str] = []
    errors:  list[str] = []

    namespaces = []
    for t in targets:
        ns = t.get("namespace", "")
        if not _valid_ns(ns):
            skipped.append(f"{ns} (invalid name)")
            continue
        if ns not in allowed:
            skipped.append(f"{ns} (not allowed)")
            continue
        namespaces.append(ns)

    if not namespaces:
        return JSONResponse({"error": "No valid namespaces.", "skipped": skipped, "errors": errors}, status_code=400)

    # Dedup: reject namespaces already covered by a live request from this requester on this cluster
    all_requests = list_access_requests()
    live_phases  = (Phase.PENDING, Phase.APPROVED, Phase.ACTIVE)
    busy_ns: set[str] = set()
    for ar in all_requests:
        sp = ar.get("spec", {})
        if (sp.get("requester") == requester
                and sp.get("cluster") == cluster
                and ar.get("status", {}).get("phase", "") in live_phases):
            ar_nss = sp.get("namespaces") or ([sp["namespace"]] if sp.get("namespace") else [])
            busy_ns.update(ar_nss)

    duplicate_ns = [ns for ns in namespaces if ns in busy_ns]
    if duplicate_ns:
        dupes = ", ".join(duplicate_ns)
        return JSONResponse(
            {"error": f"You already have an active request for: {dupes}. Wait for it to expire or ask an admin to revoke it."},
            status_code=409,
        )

    # Rate limit: max 10 active/pending/approved
    active_count = sum(
        1 for ar in all_requests
        if ar.get("spec", {}).get("requester") == requester
        and ar.get("status", {}).get("phase", "") in live_phases
    )
    if active_count >= 10:
        return JSONResponse(
            {"error": "Too many active requests. Wait for existing requests to expire or be revoked."},
            status_code=429,
        )

    central_api, _ = get_api_clients(get_clusters()[0]["name"])
    safe_requester  = requester.split("@")[0].lower().replace(".", "-")[:20]
    ts_base         = datetime.now(timezone.utc).strftime("%m%d%H%M%S")
    name            = f"k8s-janus-{safe_requester}-{ts_base}"

    ar_body = {
        "apiVersion": f"{CRD_GROUP}/{CRD_VERSION}",
        "kind": "AccessRequest",
        "metadata": {"name": name},
        "spec": {
            "requester":   requester,
            "namespaces":  namespaces,
            "namespace":   namespaces[0],  # backwards compat field
            "reason":      reason,
            "ttlSeconds":  ttl_seconds,
            "cluster":     cluster,
        },
    }

    try:
        central_api.create_cluster_custom_object(
            group=CRD_GROUP, version=CRD_VERSION, plural="accessrequests", body=ar_body,
        )
        logger.info(f"🎫 Created AccessRequest {name} for {requester} on {cluster} ns={namespaces}")
        upsert_request(
            name,
            cluster=cluster, namespace=namespaces[0], requester=requester,
            ttl_seconds=ttl_seconds, reason=reason, phase=Phase.PENDING, created_at=_now(),
        )
        log_audit(name, "request.created", actor=requester,
                  detail=f"cluster={cluster} ns={namespaces} ttl={ttl_seconds}s")
        return JSONResponse({"created": [name], "skipped": skipped, "errors": errors})
    except ApiException as e:
        logger.error(f"💥 Failed to create AccessRequest for {cluster} ns={namespaces}: {e}")
        return JSONResponse({"error": "Failed to create request.", "errors": [str(e)]}, status_code=500)


@app.get("/status/{cluster}/{name}", response_class=HTMLResponse)
async def status(request: Request, cluster: str, name: str):
    ar = get_access_request(name, cluster)
    if not ar:
        ctx = _base_context(request)
        ctx["error"] = f"Request '{name}' not found on cluster '{cluster}'"
        ctx["access_requests"] = [
            ar for ar in list_access_requests()
            if ar.get("spec", {}).get("requester", "").lower() == ctx["user_email"].lower()
        ]
        ctx["is_admin"] = False
        return templates.TemplateResponse("index.html", ctx)

    ar_status   = ar.get("status", {})
    token = server = ca = ""
    if ar_status.get("phase") == Phase.ACTIVE:
        secret_name = ar_status.get("tokenSecret", "")
        if secret_name:
            try:
                token, server, ca = read_token_secret(secret_name)
            except Exception as e:
                logger.error(f"🔑 Failed to read token secret {secret_name}: {e}")

    cluster_cfg = get_cluster_config(cluster)
    cluster_display_name = cluster_cfg.get("displayName", cluster) if cluster_cfg else cluster
    ctx = _base_context(request)
    ctx.update({
        "cluster_name": cluster_display_name,
        "cluster_display": cluster_display_name,
        "ar": ar,
        "spec": ar.get("spec", {}),
        "status": ar_status,
        "name": name,
        "cluster": cluster,
        "token": token,
        "server": server,
        "ca": ca,
    })
    return templates.TemplateResponse("status.html", ctx)


@app.get("/callback", response_class=HTMLResponse)
async def callback(request: Request, action: str, name: str, cluster: str = ""):
    if not cluster:
        cluster = get_clusters()[0]["name"]
    ar = get_access_request(name, cluster)
    if not ar:
        return templates.TemplateResponse("404.html", {"request": request, "path": f"/action/{name}"}, status_code=404)

    cluster_cfg     = get_cluster_config(cluster)
    cluster_display = cluster_cfg.get("displayName", cluster) if cluster_cfg else cluster
    current_phase   = ar.get("status", {}).get("phase", "")

    _cb_base = {**_base_context(request), "cluster_name": cluster_display, "name": name, "spec": ar.get("spec", {})}
    if current_phase not in (Phase.PENDING, ""):
        return templates.TemplateResponse("callback.html", {
            **_cb_base, "action": action,
            "already_actioned": True, "current_phase": current_phase,
        })

    if action == "deny":
        return templates.TemplateResponse("deny-confirm.html", {
            **_cb_base, "cluster": cluster,
        })

    approver, _ = _get_user(request)
    approver = approver or "devops-team"
    try:
        _patch_status(name, {
            "phase": Phase.APPROVED,
            "approvedBy": approver,
            "approvedAt": datetime.now(timezone.utc).isoformat(),
        })
        logger.info(f"✅ AccessRequest {name} on {cluster} Approved by {approver}")
    except ApiException as e:
        logger.error(f"💥 Failed to update AccessRequest {name}: {e}")
        return templates.TemplateResponse("500.html", {"request": request, "detail": "Error updating request."}, status_code=500)

    return templates.TemplateResponse("callback.html", {
        **_cb_base, "action": "approve",
        "already_actioned": False, "current_phase": Phase.APPROVED,
    })


@app.post("/deny-confirm", response_class=HTMLResponse)
async def deny_confirm(request: Request, name: str = Form(...), cluster: str = Form(...), denial_reason: str = Form("")):
    if (err := _require_admin(request)):
        return err
    denial_reason = denial_reason.strip()[:500]
    ar = get_access_request(name, cluster)
    if not ar:
        return templates.TemplateResponse("404.html", {"request": request, "path": f"/deny/{name}"}, status_code=404)

    cluster_cfg     = get_cluster_config(cluster)
    cluster_display = cluster_cfg.get("displayName", cluster) if cluster_cfg else cluster
    approver, _     = _get_user(request)
    approver        = approver or "devops-team"
    denial_msg      = f"Denied by {approver}" + (f": {denial_reason}" if denial_reason else "")

    try:
        _patch_status(name, {
            "phase": Phase.DENIED,
            "approvedBy": approver,
            "approvedAt": datetime.now(timezone.utc).isoformat(),
            "message": denial_msg,
            "denialReason": denial_reason or None,
        })
        logger.info(f"🚫 AccessRequest {name} on {cluster} Denied by {approver}: {denial_reason or '(no reason)'}")
    except ApiException as e:
        logger.error(f"💥 Failed to update AccessRequest {name}: {e}")
        return templates.TemplateResponse("500.html", {"request": request, "detail": "Error updating request."}, status_code=500)

    _dc_base = {**_base_context(request), "cluster_name": cluster_display, "name": name, "spec": ar.get("spec", {})}
    return templates.TemplateResponse("callback.html", {
        **_dc_base, "action": "deny",
        "already_actioned": False, "current_phase": Phase.DENIED,
    })


@app.post("/approve/{cluster}/{name}")
async def approve(request: Request, cluster: str, name: str):
    if _require_admin(request):
        return JSONResponse({"ok": False, "error": "403 Forbidden"}, status_code=403)
    if not _valid_cluster(cluster) or not _valid_name(name):
        return JSONResponse({"ok": False, "error": "Invalid parameters"}, status_code=400)
    ar = get_access_request(name, cluster)
    if not ar:
        return JSONResponse({"ok": False, "error": f"Request '{name}' not found."}, status_code=404)
    current_phase = ar.get("status", {}).get("phase", "")
    if current_phase != Phase.PENDING:
        return JSONResponse({"ok": False, "error": f"Request is already {current_phase}."}, status_code=409)
    approver, _ = _get_user(request)
    approver = approver or "admin"

    # Optional TTL override from JSON body
    try:
        body = await request.json()
        ttl_override = int(body.get("ttl_seconds") or 0)
    except Exception as _e:
        logger.warning(f"⚠️  approve {name}: failed to parse body: {_e}")
        ttl_override = 0
    if ttl_override < 0 or ttl_override > MAX_TTL_SECONDS:
        ttl_override = 0

    try:
        status_patch: dict = {
            "phase": Phase.APPROVED,
            "approvedBy": approver,
            "approvedAt": datetime.now(timezone.utc).isoformat(),
        }
        effective_ttl = ttl_override or ar.get("spec", {}).get("ttlSeconds", 3600)
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=effective_ttl)).isoformat()
        if ttl_override:
            # Write override into both spec (source of truth) and status (so the controller
            # handler reads it from the same atomic event, avoiding any race window).
            central_api, _ = get_api_clients(get_clusters()[0]["name"])
            central_api.patch_cluster_custom_object(
                group=CRD_GROUP, version=CRD_VERSION, plural="accessrequests", name=name,
                body={"spec": {"ttlSeconds": ttl_override}},
            )
            status_patch["ttlOverride"] = ttl_override
        _patch_status(name, status_patch)
        logger.info(f"✅ AccessRequest {name} on {cluster} Approved by {approver}"
                    + (f" (TTL override {ttl_override}s)" if ttl_override else "")
                    + f" — expires {expires_at}")
        upsert_request(name, phase=Phase.APPROVED, approved_by=approver, approved_at=_now(),
                       cluster=cluster, namespace=ar.get("spec", {}).get("namespace", ""),
                       requester=ar.get("spec", {}).get("requester", ""),
                       ttl_seconds=effective_ttl,
                       created_at=_now())
        log_audit(name, "request.approved", actor=approver,
                  detail=f"cluster={cluster} ttl={effective_ttl}s expires={expires_at}"
                         + (f" ttl_override={ttl_override}s" if ttl_override else ""))
    except ApiException as e:
        logger.error(f"💥 Failed to approve AccessRequest {name}: {e}")
        return JSONResponse({"ok": False, "error": "Failed to approve request"}, status_code=500)
    return JSONResponse({"ok": True, "phase": Phase.APPROVED})


@app.post("/deny/{cluster}/{name}")
async def deny(request: Request, cluster: str, name: str, denial_reason: str = Form("")):
    if _require_admin(request):
        return JSONResponse({"ok": False, "error": "403 Forbidden"}, status_code=403)
    if not _valid_cluster(cluster) or not _valid_name(name):
        return JSONResponse({"ok": False, "error": "Invalid parameters"}, status_code=400)
    ar = get_access_request(name, cluster)
    if not ar:
        return JSONResponse({"ok": False, "error": f"Request '{name}' not found."}, status_code=404)
    current_phase = ar.get("status", {}).get("phase", "")
    if current_phase != Phase.PENDING:
        return JSONResponse({"ok": False, "error": f"Request is already {current_phase}."}, status_code=409)
    approver, _ = _get_user(request)
    approver = approver or "admin"
    denial_reason = denial_reason.strip()[:500]
    denial_msg    = f"Denied by {approver}" + (f": {denial_reason}" if denial_reason else "")
    try:
        _patch_status(name, {
            "phase": Phase.DENIED,
            "approvedBy": approver,
            "approvedAt": datetime.now(timezone.utc).isoformat(),
            "message": denial_msg,
            "denialReason": denial_reason or None,
        })
        logger.info(f"🚫 AccessRequest {name} on {cluster} Denied by {approver}: {denial_reason or '(no reason)'}")
        upsert_request(name, phase=Phase.DENIED, approved_by=approver, denied_at=_now(),
                       denial_reason=denial_reason,
                       cluster=cluster, namespace=ar.get("spec", {}).get("namespace", ""),
                       requester=ar.get("spec", {}).get("requester", ""),
                       ttl_seconds=ar.get("spec", {}).get("ttlSeconds", 3600), created_at=_now())
        log_audit(name, "request.denied", actor=approver,
                  detail=denial_reason or f"denied by {approver}")
    except ApiException as e:
        logger.error(f"💥 Failed to deny AccessRequest {name}: {e}")
        return JSONResponse({"ok": False, "error": "Failed to deny request"}, status_code=500)
    return JSONResponse({"ok": True, "phase": Phase.DENIED})


@app.post("/revoke/{cluster}/{name}", response_class=HTMLResponse)
async def revoke(request: Request, cluster: str, name: str):
    if (err := _require_admin(request)):
        return err
    caller, _ = _get_user(request)
    caller    = caller or "admin"
    ar = get_access_request(name, cluster)
    if not ar:
        return templates.TemplateResponse("404.html", {"request": request, "path": f"/revoke/{name}"}, status_code=404)
    current_phase = ar.get("status", {}).get("phase", "")
    if current_phase not in (Phase.ACTIVE, Phase.APPROVED, Phase.PENDING):
        return RedirectResponse(url="/admin", status_code=303)
    try:
        _patch_status(name, {
            "phase": Phase.REVOKED,
            "message": "Access revoked by admin",
            "revokedAt": datetime.now(timezone.utc).isoformat(),
        })
        logger.info(f"🔒 AccessRequest {name} on {cluster} revoked (was {current_phase})")
        upsert_request(name, phase=Phase.REVOKED, approved_by=caller, revoked_at=_now(),
                       cluster=cluster, namespace=ar.get("spec", {}).get("namespace", ""),
                       requester=ar.get("spec", {}).get("requester", ""),
                       ttl_seconds=ar.get("spec", {}).get("ttlSeconds", 3600), created_at=_now())
        log_audit(name, "access.revoked", actor=caller, detail=f"cluster={cluster} was {current_phase}")
        await notify_revoked(name, revoked_by=caller)
    except ApiException as e:
        logger.error(f"💥 Failed to revoke AccessRequest {name}: {e}")
        wants_json = "application/json" in (request.headers.get("accept") or "")
        if wants_json:
            return JSONResponse({"ok": False, "error": "Failed to revoke request"}, status_code=500)
        return templates.TemplateResponse("500.html", {"request": request, "detail": "Error revoking request."}, status_code=500)
    wants_json = "application/json" in (request.headers.get("accept") or "")
    if wants_json:
        return JSONResponse({"ok": True, "phase": Phase.REVOKED})
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/cancel/{cluster}/{name}")
async def cancel_request(request: Request, cluster: str, name: str):
    """Requester cancels their own Pending or Active request."""
    caller, _ = _get_user(request)
    if not caller:
        return JSONResponse({"ok": False, "error": "Unauthenticated"}, status_code=401)
    if not _valid_cluster(cluster) or not _valid_name(name):
        return JSONResponse({"ok": False, "error": "Invalid parameters"}, status_code=400)
    ar = get_access_request(name, cluster)
    if not ar:
        return JSONResponse({"ok": False, "error": "Request not found"}, status_code=404)
    requester = ar.get("spec", {}).get("requester", "")
    if requester.lower() != caller.lower() and not _is_admin(caller):
        return JSONResponse({"ok": False, "error": "Forbidden"}, status_code=403)
    current_phase = ar.get("status", {}).get("phase", "")
    if current_phase not in (Phase.PENDING, Phase.ACTIVE, Phase.APPROVED):
        return JSONResponse({"ok": False, "error": f"Cannot cancel a {current_phase} request"}, status_code=409)
    try:
        _patch_status(name, {
            "phase": Phase.CANCELLED,
            "message": f"Cancelled by requester {caller}",
            "revokedAt": datetime.now(timezone.utc).isoformat(),
        })
        logger.info(f"🚫 AccessRequest {name} on {cluster} cancelled by requester {caller} (was {current_phase})")
        upsert_request(name, phase=Phase.CANCELLED, approved_by=caller, revoked_at=_now(),
                       cluster=cluster, namespace=ar.get("spec", {}).get("namespace", ""),
                       requester=requester,
                       ttl_seconds=ar.get("spec", {}).get("ttlSeconds", 3600), created_at=_now())
        log_audit(name, "request.cancelled", actor=caller, detail=f"cluster={cluster} was {current_phase}")
        await notify_revoked(name, revoked_by=caller)
    except ApiException as e:
        logger.error(f"💥 Failed to cancel AccessRequest {name}: {e}")
        return JSONResponse({"ok": False, "error": "Failed to cancel request"}, status_code=500)
    return JSONResponse({"ok": True, "phase": Phase.CANCELLED})


@app.get("/terminal/{cluster}/{name}", response_class=HTMLResponse)
async def terminal(request: Request, cluster: str, name: str):
    ar = get_access_request(name, cluster)
    if not ar:
        return templates.TemplateResponse("404.html", {"request": request, "path": f"/terminal/{name}"}, status_code=404)
    phase = ar.get("status", {}).get("phase", "")
    if phase != Phase.ACTIVE:
        return templates.TemplateResponse("403.html", {"request": request, "reason": f"Access is not active. Current phase: {phase}"}, status_code=403)
    cluster_cfg     = get_cluster_config(cluster)
    cluster_display = cluster_cfg.get("displayName", cluster) if cluster_cfg else cluster
    _, user_name    = _get_user(request)
    spec       = ar.get("spec", {})
    namespaces = spec.get("namespaces") or ([spec["namespace"]] if spec.get("namespace") else [])
    ctx = _base_context(request)
    ctx.update({
        "cluster": cluster,
        "cluster_display": cluster_display,
        "request_name": name,
        "namespace": namespaces[0] if namespaces else "",
        "namespaces": namespaces,
        "expires_at": ar.get("status", {}).get("expiresAt", ""),
    })
    return templates.TemplateResponse("terminal.html", ctx)


@app.websocket("/ws/terminal/{cluster}/{name}")
async def terminal_websocket(websocket: WebSocket, cluster: str, name: str):
    await terminal_websocket_handler(websocket, cluster, name)


# ---------------------------------------------------------------------------
# Terminal API (pods / logs / events)
# ---------------------------------------------------------------------------

@app.get("/api/terminal/{cluster}/{name}/pods")
async def list_pods(cluster: str, name: str, namespace: str = ""):
    if not _valid_cluster(cluster) or not _valid_name(name):
        return JSONResponse({"error": "Invalid parameters", "pods": []}, status_code=400)
    core_v1, resolved_ns = _token_client(name, cluster, namespace)
    if core_v1 is None:
        return JSONResponse({"error": "Access not active or request not found", "pods": []})
    try:
        pods = core_v1.list_namespaced_pod(namespace=resolved_ns)
        DISTROLESS = ("distroless", "scratch", "gcr.io/distroless", "chainguard")
        pod_list = []
        for pod in pods.items:
            images    = [c.image or "" for c in pod.spec.containers]
            has_shell = not any(any(d in img.lower() for d in DISTROLESS) for img in images)
            pod_list.append({
                "name": pod.metadata.name, "status": pod.status.phase,
                "hasShell": has_shell, "namespace": resolved_ns,
            })
        return JSONResponse({"pods": pod_list, "namespace": resolved_ns, "error": None})
    except Exception as e:
        logger.error(f"💥 Failed to list pods in {cluster}/{resolved_ns}: {e}")
        return JSONResponse({"error": "Failed to list pods", "pods": []})


@app.get("/api/terminal/{cluster}/{name}/{pod}/logs")
async def get_pod_logs(cluster: str, name: str, pod: str, namespace: str = "", tail: int = 100):
    if not _valid_cluster(cluster) or not _valid_name(name):
        return JSONResponse({"error": "Invalid parameters", "logs": ""}, status_code=400)
    tail = max(10, min(tail, 5000))
    core_v1, resolved_ns = _token_client(name, cluster, namespace)
    if core_v1 is None:
        return JSONResponse({"error": "Access not active or request not found", "logs": ""})
    try:
        logs = core_v1.read_namespaced_pod_log(name=pod, namespace=resolved_ns, tail_lines=tail, timestamps=True)
        return JSONResponse({"logs": logs or "", "error": None})
    except Exception as e:
        logger.error(f"💥 Failed to get logs for {cluster}/{resolved_ns}/{pod}: {e}")
        return JSONResponse({"error": "Failed to retrieve pod logs", "logs": ""})


@app.get("/api/terminal/{cluster}/{name}/{pod}/events")
async def get_pod_events(cluster: str, name: str, pod: str, namespace: str = ""):
    if not _valid_cluster(cluster) or not _valid_name(name):
        return JSONResponse({"error": "Invalid parameters", "events": []}, status_code=400)
    core_v1, resolved_ns = _token_client(name, cluster, namespace)
    if core_v1 is None:
        return JSONResponse({"error": "Access not active or request not found", "events": []})
    try:
        events = core_v1.list_namespaced_event(
            namespace=resolved_ns, field_selector=f"involvedObject.name={pod}"
        )
        event_list = [
            {
                "type": e.type, "reason": e.reason, "message": e.message, "count": e.count,
                "firstTimestamp": e.first_timestamp.isoformat() if e.first_timestamp else "",
                "lastTimestamp":  e.last_timestamp.isoformat()  if e.last_timestamp  else "",
            }
            for e in events.items
        ]
        event_list.sort(key=lambda x: x["lastTimestamp"], reverse=True)
        return JSONResponse({"events": event_list, "error": None})
    except ApiException as e:
        if e.status == 403:
            logger.warning(f"⛔ Events forbidden for {cluster}/{resolved_ns}/{pod}")
            return JSONResponse({"events": [], "forbidden": True, "error": None})
        logger.error(f"💥 Failed to get events for {cluster}/{resolved_ns}/{pod}: {e}")
        return JSONResponse({"error": "Failed to retrieve pod events", "events": []})
    except Exception as e:
        logger.error(f"💥 Failed to get events for {cluster}/{resolved_ns}/{pod}: {e}")
        return JSONResponse({"error": "Failed to retrieve pod events", "events": []})


# ---------------------------------------------------------------------------
# Audit / command history APIs
# ---------------------------------------------------------------------------

@app.get("/api/audit")
async def audit_recent(limit: int = 200, offset: int = 0):
    return JSONResponse(get_recent_audit_logs(limit=min(limit, 500), offset=offset))


@app.get("/api/audit/{name}")
async def audit_for_request(name: str):
    if not _valid_name(name):
        return JSONResponse({"error": "Invalid request name"}, status_code=400)
    return JSONResponse(get_audit_log(name))


# ---------------------------------------------------------------------------
# Lightweight requests count (for admin auto-refresh polling)
# ---------------------------------------------------------------------------

@app.get("/api/requests/count")
async def api_requests_count(request: Request):
    """Returns the current count of access requests — used by admin page to detect new arrivals."""
    if _require_admin(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    reqs = list_access_requests()
    return JSONResponse({"count": len(reqs)})


@app.get("/api/requests")
async def api_get_requests(request: Request):
    """Returns all access requests as JSON for admin live-update."""
    if _require_admin(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    reqs = list_access_requests()
    result = []
    for ar in reqs:
        spec   = ar.get("spec", {})
        status = ar.get("status", {})
        result.append({
            "name":        ar["metadata"]["name"],
            "cluster":     ar.get("_cluster", ""),
            "clusterDisplay": ar.get("_clusterDisplay", ar.get("_cluster", "")),
            "requester":   spec.get("requester", ""),
            "namespaces":  spec.get("namespaces") or ([spec.get("namespace")] if spec.get("namespace") else []),
            "reason":      spec.get("reason", ""),
            "ttlSeconds":  spec.get("ttlSeconds", 3600),
            "phase":       status.get("phase", "Pending"),
            "approvedBy":  status.get("approvedBy", ""),
            "expiresAt":   status.get("expiresAt", ""),
            "createdAt":   ar["metadata"].get("creationTimestamp", ""),
        })
    return JSONResponse({"requests": result})


# ---------------------------------------------------------------------------
# User quick commands CRUD
# ---------------------------------------------------------------------------

@app.get("/api/quick-commands")
async def api_get_quick_commands(request: Request):
    email, _ = _get_user(request)
    if not email:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)
    if not db_enabled:
        return JSONResponse({"commands": [], "db_enabled": False})
    return JSONResponse({"commands": get_user_quick_commands(email), "db_enabled": True})


@app.post("/api/quick-commands")
async def api_create_quick_command(request: Request):
    email, _ = _get_user(request)
    if not email:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)
    body = await request.json()
    label   = (body.get("label") or "").strip()[:100]
    command = (body.get("command") or "").strip()
    if not label or not command:
        return JSONResponse({"error": "label and command are required"}, status_code=400)
    rec = create_user_quick_command(email, label, command)
    if rec is None:
        return JSONResponse({"error": "db unavailable"}, status_code=503)
    return JSONResponse(rec, status_code=201)


@app.put("/api/quick-commands/{cmd_id}")
async def api_update_quick_command(cmd_id: int, request: Request):
    email, _ = _get_user(request)
    if not email:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)
    body = await request.json()
    label   = (body.get("label") or "").strip()[:100]
    command = (body.get("command") or "").strip()
    if not label or not command:
        return JSONResponse({"error": "label and command are required"}, status_code=400)
    ok = update_user_quick_command(email, cmd_id, label, command)
    if not ok:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"id": cmd_id, "label": label, "command": command})


@app.delete("/api/quick-commands/{cmd_id}")
async def api_delete_quick_command(cmd_id: int, request: Request):
    email, _ = _get_user(request)
    if not email:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)
    ok = delete_user_quick_command(email, cmd_id)
    if not ok:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"deleted": cmd_id})


# Phase polling (for status page auto-redirect on revoke/expire)
# ---------------------------------------------------------------------------

@app.get("/api/status/{cluster}/{name}")
async def api_request_phase(cluster: str, name: str):
    """Lightweight endpoint returning just the current phase of an access request."""
    if not _valid_name(name):
        return JSONResponse({"error": "Invalid name"}, status_code=400)
    ar = get_access_request(name, cluster)
    if not ar:
        return JSONResponse({"phase": "NotFound"})
    return JSONResponse({"phase": ar.get("status", {}).get("phase", "Pending")})


# ---------------------------------------------------------------------------
# TTL extension
# ---------------------------------------------------------------------------

@app.post("/extend/{cluster}/{name}")
async def extend_access(cluster: str, name: str, request: Request):
    """Extend the expiresAt on an Active AccessRequest. Admin only."""
    if (err := _require_admin(request)):
        return err
    if not _valid_cluster(cluster) or not _valid_name(name):
        return JSONResponse({"ok": False, "error": "Invalid parameters"}, status_code=400)

    body = await request.json()
    extra_seconds = int(body.get("seconds", 3600))
    if extra_seconds <= 0:
        return JSONResponse({"ok": False, "error": "seconds must be > 0"}, status_code=400)

    ar = get_access_request(name, cluster)
    if not ar:
        return JSONResponse({"ok": False, "error": f"Request '{name}' not found."}, status_code=404)
    if ar.get("status", {}).get("phase") != Phase.ACTIVE:
        return JSONResponse({"ok": False, "error": "Request is not Active"}, status_code=409)

    now = datetime.now(timezone.utc)
    current_expires_str = ar.get("status", {}).get("expiresAt", "")
    try:
        current_expires = datetime.fromisoformat(current_expires_str.replace("Z", "+00:00"))
    except Exception:
        current_expires = now

    # Never shorten — extend from max(now, current_expires)
    base = max(now, current_expires)
    new_expires = base + timedelta(seconds=extra_seconds)

    # Cap at MAX_TTL_SECONDS from now
    max_expires = now + timedelta(seconds=MAX_TTL_SECONDS)
    if new_expires > max_expires:
        new_expires = max_expires

    new_expires_iso = new_expires.isoformat()

    caller, _ = _get_user(request)
    caller = caller or "admin"
    try:
        _patch_status(name, {"expiresAt": new_expires_iso})
        logger.info(f"⏰ [{name}] TTL extended by {caller}: new expiresAt={new_expires_iso}")
        log_audit(name, "access.extended", actor=caller,
                  detail=f"+{extra_seconds}s → {new_expires_iso}")
    except ApiException as e:
        logger.error(f"💥 Failed to extend TTL for {name}: {e}")
        return JSONResponse({"ok": False, "error": "Failed to patch CRD status"}, status_code=500)

    return JSONResponse({"ok": True, "expiresAt": new_expires_iso})


# ---------------------------------------------------------------------------
# Logs page + system log streaming
# ---------------------------------------------------------------------------

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    if (err := _require_admin(request)):
        return err
    ctx = _base_context(request)
    return templates.TemplateResponse("logs.html", ctx)


@app.get("/api/system-logs/{component}")
async def stream_system_logs(component: str, tail: int = 200):
    """SSE endpoint: stream logs from the controller or webui pod."""
    if component not in ("controller", "webui"):
        return JSONResponse({"error": "component must be 'controller' or 'webui'"}, status_code=400)
    tail = max(10, min(tail, 5000))

    from k8s import _get_central_core_v1
    try:
        core_v1 = _get_central_core_v1()
        pods = core_v1.list_namespaced_pod(
            namespace=JANUS_NAMESPACE,
            label_selector=f"app.kubernetes.io/name=janus-{component}",
        )
        if not pods.items:
            async def _no_pod():
                yield f"data: [no {component} pod found in {JANUS_NAMESPACE}]\n\n"
            return StreamingResponse(_no_pod(), media_type="text/event-stream")
        pod_name = pods.items[0].metadata.name
    except Exception as e:
        async def _err_gen(msg=str(e)):
            yield f"data: [error resolving pod: {msg}]\n\n"
        return StreamingResponse(_err_gen(), media_type="text/event-stream")

    async def _log_generator():
        loop = asyncio.get_event_loop()

        def _fetch_tail():
            try:
                return core_v1.read_namespaced_pod_log(
                    name=pod_name, namespace=JANUS_NAMESPACE,
                    tail_lines=tail, timestamps=False,
                )
            except Exception as exc:
                return f"[error: {exc}]"

        # Send historical tail first
        lines = await loop.run_in_executor(None, _fetch_tail)
        for line in (lines or "").splitlines():
            yield f"data: {line}\n\n"

        # Then follow live
        def _stream_follow():
            try:
                resp = core_v1.read_namespaced_pod_log(
                    name=pod_name, namespace=JANUS_NAMESPACE,
                    follow=True, _preload_content=False,
                )
                return resp
            except Exception:
                return None

        resp = await loop.run_in_executor(None, _stream_follow)
        if resp is None:
            yield "data: [could not open log stream]\n\n"
            return

        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

        def _safe_put(item):
            try:
                queue.put_nowait(item)
            except asyncio.QueueFull:
                pass  # drop line — consumer is too slow, prevents cascading errors

        def _reader():
            try:
                for chunk in resp:
                    text = chunk.decode("utf-8", errors="replace") if isinstance(chunk, (bytes, bytearray)) else str(chunk)
                    for line in text.splitlines():
                        if line:
                            loop.call_soon_threadsafe(_safe_put, line)
            except Exception as exc:
                loop.call_soon_threadsafe(_safe_put, f"[stream ended: {exc}]")
            finally:
                try:
                    resp.close()
                except Exception:
                    pass
                loop.call_soon_threadsafe(_safe_put, None)  # sentinel

        loop.run_in_executor(None, _reader)
        while True:
            item = await queue.get()
            if item is None:
                break
            yield f"data: {item}\n\n"

    return StreamingResponse(_log_generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/healthz")
async def healthz():
    health: dict = {"status": "ok", "db": "disabled", "version": APP_VERSION}
    if db_enabled:
        try:
            from db import get_session
            from sqlalchemy import text as _text
            with get_session() as session:
                if session:
                    session.execute(_text("SELECT 1"))
                    health["db"] = "ok"
                else:
                    health["db"] = "unavailable"
        except Exception as e:
            health["db"] = f"error: {e}"
            health["status"] = "degraded"
    return JSONResponse(health, status_code=200 if health["status"] == "ok" else 207)
