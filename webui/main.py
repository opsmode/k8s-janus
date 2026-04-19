"""K8s-Janus WebUI — app entry point.

Registers middleware, exception handlers, startup event, and mounts all routers.
Route implementations live in routers/; shared logic in core/; DB in db/.
"""
import asyncio
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from core.config import (
    OIDC_ENABLED, LOCAL_AUTH_ENABLED, OIDC_SESSION_SECRET,
    APP_VERSION, BUILD_DATE, OIDC_PROVIDER,
)
from core.logging_setup import logger
from core.templates import templates
from db import init_db
from k8s import JANUS_NAMESPACE, EXCLUDED_NAMESPACES
import local_auth

from routers import auth, mfa
from routers import setup as setup_router
from routers import admin, access_requests, terminal, audit, misc

# ---------------------------------------------------------------------------
# App + static files
# ---------------------------------------------------------------------------
_APP_DIR = os.environ.get("APP_DIR", "/app")
app = FastAPI(title="K8s-Janus", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=f"{_APP_DIR}/static"), name="static")

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
_AUTH_PUBLIC_PATHS = {"/login", "/login/redirect", "/auth/callback", "/healthz", "/logout",
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


class _OIDCAuthMiddleware:
    """Pure ASGI auth middleware — works for both HTTP and WebSocket connections."""
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        if not OIDC_ENABLED and not LOCAL_AUTH_ENABLED:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in _AUTH_PUBLIC_PATHS or path.startswith("/static") or path.startswith("/setup"):
            await self.app(scope, receive, send)
            return

        # Read session populated by SessionMiddleware (already ran as outer layer)
        from starlette.requests import HTTPConnection
        conn = HTTPConnection(scope)
        if not conn.session.get("user_email"):
            if scope["type"] == "websocket":
                # Close WebSocket with policy violation code
                await send({"type": "websocket.close", "code": 4401, "reason": "unauthenticated"})
                return
            _json_prefixes = ("/api/", "/ws/", "/approve/", "/deny/", "/revoke/", "/cancel/", "/extend/")
            headers = dict(scope.get("headers", []))
            accept = headers.get(b"accept", b"").decode()
            if path.startswith(_json_prefixes) or accept.startswith("application/json"):
                body = b'{"error":"unauthenticated"}'
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json"),
                                        (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
                return
            location = f"/login?next={path}".encode()
            await send({"type": "http.response.start", "status": 302,
                        "headers": [(b"location", location)]})
            await send({"type": "http.response.body", "body": b""})
            return

        await self.app(scope, receive, send)


# Middleware stack — LIFO: last added = outermost = runs first
app.add_middleware(_OIDCAuthMiddleware)
app.add_middleware(_SecurityHeadersMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=OIDC_SESSION_SECRET,
    https_only=True,
    same_site="lax",
    max_age=86400,
)

# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------

@app.exception_handler(404)
async def _not_found(request: Request, exc):
    return templates.TemplateResponse(request, "404.html", {"path": request.url.path}, status_code=404)


@app.exception_handler(500)
async def _server_error(request: Request, exc):
    return templates.TemplateResponse(request, "500.html", {"detail": str(exc)}, status_code=500)

# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def on_startup():
    init_db()
    if OIDC_ENABLED:
        logger.info(f"🔐 OIDC auth enabled — provider: {OIDC_PROVIDER or 'custom'} version={APP_VERSION} built={BUILD_DATE}")
    elif LOCAL_AUTH_ENABLED:
        logger.info(f"🔐 K8s-Janus WebUI {APP_VERSION} (built {BUILD_DATE}) — local auth enabled")

        async def _bootstrap_admin():
            generated = await asyncio.get_event_loop().run_in_executor(
                None, local_auth.ensure_admin_user
            )
            if generated:
                secret_stored = False
                secret_name = "janus-admin-bootstrap"
                try:
                    from kubernetes import client as _k8s, config as _k8sc
                    try:
                        _k8sc.load_incluster_config()
                    except Exception:
                        _k8sc.load_kube_config()
                    core = _k8s.CoreV1Api()
                    body = _k8s.V1Secret(
                        metadata=_k8s.V1ObjectMeta(
                            name=secret_name,
                            namespace=JANUS_NAMESPACE,
                            annotations={"janus/info": "Delete this Secret after logging in and changing the admin password."},
                        ),
                        string_data={"email": "admin@local", "password": generated},
                    )
                    try:
                        core.create_namespaced_secret(namespace=JANUS_NAMESPACE, body=body)
                    except _k8s.exceptions.ApiException:
                        core.patch_namespaced_secret(name=secret_name, namespace=JANUS_NAMESPACE, body=body)
                    secret_stored = True
                except Exception as e:
                    logger.warning(f"Could not store admin bootstrap Secret: {e}")

                logger.warning("=" * 60)
                logger.warning("🔑 LOCAL AUTH — default admin account created")
                logger.warning("   email : admin@local")
                if secret_stored:
                    logger.warning(f"   password stored in Secret '{secret_name}' — retrieve with:")
                    logger.warning(f"   kubectl get secret {secret_name} -n {JANUS_NAMESPACE} "
                                   "-o jsonpath='{.data.password}' | base64 -d")
                else:
                    logger.warning(f"   password: {generated}")
                logger.warning("   Change this password via Admin → Users, then delete the Secret.")
                logger.warning("=" * 60)

        asyncio.ensure_future(_bootstrap_admin())
    else:
        logger.info(f"🚀 K8s-Janus WebUI {APP_VERSION} (built {BUILD_DATE}) — auth via ingress/oauth2-proxy (X-Forwarded-Email)")

    if EXCLUDED_NAMESPACES:
        logger.info(f"🚫 Excluded namespaces: {sorted(EXCLUDED_NAMESPACES)}")
    else:
        logger.info("ℹ️  No namespaces excluded (EXCLUDED_NAMESPACES not set)")

    async def _db_cleanup_loop():
        while True:
            await asyncio.sleep(86400)
            try:
                from db import purge_old_records
                purge_old_records(days=30)
            except Exception as e:
                logger.error(f"💥 DB cleanup failed: {e}")
    asyncio.ensure_future(_db_cleanup_loop())

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(auth.router)
app.include_router(mfa.router)
app.include_router(setup_router.router)
app.include_router(admin.router)
app.include_router(access_requests.router)
app.include_router(terminal.router)
app.include_router(audit.router)
app.include_router(misc.router)
