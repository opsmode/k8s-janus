import asyncio
import os
import re
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, Request, Form, WebSocket, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from kubernetes.client.rest import ApiException

from db import (
    init_db, upsert_request, log_audit, get_audit_log,
    get_recent_audit_logs, get_session_commands, _now, db_enabled,
)
from k8s import (
    get_api_clients, get_cluster_config, get_allowed_namespaces,
    get_access_request, list_access_requests, read_token_secret,
    CLUSTERS, CRD_GROUP, CRD_VERSION, JANUS_NAMESPACE,
)
from terminal_ws import terminal_websocket_handler, broadcast_to_all, notify_revoked

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
    _SUPPRESS = ("GET /healthz", "/api/terminal/", "/api/audit", "/api/status/")

    def filter(self, record):
        msg = record.getMessage()
        if any(s in msg for s in self._SUPPRESS):
            return False
        # Drop 404s — scanner/bot noise hitting non-existent paths
        if '" 404 ' in msg:
            return False
        return True


logging.getLogger("uvicorn.access").addFilter(_AccessLogFilter())

# ---------------------------------------------------------------------------
# Phase enum
# ---------------------------------------------------------------------------

class Phase(str, Enum):
    PENDING  = "Pending"
    APPROVED = "Approved"
    ACTIVE   = "Active"
    DENIED   = "Denied"
    EXPIRED  = "Expired"
    REVOKED  = "Revoked"
    FAILED   = "Failed"

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


_SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (b"content-security-policy", (
        b"default-src 'self'; "
        b"script-src 'self' https://cdn.jsdelivr.net https://unpkg.com 'unsafe-inline'; "
        b"style-src 'self' https://cdn.jsdelivr.net https://unpkg.com https://fonts.googleapis.com 'unsafe-inline'; "
        b"font-src 'self' https://cdn.jsdelivr.net https://unpkg.com https://fonts.gstatic.com; "
        b"img-src 'self' data:; "
        b"connect-src 'self' wss: ws:;"
    )),
]


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    for name, value in _SECURITY_HEADERS:
        response.headers[name.decode()] = value.decode()
    return response


@app.on_event("startup")
async def on_startup():
    import asyncio
    init_db()
    if AUTH_ENABLED:
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


def _is_admin(email: str) -> bool:
    # Auth disabled → everyone is admin regardless of email lists
    if not AUTH_ENABLED:
        return True
    e = email.lower()
    return e in ADMIN_EMAILS


def _get_user(request: Request) -> tuple[str, str]:
    """Return (email, name) from proxy headers set by oauth2-proxy/ingress.

    When AUTH_ENABLED=false (no auth proxy in front), headers will be absent
    and the app runs in open mode — any user can submit requests, admin routes
    are open if ADMIN_EMAILS is empty.
    """
    email = request.headers.get("X-Forwarded-Email", "")
    name  = request.headers.get("X-Forwarded-Preferred-Username", email)
    return email, name


def _base_context(request: Request) -> dict:
    user_email, user_name = _get_user(request)
    return {
        "request": request,
        "clusters": CLUSTERS,
        "user_email": user_email,
        "user_name": user_name,
        "is_devops": _is_admin(user_email),
        "is_admin": _is_admin(user_email),
        "default_ttl": DEFAULT_TTL_SECONDS // 3600,
        "max_ttl": MAX_TTL_SECONDS // 3600,
    }


def _require_admin(request: Request):
    """Return 403 if caller is not in ADMIN_EMAILS, else None.
    When AUTH_ENABLED=false, skip the check entirely.
    """
    if not AUTH_ENABLED:
        return None
    user_email, _ = _get_user(request)
    if not _is_admin(user_email):
        return HTMLResponse("<h2>403 Forbidden — admin access required.</h2>", status_code=403)
    return None


def _patch_status(name: str, body: dict) -> None:
    """Patch an AccessRequest CRD status on the central cluster."""
    custom_api, _ = get_api_clients(CLUSTERS[0]["name"])
    custom_api.patch_cluster_custom_object_status(
        group=CRD_GROUP, version=CRD_VERSION, plural="accessrequests", name=name,
        body={"status": body},
    )


def _token_client(name: str, cluster: str):
    """Return (core_v1_with_token, namespace) for the given AccessRequest."""
    from k8s import get_client_with_token
    ar = get_access_request(name, cluster)
    if not ar:
        return None, None
    if ar.get("status", {}).get("phase") != Phase.ACTIVE:
        return None, None
    namespace   = ar.get("spec", {}).get("namespace", "")
    secret_name = ar.get("status", {}).get("tokenSecret", "")
    if not namespace or not secret_name:
        return None, None
    try:
        token, server, ca = read_token_secret(secret_name)
    except Exception as e:
        logger.error(f"🔑 Failed to read token secret {secret_name}: {e}")
        return None, None
    core_v1 = get_client_with_token(cluster, token, server, ca)
    return core_v1, namespace


# ---------------------------------------------------------------------------
# Setup wizard routes
# ---------------------------------------------------------------------------

@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    """Serve the setup wizard (always accessible from the admin page)."""
    return templates.TemplateResponse("setup.html", {"request": request})


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


@app.post("/setup/run")
async def setup_run(request: Request):
    """Kick off the setup background task for a previously uploaded kubeconfig."""
    body = await request.json()
    session_id    = body.get("session_id", "")
    central       = body.get("central", "")
    remotes       = body.get("remotes", [])

    if not session_id or session_id not in _setup_kubeconfigs:
        return JSONResponse({"error": "Session not found. Please re-upload your kubeconfig."}, status_code=400)
    if not central:
        return JSONResponse({"error": "No central cluster selected."}, status_code=400)

    kc = _setup_kubeconfigs[session_id]
    q: asyncio.Queue = asyncio.Queue()
    _setup_queues[session_id] = q
    asyncio.ensure_future(_run_setup_task(session_id, kc, central, remotes, JANUS_NAMESPACE, q))
    return JSONResponse({"ok": True})


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
    remotes: list,
    janus_namespace: str,
    q: asyncio.Queue,
) -> None:
    """Background coroutine: runs the setup generator and pushes lines to the queue."""
    try:
        from setup import run_setup
        async for line in run_setup(kubeconfig, central, remotes, janus_namespace):
            await q.put(line)
        # Invalidate setup-complete cache so next request re-checks
        _setup_complete_cache["result"] = None
        _setup_complete_cache["expires"] = 0.0
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
    return templates.TemplateResponse("index.html", ctx)


@app.get("/admin", response_class=HTMLResponse)
async def admin(request: Request):
    if (err := _require_admin(request)):
        return err
    ctx = _base_context(request)
    ctx["access_requests"] = list_access_requests()
    ctx["is_admin"] = True
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


@app.get("/namespaces/{cluster_name}", response_class=HTMLResponse)
async def namespaces(cluster_name: str):
    if not _valid_cluster(cluster_name):
        return JSONResponse([], status_code=400)
    logger.info(f"📡 API request: GET /namespaces/{cluster_name}")
    ns_list = get_allowed_namespaces(cluster_name)  # returns [] on error
    logger.info(f"📤 Returning {len(ns_list)} namespaces for cluster {cluster_name}")
    return JSONResponse(ns_list)


@app.post("/request", response_class=HTMLResponse)
async def submit_request(
    request: Request,
    cluster: str   = Form(...),
    namespace: str = Form(...),
    reason: str    = Form(...),
    ttl_hours: int = Form(...),
    requester: str = Form(default=""),
):
    user_from_auth, _ = _get_user(request)
    requester = user_from_auth or requester
    if not requester:
        return HTMLResponse("<h2>Unauthorized: no authenticated user found.</h2>", status_code=401)

    if not get_cluster_config(cluster):
        return HTMLResponse(f"<h2>Unknown cluster: {cluster}</h2>", status_code=400)

    if not _valid_ns(namespace):
        return HTMLResponse(f"<h2>Invalid namespace: {namespace}</h2>", status_code=400)

    reason = reason.strip()[:500]

    # Validate TTL — must be a positive number within bounds
    if ttl_hours < 1:
        return HTMLResponse("<h2>Invalid TTL: must be at least 1 hour.</h2>", status_code=400)
    ttl_seconds = ttl_hours * 3600
    if ttl_seconds > MAX_TTL_SECONDS:
        ttl_seconds = MAX_TTL_SECONDS
        logger.info(f"⏱️  TTL capped to {MAX_TTL_SECONDS}s for {requester}")

    allowed = get_allowed_namespaces(cluster)
    if namespace not in allowed:
        ctx = _base_context(request)
        ctx["error"] = f"Namespace '{namespace}' is not allowed."
        ctx["access_requests"] = [
            ar for ar in list_access_requests()
            if ar.get("spec", {}).get("requester", "").lower() == requester.lower()
        ]
        ctx["is_admin"] = False
        return templates.TemplateResponse("index.html", ctx, status_code=400)

    ts = datetime.now(timezone.utc).strftime("%m%d%H%M%S")
    safe_requester = requester.split("@")[0].lower().replace(".", "-")[:20]
    name = f"k8s-janus-{safe_requester}-{ts}"

    body = {
        "apiVersion": f"{CRD_GROUP}/{CRD_VERSION}",
        "kind": "AccessRequest",
        "metadata": {"name": name},
        "spec": {
            "requester": requester,
            "namespace": namespace,
            "reason": reason,
            "ttlSeconds": ttl_seconds,
            "cluster": cluster,
        },
    }

    # Rate limit: max 10 pending/approved/active requests per user
    all_requests = list_access_requests()
    active_count = sum(
        1 for ar in all_requests
        if ar.get("spec", {}).get("requester") == requester
        and ar.get("status", {}).get("phase", "") in (Phase.PENDING, Phase.APPROVED, Phase.ACTIVE)
    )
    if active_count >= 10:
        ctx = _base_context(request)
        ctx["error"] = "Too many active requests. Wait for existing requests to expire or be revoked."
        ctx["access_requests"] = [ar for ar in all_requests if ar.get("spec", {}).get("requester", "").lower() == requester.lower()]
        ctx["is_admin"] = False
        return templates.TemplateResponse("index.html", ctx, status_code=429)

    # Block duplicate active/pending requests
    for ar in all_requests:
        ar_spec  = ar.get("spec", {})
        ar_phase = ar.get("status", {}).get("phase", "")
        if (
            ar_spec.get("requester") == requester
            and ar_spec.get("cluster") == cluster
            and ar_spec.get("namespace") == namespace
            and ar_phase in (Phase.PENDING, Phase.APPROVED, Phase.ACTIVE)
        ):
            existing_name = ar["metadata"]["name"]
            logger.info(f"🚫 Duplicate request blocked for {requester} — existing {existing_name} is {ar_phase}")
            return RedirectResponse(url=f"/status/{cluster}/{existing_name}", status_code=303)

    try:
        central_api, _ = get_api_clients(CLUSTERS[0]["name"])
        central_api.create_cluster_custom_object(
            group=CRD_GROUP, version=CRD_VERSION, plural="accessrequests", body=body,
        )
        logger.info(f"🎫 Created AccessRequest {name} for {requester} on cluster {cluster}")
        upsert_request(
            name,
            cluster=cluster, namespace=namespace, requester=requester,
            ttl_seconds=ttl_seconds, reason=reason, phase=Phase.PENDING, created_at=_now(),
        )
        log_audit(name, "request.created", actor=requester,
                  detail=f"cluster={cluster} ns={namespace} ttl={ttl_seconds}s")
    except ApiException as e:
        logger.error(f"💥 Failed to create AccessRequest: {e}")
        ctx = _base_context(request)
        ctx["error"] = "Failed to submit request. Please try again."
        ctx["access_requests"] = [
            ar for ar in all_requests
            if ar.get("spec", {}).get("requester", "").lower() == requester.lower()
        ]
        ctx["is_admin"] = False
        return templates.TemplateResponse("index.html", ctx, status_code=500)

    return RedirectResponse(url=f"/status/{cluster}/{name}", status_code=303)


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
    user_email, user_name = _get_user(request)
    return templates.TemplateResponse("status.html", {
        "request": request,
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
        "user_name": user_name,
    })


@app.get("/callback", response_class=HTMLResponse)
async def callback(request: Request, action: str, name: str, cluster: str = ""):
    if not cluster:
        cluster = CLUSTERS[0]["name"]
    ar = get_access_request(name, cluster)
    if not ar:
        return HTMLResponse(f"<h2>Request '{name}' not found on cluster '{cluster}'.</h2>", status_code=404)

    cluster_cfg     = get_cluster_config(cluster)
    cluster_display = cluster_cfg.get("displayName", cluster) if cluster_cfg else cluster
    current_phase   = ar.get("status", {}).get("phase", "")

    if current_phase not in (Phase.PENDING, ""):
        return templates.TemplateResponse("callback.html", {
            "request": request,
            "cluster_name": cluster_display,
            "name": name, "action": action,
            "already_actioned": True, "current_phase": current_phase,
            "spec": ar.get("spec", {}),
        })

    if action == "deny":
        return templates.TemplateResponse("deny-confirm.html", {
            "request": request,
            "cluster_name": cluster_display,
            "name": name, "cluster": cluster,
            "spec": ar.get("spec", {}),
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
        return HTMLResponse("<h2>Error updating request. Please try again.</h2>", status_code=500)

    return templates.TemplateResponse("callback.html", {
        "request": request,
        "cluster_name": cluster_display,
        "name": name, "action": "approve",
        "already_actioned": False, "current_phase": Phase.APPROVED,
        "spec": ar.get("spec", {}),
    })


@app.post("/deny-confirm", response_class=HTMLResponse)
async def deny_confirm(request: Request, name: str = Form(...), cluster: str = Form(...), denial_reason: str = Form("")):
    if (err := _require_admin(request)):
        return err
    denial_reason = denial_reason.strip()[:500]
    ar = get_access_request(name, cluster)
    if not ar:
        return HTMLResponse(f"<h2>Request '{name}' not found on cluster '{cluster}'.</h2>", status_code=404)

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
        return HTMLResponse("<h2>Error updating request. Please try again.</h2>", status_code=500)

    return templates.TemplateResponse("callback.html", {
        "request": request,
        "cluster_name": cluster_display,
        "name": name, "action": "deny",
        "already_actioned": False, "current_phase": Phase.DENIED,
        "spec": ar.get("spec", {}),
    })


@app.post("/approve/{cluster}/{name}")
async def approve(request: Request, cluster: str, name: str):
    if _require_admin(request):
        return JSONResponse({"ok": False, "error": "403 Forbidden"}, status_code=403)
    ar = get_access_request(name, cluster)
    if not ar:
        return JSONResponse({"ok": False, "error": f"Request '{name}' not found."}, status_code=404)
    current_phase = ar.get("status", {}).get("phase", "")
    if current_phase != Phase.PENDING:
        return JSONResponse({"ok": False, "error": f"Request is already {current_phase}."}, status_code=409)
    approver, _ = _get_user(request)
    approver = approver or "admin"
    try:
        _patch_status(name, {
            "phase": Phase.APPROVED,
            "approvedBy": approver,
            "approvedAt": datetime.now(timezone.utc).isoformat(),
        })
        logger.info(f"✅ AccessRequest {name} on {cluster} Approved by {approver}")
        upsert_request(name, phase=Phase.APPROVED, approved_by=approver, approved_at=_now(),
                       cluster=cluster, namespace=ar.get("spec", {}).get("namespace", ""),
                       requester=ar.get("spec", {}).get("requester", ""),
                       ttl_seconds=ar.get("spec", {}).get("ttlSeconds", 3600), created_at=_now())
        log_audit(name, "request.approved", actor=approver, detail=f"cluster={cluster}")
    except ApiException as e:
        logger.error(f"💥 Failed to approve AccessRequest {name}: {e}")
        return JSONResponse({"ok": False, "error": "Failed to approve request"}, status_code=500)
    return JSONResponse({"ok": True, "phase": Phase.APPROVED})


@app.post("/deny/{cluster}/{name}")
async def deny(request: Request, cluster: str, name: str, denial_reason: str = Form("")):
    if _require_admin(request):
        return JSONResponse({"ok": False, "error": "403 Forbidden"}, status_code=403)
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
        return HTMLResponse(f"<h2>Request '{name}' not found.</h2>", status_code=404)
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
        return HTMLResponse("<h2>Error revoking request. Please try again.</h2>", status_code=500)
    return RedirectResponse(url="/admin", status_code=303)



@app.get("/terminal/{cluster}/{name}", response_class=HTMLResponse)
async def terminal(request: Request, cluster: str, name: str):
    ar = get_access_request(name, cluster)
    if not ar:
        return HTMLResponse(f"<h2>Request '{name}' not found on cluster '{cluster}'.</h2>", status_code=404)
    phase = ar.get("status", {}).get("phase", "")
    if phase != Phase.ACTIVE:
        return HTMLResponse(f"<h2>Access not active. Current phase: {phase}</h2>", status_code=403)
    cluster_cfg     = get_cluster_config(cluster)
    cluster_display = cluster_cfg.get("displayName", cluster) if cluster_cfg else cluster
    _, user_name    = _get_user(request)
    return templates.TemplateResponse("terminal.html", {
        "request": request,
        "cluster": cluster,
        "cluster_display": cluster_display,
        "request_name": name,
        "namespace": ar.get("spec", {}).get("namespace", ""),
        "expires_at": ar.get("status", {}).get("expiresAt", ""),
        "user_name": user_name,
    })


@app.websocket("/ws/terminal/{cluster}/{name}")
async def terminal_websocket(websocket: WebSocket, cluster: str, name: str):
    await terminal_websocket_handler(websocket, cluster, name)


# ---------------------------------------------------------------------------
# Terminal API (pods / logs / events)
# ---------------------------------------------------------------------------

@app.get("/api/terminal/{cluster}/{name}/pods")
async def list_pods(cluster: str, name: str):
    if not _valid_cluster(cluster) or not _valid_name(name):
        return JSONResponse({"error": "Invalid parameters", "pods": []}, status_code=400)
    core_v1, namespace = _token_client(name, cluster)
    if core_v1 is None:
        return JSONResponse({"error": "Access not active or request not found", "pods": []})
    try:
        pods = core_v1.list_namespaced_pod(namespace=namespace)
        DISTROLESS = ("distroless", "scratch", "gcr.io/distroless", "chainguard")
        pod_list = []
        for pod in pods.items:
            images   = [c.image or "" for c in pod.spec.containers]
            has_shell = not any(any(d in img.lower() for d in DISTROLESS) for img in images)
            pod_list.append({"name": pod.metadata.name, "status": pod.status.phase, "hasShell": has_shell})
        return JSONResponse({"pods": pod_list, "error": None})
    except Exception as e:
        logger.error(f"💥 Failed to list pods in {cluster}/{namespace}: {e}")
        return JSONResponse({"error": "Failed to list pods", "pods": []})


@app.get("/api/terminal/{cluster}/{name}/{pod}/logs")
async def get_pod_logs(cluster: str, name: str, pod: str):
    if not _valid_cluster(cluster) or not _valid_name(name):
        return JSONResponse({"error": "Invalid parameters", "logs": ""}, status_code=400)
    core_v1, namespace = _token_client(name, cluster)
    if core_v1 is None:
        return JSONResponse({"error": "Access not active or request not found", "logs": ""})
    try:
        logs = core_v1.read_namespaced_pod_log(name=pod, namespace=namespace, tail_lines=100, timestamps=True)
        return JSONResponse({"logs": logs or "", "error": None})
    except Exception as e:
        logger.error(f"💥 Failed to get logs for {cluster}/{namespace}/{pod}: {e}")
        return JSONResponse({"error": "Failed to retrieve pod logs", "logs": ""})


@app.get("/api/terminal/{cluster}/{name}/{pod}/events")
async def get_pod_events(cluster: str, name: str, pod: str):
    if not _valid_cluster(cluster) or not _valid_name(name):
        return JSONResponse({"error": "Invalid parameters", "events": []}, status_code=400)
    core_v1, namespace = _token_client(name, cluster)
    if core_v1 is None:
        return JSONResponse({"error": "Access not active or request not found", "events": []})
    try:
        events = core_v1.list_namespaced_event(
            namespace=namespace, field_selector=f"involvedObject.name={pod}"
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
            logger.warning(f"⛔ Events forbidden for {cluster}/{namespace}/{pod}")
            return JSONResponse({"events": [], "forbidden": True, "error": None})
        logger.error(f"💥 Failed to get events for {cluster}/{namespace}/{pod}: {e}")
        return JSONResponse({"error": "Failed to retrieve pod events", "events": []})
    except Exception as e:
        logger.error(f"💥 Failed to get events for {cluster}/{namespace}/{pod}: {e}")
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


@app.get("/api/commands/{name}")
async def commands_for_request(request: Request, name: str):
    """Return typed commands for an access request. Caller must be the requester or admin."""
    if not _valid_name(name):
        return JSONResponse({"error": "Invalid request name"}, status_code=400)
    user_email, _ = _get_user(request)
    ar = get_access_request(name, CLUSTERS[0]["name"])
    if ar is None:
        # Try all clusters
        for c in CLUSTERS:
            ar = get_access_request(name, c["name"])
            if ar:
                break
    if ar is None:
        return JSONResponse({"error": "Not found", "commands": []}, status_code=404)
    requester = ar.get("spec", {}).get("requester", "").lower()
    if user_email.lower() != requester and not _is_admin(user_email):
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    return JSONResponse(get_session_commands(name))


# ---------------------------------------------------------------------------
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
# Broadcast (admin only)
# ---------------------------------------------------------------------------

@app.post("/admin/broadcast")
async def admin_broadcast(request: Request, message: str = Form(...)):
    if (err := _require_admin(request)):
        return err
    sender, _ = _get_user(request)
    sender    = sender or "admin"
    message   = message.strip()[:500]
    if not message:
        return RedirectResponse(url="/admin", status_code=303)
    count = await broadcast_to_all(message, sender)
    logger.info(f"📣 Broadcast from {sender} to {count} terminal sessions: {message[:80]}")
    log_audit("system", "broadcast.sent", actor=sender, detail=f"recipients={count} msg={message[:100]}")
    if count == 0:
        logger.warning("📣 Broadcast sent but no active terminal sessions connected")
    return RedirectResponse(url="/admin", status_code=303)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/healthz")
async def healthz():
    health: dict = {"status": "ok", "db": "disabled"}
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


__version__ = "0.2.0"
