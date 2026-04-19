"""Misc router — GET /, /version, /healthz, /api/quick-commands/*, /api/status/*."""
import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

from core.auth import _base_context, _get_user, _is_admin
from core.config import APP_VERSION, BUILD_DATE
from core.k8s_helpers import _valid_name
from core.templates import templates
from db import (
    db_enabled,
    get_user_quick_commands, create_user_quick_command,
    update_user_quick_command, delete_user_quick_command,
)
from k8s import list_access_requests, get_access_request

logger = logging.getLogger("k8s-janus-webui")

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    ctx = _base_context(request)
    user_email = ctx["user_email"]
    if _is_admin(user_email):
        return RedirectResponse(url="/admin", status_code=302)
    all_requests = list_access_requests()
    user_reqs = [
        ar for ar in all_requests
        if ar.get("spec", {}).get("requester", "").lower() == user_email.lower()
    ]
    ctx["access_requests"] = user_reqs
    ctx["is_admin"] = False
    # Pre-flatten for the JS history recorder (avoids serializing raw k8s dicts)
    ctx["js_access_requests"] = [
        {
            "name":           ar["metadata"]["name"],
            "cluster":        ar.get("_cluster", ""),
            "clusterDisplay": ar.get("_clusterDisplay", ar.get("_cluster", "")),
            "namespace":      (ar.get("spec", {}).get("namespaces") or [ar.get("spec", {}).get("namespace", "")])[0],
            "phase":          ar.get("status", {}).get("phase", "Pending"),
            "requester":      ar.get("spec", {}).get("requester", ""),
        }
        for ar in user_reqs
    ]
    return templates.TemplateResponse(request, "index.html", ctx)


@router.get("/api/status/{cluster}/{name}")
async def api_request_phase(cluster: str, name: str):
    if not _valid_name(name):
        return JSONResponse({"error": "Invalid name"}, status_code=400)
    ar = get_access_request(name, cluster)
    if not ar:
        return JSONResponse({"phase": "NotFound"})
    return JSONResponse({"phase": ar.get("status", {}).get("phase", "Pending")})


@router.get("/api/quick-commands")
async def api_get_quick_commands(request: Request):
    email, _ = _get_user(request)
    if not email:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)
    if not db_enabled:
        return JSONResponse({"commands": [], "db_enabled": False})
    return JSONResponse({"commands": get_user_quick_commands(email), "db_enabled": True})


@router.post("/api/quick-commands")
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


@router.put("/api/quick-commands/{cmd_id}")
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


@router.delete("/api/quick-commands/{cmd_id}")
async def api_delete_quick_command(cmd_id: int, request: Request):
    email, _ = _get_user(request)
    if not email:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)
    ok = delete_user_quick_command(email, cmd_id)
    if not ok:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"deleted": cmd_id})


@router.get("/version")
async def version_endpoint():
    return JSONResponse({"version": APP_VERSION, "build_date": BUILD_DATE})


@router.get("/healthz")
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
