"""Admin router — /admin, /admin/users, /api/local-users/*, /api/me/password, /api/profile, /api/avatar/*."""
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from core.auth import _base_context, _require_admin, _get_user
from core.config import LOCAL_AUTH_ENABLED
from core.templates import templates
from db import get_user_profile, save_user_profile
import db as _db
from k8s import JANUS_NAMESPACE, list_access_requests
import local_auth
from core.security import invalidate_user_cache

logger = logging.getLogger("k8s-janus-webui")

router = APIRouter()

_memory_profiles: dict[str, dict] = {}


@router.get("/admin", response_class=None)
async def admin(request: Request):
    if (err := _require_admin(request)):
        return err
    ctx = _base_context(request)
    ctx["access_requests"] = list_access_requests()
    ctx["is_admin"] = True
    ctx["janus_namespace"] = JANUS_NAMESPACE
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
    return templates.TemplateResponse(request, "admin.html", ctx)


@router.get("/admin/users", response_class=None)
async def admin_users(request: Request):
    if (err := _require_admin(request)):
        return err
    ctx = _base_context(request)
    ctx["is_admin"] = True
    return templates.TemplateResponse(request, "admin_users.html", ctx)


@router.post("/api/me/password", include_in_schema=False)
async def api_change_my_password(request: Request):
    if not LOCAL_AUTH_ENABLED:
        return JSONResponse({"error": "not available"}, status_code=404)
    user_email, _ = _get_user(request)
    if not user_email:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)
    body = await request.json()
    current_password = str(body.get("current_password", "")).strip()
    new_password = str(body.get("new_password", "")).strip()
    if len(new_password) < 8:
        return JSONResponse({"error": "New password must be at least 8 characters"}, status_code=400)
    if not local_auth.verify_user(user_email, current_password):
        return JSONResponse({"error": "Current password is incorrect"}, status_code=400)
    if not local_auth.set_password(user_email, new_password):
        return JSONResponse({"error": "user not found"}, status_code=404)
    logger.info(f"👤 Password changed by: {user_email}")
    return JSONResponse({"ok": True})


@router.post("/api/profile", include_in_schema=False)
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
    if photo and not photo.startswith("data:image/"):
        photo = ""
    if _db.db_enabled:
        save_user_profile(user_email, name, photo)
    else:
        _memory_profiles[user_email.lower()] = {"name": name, "photo": photo}
    return JSONResponse({"ok": True})


@router.get("/api/avatar/{email}", include_in_schema=False)
async def get_avatar(email: str):
    if _db.db_enabled:
        p = get_user_profile(email)
    else:
        p = _memory_profiles.get(email.lower(), {})
    return JSONResponse({"name": p.get("name", ""), "photo": p.get("photo", "")})


@router.get("/api/local-users", include_in_schema=False)
async def api_list_local_users(request: Request):
    if not LOCAL_AUTH_ENABLED:
        return JSONResponse({"error": "not available"}, status_code=404)
    if _require_admin(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return JSONResponse(local_auth.list_users())


@router.post("/api/local-users", include_in_schema=False)
async def api_create_local_user(request: Request):
    if not LOCAL_AUTH_ENABLED:
        return JSONResponse({"error": "not available"}, status_code=404)
    if _require_admin(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    body = await request.json()
    email    = str(body.get("email", "")).strip().lower()
    name     = str(body.get("name", "")).strip()
    password = str(body.get("password", "")).strip()
    is_admin = bool(body.get("is_admin", False))
    if not email or not name or not password:
        return JSONResponse({"error": "email, name, and password are required"}, status_code=400)
    user = local_auth.create_user(email, name, password, is_admin=is_admin)
    if user is None:
        return JSONResponse({"error": "user already exists"}, status_code=409)
    logger.info(f"👤 Local user created: {email} (admin={is_admin}) by {_get_user(request)[0]}")
    return JSONResponse(user, status_code=201)


@router.delete("/api/local-users/{email:path}", include_in_schema=False)
async def api_delete_local_user(request: Request, email: str):
    if not LOCAL_AUTH_ENABLED:
        return JSONResponse({"error": "not available"}, status_code=404)
    if _require_admin(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    caller, _ = _get_user(request)
    if email.lower() == caller.lower():
        return JSONResponse({"error": "cannot delete your own account"}, status_code=400)
    if not local_auth.delete_user(email):
        return JSONResponse({"error": "user not found"}, status_code=404)
    invalidate_user_cache(email)
    logger.info(f"👤 Local user deleted: {email} by {caller}")
    return JSONResponse({"ok": True})


@router.post("/api/local-users/{email:path}/password", include_in_schema=False)
async def api_reset_local_user_password(request: Request, email: str):
    if not LOCAL_AUTH_ENABLED:
        return JSONResponse({"error": "not available"}, status_code=404)
    if _require_admin(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    body = await request.json()
    new_password = str(body.get("password", "")).strip()
    if len(new_password) < 8:
        return JSONResponse({"error": "password must be at least 8 characters"}, status_code=400)
    if not local_auth.set_password(email, new_password):
        return JSONResponse({"error": "user not found"}, status_code=404)
    logger.info(f"👤 Password reset for: {email} by {_get_user(request)[0]}")
    return JSONResponse({"ok": True})


@router.post("/api/local-users/{email:path}/admin", include_in_schema=False)
async def api_set_local_user_admin(request: Request, email: str):
    if not LOCAL_AUTH_ENABLED:
        return JSONResponse({"error": "not available"}, status_code=404)
    if _require_admin(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    caller, _ = _get_user(request)
    if email.lower() == caller.lower():
        return JSONResponse({"error": "cannot change your own admin status"}, status_code=400)
    body = await request.json()
    is_admin = bool(body.get("is_admin", False))
    if not local_auth.set_admin(email, is_admin):
        return JSONResponse({"error": "user not found"}, status_code=404)
    return JSONResponse({"ok": True})


@router.get("/api/requests/count")
async def api_requests_count(request: Request):
    if _require_admin(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    reqs = list_access_requests()
    return JSONResponse({"count": len(reqs)})


@router.get("/api/requests")
async def api_get_requests(request: Request):
    if _require_admin(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    reqs = list_access_requests()
    result = []
    for ar in reqs:
        spec   = ar.get("spec", {})
        status = ar.get("status", {})
        result.append({
            "name":           ar["metadata"]["name"],
            "cluster":        ar.get("_cluster", ""),
            "clusterDisplay": ar.get("_clusterDisplay", ar.get("_cluster", "")),
            "requester":      spec.get("requester", ""),
            "namespaces":     spec.get("namespaces") or ([spec.get("namespace")] if spec.get("namespace") else []),
            "reason":         spec.get("reason", ""),
            "ttlSeconds":     spec.get("ttlSeconds", 3600),
            "phase":          status.get("phase", "Pending"),
            "approvedBy":     status.get("approvedBy", ""),
            "expiresAt":      status.get("expiresAt", ""),
            "createdAt":      ar["metadata"].get("creationTimestamp", ""),
        })
    return JSONResponse({"requests": result})
