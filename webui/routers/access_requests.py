"""Requests router — /namespaces/*, POST /request, /approve, /deny, /revoke, /cancel, /callback, /status/*, /extend/*."""
import logging
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from kubernetes.client.rest import ApiException

from core.auth import _base_context, _require_admin, _get_user, _is_admin
from core.config import MAX_TTL_SECONDS, MAX_ACTIVE_REQUESTS
from core.k8s_helpers import (
    Phase, _valid_name, _valid_ns, _valid_cluster,
    _check_rate_limit, _patch_status,
)
from core.templates import templates
from db import upsert_request, log_audit, _now
from k8s import (
    get_api_clients, get_clusters, get_cluster_config,
    get_allowed_namespaces, get_access_request, list_access_requests,
    read_token_secret, CRD_GROUP, CRD_VERSION,
)
from terminal_ws import notify_revoked

logger = logging.getLogger("k8s-janus-webui")

router = APIRouter()


@router.get("/namespaces/{cluster_name}")
async def namespaces(cluster_name: str):
    if not _valid_cluster(cluster_name):
        return JSONResponse([], status_code=400)
    ns_list = get_allowed_namespaces(cluster_name)
    return JSONResponse(ns_list)


@router.post("/request")
async def submit_request(request: Request):
    user_from_auth, _ = _get_user(request)
    body      = await request.json()
    requester = user_from_auth or body.get("requester", "").strip()
    reason    = body.get("reason", "").strip()[:500]
    ttl_hours = int(body.get("ttl_hours", 1))
    targets   = body.get("targets", [])

    if not requester:
        return JSONResponse({"error": "Unauthorized: no authenticated user found."}, status_code=401)
    if not targets:
        return JSONResponse({"error": "No targets specified."}, status_code=400)
    if not reason:
        return JSONResponse({"error": "Reason is required."}, status_code=400)
    if ttl_hours < 1:
        return JSONResponse({"error": "TTL must be at least 1 hour."}, status_code=400)

    if (rate_err := _check_rate_limit(requester)):
        return JSONResponse({"error": rate_err}, status_code=429)

    all_requests = list_access_requests()
    live_phases  = (Phase.PENDING, Phase.APPROVED, Phase.ACTIVE)
    user_live = [
        ar for ar in all_requests
        if ar.get("spec", {}).get("requester") == requester
        and ar.get("status", {}).get("phase", "") in live_phases
    ]
    if len(user_live) >= MAX_ACTIVE_REQUESTS:
        return JSONResponse(
            {"error": f"You already have {len(user_live)} active/pending requests (max {MAX_ACTIVE_REQUESTS}). Cancel or wait for existing requests to expire."},
            status_code=429,
        )

    ttl_seconds = min(ttl_hours * 3600, MAX_TTL_SECONDS)

    clusters_in_request = {t.get("cluster", "") for t in targets}
    if len(clusters_in_request) > 1:
        return JSONResponse({"error": "All namespaces must be on the same cluster."}, status_code=400)

    cluster = targets[0]["cluster"]
    if not _valid_cluster(cluster) or not get_cluster_config(cluster):
        return JSONResponse({"error": f"Unknown cluster: {cluster}"}, status_code=400)

    allowed = get_allowed_namespaces(cluster)
    skipped: list[str] = []
    errors:  list[str] = []
    valid_namespaces = []
    for t in targets:
        ns = t.get("namespace", "")
        if not _valid_ns(ns):
            skipped.append(f"{ns} (invalid name)")
            continue
        if ns not in allowed:
            skipped.append(f"{ns} (not allowed)")
            continue
        valid_namespaces.append(ns)

    if not valid_namespaces:
        return JSONResponse({"error": "No valid namespaces.", "skipped": skipped, "errors": errors}, status_code=400)

    busy_ns: set[str] = set()
    for ar in all_requests:
        sp = ar.get("spec", {})
        if (sp.get("requester") == requester
                and sp.get("cluster") == cluster
                and ar.get("status", {}).get("phase", "") in live_phases):
            ar_nss = sp.get("namespaces") or ([sp["namespace"]] if sp.get("namespace") else [])
            busy_ns.update(ar_nss)

    duplicate_ns = [ns for ns in valid_namespaces if ns in busy_ns]
    if duplicate_ns:
        dupes = ", ".join(duplicate_ns)
        return JSONResponse(
            {"error": f"You already have an active request for: {dupes}. Wait for it to expire or ask an admin to revoke it."},
            status_code=409,
        )

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
            "requester":  requester,
            "namespaces": valid_namespaces,
            "namespace":  valid_namespaces[0],
            "reason":     reason,
            "ttlSeconds": ttl_seconds,
            "cluster":    cluster,
        },
    }

    try:
        central_api.create_cluster_custom_object(
            group=CRD_GROUP, version=CRD_VERSION, plural="accessrequests", body=ar_body,
        )
        logger.info(f"🎫 Created AccessRequest {name} for {requester} on {cluster} ns={valid_namespaces}")
        upsert_request(
            name,
            cluster=cluster, namespace=valid_namespaces[0], requester=requester,
            ttl_seconds=ttl_seconds, reason=reason, phase=Phase.PENDING, created_at=_now(),
        )
        log_audit(name, "request.created", actor=requester,
                  detail=f"cluster={cluster} ns={valid_namespaces} ttl={ttl_seconds}s")
        return JSONResponse({"created": [name], "skipped": skipped, "errors": errors})
    except ApiException as e:
        logger.error(f"💥 Failed to create AccessRequest for {cluster} ns={valid_namespaces}: {e}")
        return JSONResponse({"error": "Failed to create request.", "errors": [str(e)]}, status_code=500)


@router.get("/status/{cluster}/{name}", response_class=HTMLResponse)
async def status(request: Request, cluster: str, name: str):
    ar = get_access_request(name, cluster)
    if not ar:
        ctx = _base_context(request)
        ctx["error"] = f"Request '{name}' not found on cluster '{cluster}'"
        _ue = ctx["user_email"]
        _adm = _is_admin(_ue)
        _all = list_access_requests()
        ctx["access_requests"] = _all if _adm else [r for r in _all if r.get("spec", {}).get("requester", "").lower() == _ue.lower()]
        ctx["is_admin"] = _adm
        return templates.TemplateResponse(request, "index.html", ctx)

    ar_status = ar.get("status", {})
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
        "cluster_name":    cluster_display_name,
        "cluster_display": cluster_display_name,
        "ar":     ar,
        "spec":   ar.get("spec", {}),
        "status": ar_status,
        "name":   name,
        "cluster": cluster,
        "token":  token,
        "server": server,
        "ca":     ca,
        "can_withdraw": (
            ar_status.get("phase") in (Phase.PENDING, Phase.ACTIVE)
            and ar.get("spec", {}).get("requester", "").lower() == ctx.get("user_email", "").lower()
        ),
    })
    return templates.TemplateResponse(request, "status.html", ctx)


@router.get("/callback", response_class=HTMLResponse)
async def callback(request: Request, action: str, name: str, cluster: str = ""):
    if not cluster:
        cluster = get_clusters()[0]["name"]
    ar = get_access_request(name, cluster)
    if not ar:
        return templates.TemplateResponse(request, "404.html", {"path": f"/action/{name}"}, status_code=404)

    cluster_cfg     = get_cluster_config(cluster)
    cluster_display = cluster_cfg.get("displayName", cluster) if cluster_cfg else cluster
    current_phase   = ar.get("status", {}).get("phase", "")

    _cb_base = {**_base_context(request), "cluster_name": cluster_display, "name": name, "spec": ar.get("spec", {})}
    if current_phase not in (Phase.PENDING, ""):
        return templates.TemplateResponse(request, "callback.html", {
            **_cb_base, "action": action,
            "already_actioned": True, "current_phase": current_phase,
        })

    if action == "deny":
        return templates.TemplateResponse(request, "deny-confirm.html", {
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
        return templates.TemplateResponse(request, "500.html", {"detail": "Error updating request."}, status_code=500)

    return templates.TemplateResponse(request, "callback.html", {
        **_cb_base, "action": "approve",
        "already_actioned": False, "current_phase": Phase.APPROVED,
    })


@router.post("/deny-confirm", response_class=HTMLResponse)
async def deny_confirm(request: Request, name: str = Form(...), cluster: str = Form(...), denial_reason: str = Form("")):
    if (err := _require_admin(request)):
        return err
    denial_reason = denial_reason.strip()[:500]
    ar = get_access_request(name, cluster)
    if not ar:
        return templates.TemplateResponse(request, "404.html", {"path": f"/deny/{name}"}, status_code=404)

    cluster_cfg     = get_cluster_config(cluster)
    cluster_display = cluster_cfg.get("displayName", cluster) if cluster_cfg else cluster
    approver, _     = _get_user(request)
    approver        = approver or "devops-team"
    denial_msg      = f"Denied by {approver}" + (f": {denial_reason}" if denial_reason else "")

    try:
        _patch_status(name, {
            "phase":        Phase.DENIED,
            "approvedBy":   approver,
            "approvedAt":   datetime.now(timezone.utc).isoformat(),
            "message":      denial_msg,
            "denialReason": denial_reason or None,
        })
        logger.info(f"🚫 AccessRequest {name} on {cluster} Denied by {approver}: {denial_reason or '(no reason)'}")
    except ApiException as e:
        logger.error(f"💥 Failed to update AccessRequest {name}: {e}")
        return templates.TemplateResponse(request, "500.html", {"detail": "Error updating request."}, status_code=500)

    _dc_base = {**_base_context(request), "cluster_name": cluster_display, "name": name, "spec": ar.get("spec", {})}
    return templates.TemplateResponse(request, "callback.html", {
        **_dc_base, "action": "deny",
        "already_actioned": False, "current_phase": Phase.DENIED,
    })


@router.post("/approve/{cluster}/{name}")
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
            "phase":      Phase.APPROVED,
            "approvedBy": approver,
            "approvedAt": datetime.now(timezone.utc).isoformat(),
        }
        effective_ttl = ttl_override or ar.get("spec", {}).get("ttlSeconds", 3600)
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=effective_ttl)).isoformat()
        if ttl_override:
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
                       ttl_seconds=effective_ttl, created_at=_now())
        log_audit(name, "request.approved", actor=approver,
                  detail=f"cluster={cluster} ttl={effective_ttl}s expires={expires_at}"
                         + (f" ttl_override={ttl_override}s" if ttl_override else ""))
    except ApiException as e:
        logger.error(f"💥 Failed to approve AccessRequest {name}: {e}")
        return JSONResponse({"ok": False, "error": "Failed to approve request"}, status_code=500)
    return JSONResponse({"ok": True, "phase": Phase.APPROVED, "ttlSeconds": effective_ttl, "expiresAt": expires_at})


@router.post("/deny/{cluster}/{name}")
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
            "phase":        Phase.DENIED,
            "approvedBy":   approver,
            "approvedAt":   datetime.now(timezone.utc).isoformat(),
            "message":      denial_msg,
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


@router.post("/revoke/{cluster}/{name}", response_class=HTMLResponse)
async def revoke(request: Request, cluster: str, name: str):
    if (err := _require_admin(request)):
        return err
    caller, _ = _get_user(request)
    caller    = caller or "admin"
    ar = get_access_request(name, cluster)
    if not ar:
        return templates.TemplateResponse(request, "404.html", {"path": f"/revoke/{name}"}, status_code=404)
    current_phase = ar.get("status", {}).get("phase", "")
    if current_phase not in (Phase.ACTIVE, Phase.APPROVED, Phase.PENDING):
        return RedirectResponse(url="/admin", status_code=303)
    try:
        _patch_status(name, {
            "phase":     Phase.REVOKED,
            "message":   "Access revoked by admin",
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
        return templates.TemplateResponse(request, "500.html", {"detail": "Error revoking request."}, status_code=500)
    wants_json = "application/json" in (request.headers.get("accept") or "")
    if wants_json:
        return JSONResponse({"ok": True, "phase": Phase.REVOKED})
    return RedirectResponse(url="/admin", status_code=303)


@router.post("/cancel/{cluster}/{name}")
async def cancel_request(request: Request, cluster: str, name: str):
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
            "phase":     Phase.CANCELLED,
            "message":   f"Cancelled by requester {caller}",
            "revokedAt": datetime.now(timezone.utc).isoformat(),
        })
        logger.info(f"🚫 AccessRequest {name} on {cluster} cancelled by {caller} (was {current_phase})")
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


@router.post("/extend/{cluster}/{name}")
async def extend_access(cluster: str, name: str, request: Request):
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

    base = max(now, current_expires)
    new_expires = base + timedelta(seconds=extra_seconds)
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
