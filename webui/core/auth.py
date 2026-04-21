"""
Authentication and authorization helpers for K8s-Janus WebUI.
"""

from fastapi import Request

import local_auth
from core.config import (
    OIDC_ENABLED, LOCAL_AUTH_ENABLED, ADMIN_EMAILS,
    DEFAULT_TTL_SECONDS, MAX_TTL_SECONDS, APPROVAL_TTL_OPTIONS,
    APP_VERSION,
)
from core.templates import templates
from k8s import get_clusters, list_access_requests


def _is_admin(email: str) -> bool:
    if not email:
        return False
    if LOCAL_AUTH_ENABLED:
        user = local_auth.get_user(email)
        return bool(user and user["is_admin"] and user["is_active"])
    return email.lower() in ADMIN_EMAILS


def _get_user(request: Request) -> tuple[str, str]:
    """Return (email, name) for the current request.
    1. OIDC or local-auth session cookie
    2. X-Forwarded-Email header (oauth2-proxy / ingress SSO)
    3. Empty strings (AUTH_ENABLED=false without OIDC/local-auth — should not happen in prod)
    """
    if OIDC_ENABLED or LOCAL_AUTH_ENABLED:
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
        "local_auth_enabled": LOCAL_AUTH_ENABLED,
        "default_ttl": DEFAULT_TTL_SECONDS // 3600,
        "max_ttl": MAX_TTL_SECONDS // 3600,
        "approval_ttl_options": APPROVAL_TTL_OPTIONS,
        "app_version": APP_VERSION,
    }


def _require_admin(request: Request):
    """Return 403 response if caller is not an admin, else None."""
    user_email, _ = _get_user(request)
    if not _is_admin(user_email):
        return templates.TemplateResponse(request, "403.html", {"user_email": user_email}, status_code=403)
    return None


def _require_active_request(request: Request, cluster: str, namespace: str) -> bool:
    user_email, _ = _get_user(request)
    if not user_email:
        return False
    if _is_admin(user_email):
        return True
    for ar in list_access_requests():
        spec = ar.get("spec", {})
        st   = ar.get("status", {})
        if st.get("phase") != "Active":
            continue
        if ar.get("_cluster", "") != cluster:
            continue
        if spec.get("requester", "").lower() != user_email.lower():
            continue
        nss = spec.get("namespaces") or ([spec.get("namespace")] if spec.get("namespace") else [])
        if namespace in nss:
            return True
    return False
