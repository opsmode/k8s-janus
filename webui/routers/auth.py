"""Auth router — /login, /logout, /auth/callback, /mfa-verify."""
import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from core.config import (
    OIDC_ENABLED, LOCAL_AUTH_ENABLED, OIDC_PROVIDER, _PROVIDER_DISPLAY, _oauth,
    OIDC_ALLOWED_DOMAINS,
)
from core.auth import _is_admin
from core.templates import templates
import local_auth
from core.security import login_allowed, record_login_failure, clear_login_failures

logger = logging.getLogger("k8s-janus-webui")

router = APIRouter()


@router.get("/login", include_in_schema=False)
async def login_page(request: Request, next: str = "/", error: str = ""):
    if request.session.get("user_email"):
        return RedirectResponse(next or "/")
    if OIDC_ENABLED:
        provider_name = _PROVIDER_DISPLAY.get(OIDC_PROVIDER, OIDC_PROVIDER or "SSO")
        return templates.TemplateResponse(request, "login.html", {
            "mode": "oidc",
            "provider_name": provider_name,
            "provider": OIDC_PROVIDER,
            "next": next,
            "error": error,
        })
    if LOCAL_AUTH_ENABLED:
        return templates.TemplateResponse(request, "login.html", {
            "mode": "local",
            "next": next,
            "error": error,
        })
    return RedirectResponse("/")


@router.post("/login", include_in_schema=False)
async def local_login(request: Request):
    if not LOCAL_AUTH_ENABLED:
        return RedirectResponse("/", status_code=302)
    form = await request.form()
    email    = str(form.get("email", "")).strip().lower()
    password = str(form.get("password", ""))
    next_url = str(form.get("next", "/")) or "/"
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown").split(",")[0].strip()

    if not login_allowed(client_ip):
        logger.warning(f"Login blocked (rate limit): {email} from {client_ip}")
        return templates.TemplateResponse(request, "login.html", {
            "mode": "local",
            "next": next_url,
            "error": "Too many failed attempts. Try again in 15 minutes.",
        }, status_code=429)

    user = local_auth.verify_user(email, password)
    if not user:
        record_login_failure(client_ip)
        logger.warning(f"Login failed: {email} from {client_ip}")
        return templates.TemplateResponse(request, "login.html", {
            "mode": "local",
            "next": next_url,
            "error": "Invalid email or password.",
        })
    clear_login_failures(client_ip)
    request.session["user_email"] = user["email"]
    request.session["user_name"]  = user["name"]
    logger.info(f"Login success: {email} from {client_ip}")
    if next_url == "/" and user["is_admin"]:
        next_url = "/admin"
    return RedirectResponse(next_url, status_code=302)


@router.get("/login/redirect", include_in_schema=False)
async def oidc_login_redirect(request: Request, next: str = "/"):
    """Kick off the OAuth2 redirect to the IdP."""
    callback_url = request.url_for("oidc_callback")
    scheme = request.headers.get("x-forwarded-proto", callback_url.scheme)
    redirect_uri = str(callback_url).replace(f"{callback_url.scheme}://", f"{scheme}://")
    request.session["oidc_next"] = next
    if OIDC_PROVIDER == "github":
        client = _oauth.github
    else:
        client = _oauth.oidc
    return await client.authorize_redirect(request, redirect_uri)


@router.get("/auth/callback", include_in_schema=False)
async def oidc_callback(request: Request):
    """Handle IdP callback: exchange code for tokens, set session."""
    try:
        if OIDC_PROVIDER == "github":
            client = _oauth.github
            token = await client.authorize_access_token(request)
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
            return templates.TemplateResponse(request, "403.html", {"user_email": email, "reason": f"Email domain '{domain}' is not allowed."}, status_code=403)

    request.session["user_email"] = email.lower()
    request.session["user_name"]  = name
    next_url = request.session.pop("oidc_next", "/") or "/"
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    logger.info(f"Login success (oidc): {email} from {client_ip}")
    if next_url == "/" and _is_admin(email.lower()):
        next_url = "/admin"
    return RedirectResponse(next_url, status_code=302)


@router.get("/logout", include_in_schema=False)
async def oidc_logout(request: Request):
    email = request.session.get("user_email", "unknown")
    logger.info(f"Logout: {email}")
    request.session.clear()
    if OIDC_ENABLED:
        return templates.TemplateResponse(request, "signedout.html")
    return RedirectResponse("/")
