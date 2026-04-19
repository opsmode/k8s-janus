"""MFA router — /api/mfa/* endpoints."""
import base64
import logging
import secrets
from datetime import datetime, timezone
from io import BytesIO

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from core.auth import _get_user, _mfa_verified_recently, _set_mfa_verified
from db import (
    get_user_mfa, enable_user_mfa, disable_user_mfa, update_mfa_last_used,
    log_audit,
)

logger = logging.getLogger("k8s-janus-webui")

router = APIRouter()


@router.get("/api/mfa/status", include_in_schema=False)
async def mfa_status(request: Request):
    """Get MFA status for current user."""
    user_email, _ = _get_user(request)
    if not user_email:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)

    mfa_data = get_user_mfa(user_email)
    return JSONResponse({
        "enabled": mfa_data["enabled"] if mfa_data else False,
        "recently_verified": _mfa_verified_recently(request),
        "created_at": mfa_data["created_at"] if mfa_data else None,
        "last_used_at": mfa_data["last_used_at"] if mfa_data else None,
    })


@router.post("/api/mfa/setup", include_in_schema=False)
async def mfa_setup(request: Request):
    """Generate TOTP secret and QR code for MFA setup."""
    user_email, _ = _get_user(request)
    if not user_email:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)

    import pyotp
    import qrcode

    # Generate TOTP secret
    secret = pyotp.random_base32()

    # Generate QR code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user_email,
        issuer_name="K8s-Janus"
    )

    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to base64 data URL
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue()).decode()
    qr_data_url = f"data:image/png;base64,{img_str}"

    # Generate backup codes (8 random 8-character codes)
    backup_codes = [secrets.token_hex(4).upper() for _ in range(8)]

    # Store in session temporarily until user confirms
    request.session["mfa_setup_secret"] = secret
    request.session["mfa_setup_backup_codes"] = backup_codes

    return JSONResponse({
        "secret": secret,
        "qr_code": qr_data_url,
        "backup_codes": backup_codes,
    })


@router.post("/api/mfa/enable", include_in_schema=False)
async def mfa_enable(request: Request):
    """Enable MFA after verifying TOTP code."""
    user_email, _ = _get_user(request)
    if not user_email:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)

    code = body.get("code", "").strip()
    if not code:
        return JSONResponse({"error": "code required"}, status_code=400)

    # Verify the code against the secret in session
    secret = request.session.get("mfa_setup_secret")
    backup_codes = request.session.get("mfa_setup_backup_codes", [])

    if not secret:
        return JSONResponse({"error": "no setup in progress"}, status_code=400)

    import pyotp
    totp = pyotp.TOTP(secret)

    if not totp.verify(code, valid_window=1):
        return JSONResponse({"error": "invalid code"}, status_code=400)

    # Save to database
    if not enable_user_mfa(user_email, secret, backup_codes):
        return JSONResponse({"error": "failed to enable MFA"}, status_code=500)

    # Clear setup session data
    request.session.pop("mfa_setup_secret", None)
    request.session.pop("mfa_setup_backup_codes", None)

    logger.info(f"MFA enabled for {user_email}")
    log_audit("mfa", "mfa.enabled", actor=user_email, detail="TOTP enabled")

    return JSONResponse({"ok": True})


@router.post("/api/mfa/disable", include_in_schema=False)
async def mfa_disable(request: Request):
    """Disable MFA after verifying current TOTP code or backup code."""
    user_email, _ = _get_user(request)
    if not user_email:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)

    code = body.get("code", "").strip()
    if not code:
        return JSONResponse({"error": "code required"}, status_code=400)

    mfa_data = get_user_mfa(user_email)
    if not mfa_data or not mfa_data["enabled"]:
        return JSONResponse({"error": "MFA not enabled"}, status_code=400)

    # Verify code (TOTP or backup code)
    import pyotp
    totp = pyotp.TOTP(mfa_data["totp_secret"])
    valid = totp.verify(code, valid_window=1) or code.upper() in mfa_data["backup_codes"]

    if not valid:
        return JSONResponse({"error": "invalid code"}, status_code=400)

    if not disable_user_mfa(user_email):
        return JSONResponse({"error": "failed to disable MFA"}, status_code=500)

    logger.info(f"MFA disabled for {user_email}")
    log_audit("mfa", "mfa.disabled", actor=user_email, detail="TOTP disabled")

    return JSONResponse({"ok": True})


@router.post("/api/mfa/verify", include_in_schema=False)
async def mfa_verify(request: Request):
    """Verify TOTP code for terminal access."""
    user_email, _ = _get_user(request)
    if not user_email:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)

    code = body.get("code", "").strip()
    if not code:
        return JSONResponse({"error": "code required"}, status_code=400)

    mfa_data = get_user_mfa(user_email)
    if not mfa_data or not mfa_data["enabled"]:
        # No MFA enabled, treat as verified
        _set_mfa_verified(request)
        return JSONResponse({"ok": True})

    # Verify code (TOTP or backup code)
    import pyotp
    totp = pyotp.TOTP(mfa_data["totp_secret"])

    # Check TOTP code
    if totp.verify(code, valid_window=1):
        update_mfa_last_used(user_email)
        _set_mfa_verified(request)
        logger.info(f"MFA verified for {user_email}")
        return JSONResponse({"ok": True})

    # Check backup codes
    if code.upper() in mfa_data["backup_codes"]:
        # Remove used backup code
        backup_codes = [c for c in mfa_data["backup_codes"] if c != code.upper()]
        enable_user_mfa(user_email, mfa_data["totp_secret"], backup_codes)  # Update with removed code
        update_mfa_last_used(user_email)
        _set_mfa_verified(request)
        logger.info(f"MFA verified with backup code for {user_email}")
        log_audit("mfa", "mfa.backup_code_used", actor=user_email)
        return JSONResponse({"ok": True, "backup_code_used": True})

    return JSONResponse({"error": "invalid code"}, status_code=400)


@router.post("/api/mfa/backup-codes", include_in_schema=False)
async def get_backup_codes(request: Request):
    """Get backup codes after verifying current MFA code."""
    user_email, _ = _get_user(request)
    if not user_email:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid json"}, status_code=400)

    code = body.get("code", "").strip()
    if not code:
        return JSONResponse({"error": "code required"}, status_code=400)

    mfa_data = get_user_mfa(user_email)
    if not mfa_data or not mfa_data["enabled"]:
        return JSONResponse({"error": "MFA not enabled"}, status_code=400)

    # Verify code
    import pyotp
    totp = pyotp.TOTP(mfa_data["totp_secret"])

    if not totp.verify(code, valid_window=1):
        return JSONResponse({"error": "invalid code"}, status_code=400)

    return JSONResponse({"backup_codes": mfa_data["backup_codes"]})
