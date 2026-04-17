"""
Local authentication — username/password auth for Janus.

Active when neither OIDC nor X-Forwarded-Email (authEnabled) is configured.
On first startup, an admin@local account is created with a random password
printed to the application log.
"""
import logging
import secrets
import string
import time
from datetime import datetime, timezone

import bcrypt
from psycopg2.errors import UniqueViolation

import db as _db
from db import LocalUser, get_session

logger = logging.getLogger("janus.local_auth")

_ADMIN_EMAIL = "admin@local"
_PW_ALPHABET  = string.ascii_letters + string.digits


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def generate_password(length: int = 20) -> str:
    return "".join(secrets.choice(_PW_ALPHABET) for _ in range(length))


# ---------------------------------------------------------------------------
# User CRUD
# ---------------------------------------------------------------------------

def _row_to_dict(u: LocalUser) -> dict:
    return {
        "email":      u.email,
        "name":       u.name,
        "is_admin":   u.is_admin,
        "is_active":  u.is_active,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


def get_user(email: str) -> dict | None:
    if not _db.db_enabled:
        return None
    try:
        with get_session() as session:
            if session is None:
                return None
            u = session.query(LocalUser).filter_by(email=email.lower()).first()
            return _row_to_dict(u) if u else None
    except Exception as e:
        logger.error(f"get_user({email}) failed: {e}")
        return None


def verify_user(email: str, password: str) -> dict | None:
    """Return user dict if credentials are valid and account is active, else None."""
    if not _db.db_enabled:
        return None
    try:
        with get_session() as session:
            if session is None:
                return None
            u = session.query(LocalUser).filter_by(email=email.lower(), is_active=True).first()
            if u and verify_password(password, u.password_hash):
                return _row_to_dict(u)
            return None
    except Exception as e:
        logger.error(f"verify_user({email}) failed: {e}")
        return None


def list_users() -> list[dict]:
    if not _db.db_enabled:
        return []
    try:
        with get_session() as session:
            if session is None:
                return []
            users = session.query(LocalUser).order_by(LocalUser.created_at).all()
            return [_row_to_dict(u) for u in users]
    except Exception as e:
        logger.error(f"list_users() failed: {e}")
        return []


def create_user(email: str, name: str, password: str, is_admin: bool = False) -> dict | None:
    """Create a new local user. Returns user dict, or None if email already exists."""
    if not _db.db_enabled:
        return None
    try:
        with get_session() as session:
            if session is None:
                return None
            if session.query(LocalUser).filter_by(email=email.lower()).first():
                return None
            u = LocalUser(
                email=email.lower(),
                name=name,
                password_hash=hash_password(password),
                is_admin=is_admin,
                is_active=True,
                created_at=_now(),
            )
            session.add(u)
            session.flush()
            return _row_to_dict(u)
    except Exception as e:
        logger.error(f"create_user({email}) failed: {e}")
        return None


def delete_user(email: str) -> bool:
    if not _db.db_enabled:
        return False
    try:
        with get_session() as session:
            if session is None:
                return False
            deleted = session.query(LocalUser).filter_by(email=email.lower()).delete()
            return deleted > 0
    except Exception as e:
        logger.error(f"delete_user({email}) failed: {e}")
        return False


def set_password(email: str, new_password: str) -> bool:
    if not _db.db_enabled:
        return False
    try:
        with get_session() as session:
            if session is None:
                return False
            u = session.query(LocalUser).filter_by(email=email.lower()).first()
            if not u:
                return False
            u.password_hash = hash_password(new_password)
            return True
    except Exception as e:
        logger.error(f"set_password({email}) failed: {e}")
        return False


def set_admin(email: str, is_admin: bool) -> bool:
    if not _db.db_enabled:
        return False
    try:
        with get_session() as session:
            if session is None:
                return False
            u = session.query(LocalUser).filter_by(email=email.lower()).first()
            if not u:
                return False
            u.is_admin = is_admin
            return True
    except Exception as e:
        logger.error(f"set_admin({email}) failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def ensure_admin_user(retries: int = 10, delay: float = 3.0) -> str | None:
    """
    Create the default admin@local account if no local users exist.
    Returns the generated password (to be logged once), or None if users
    already exist. Retries on connection failure to handle cold starts where
    the webui comes up before PostgreSQL is ready.
    """
    for attempt in range(1, retries + 1):
        try:
            with get_session() as session:
                if session is None:
                    return None
                if session.query(LocalUser).count() > 0:
                    return None
                password = generate_password()
                u = LocalUser(
                    email=_ADMIN_EMAIL,
                    name="Admin",
                    password_hash=hash_password(password),
                    is_admin=True,
                    is_active=True,
                    created_at=_now(),
                )
                session.add(u)
                session.flush()
                return password
        except Exception as e:
            if isinstance(e.__cause__, UniqueViolation) or isinstance(e, UniqueViolation):
                return None
            if attempt < retries:
                logger.warning(
                    f"ensure_admin_user() attempt {attempt}/{retries} failed, "
                    f"retrying in {delay:.0f}s: {e}"
                )
                time.sleep(delay)
            else:
                logger.error(f"ensure_admin_user() failed after {retries} attempts: {e}")
    return None
