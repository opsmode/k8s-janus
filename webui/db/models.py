"""
SQLAlchemy ORM models for K8s-Janus.
"""

from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Boolean,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class AccessRequestRecord(Base):
    __tablename__ = "access_requests"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    name         = Column(String(255), unique=True, nullable=False, index=True)
    cluster      = Column(String(100), nullable=False, index=True)
    namespace    = Column(String(255), nullable=False, index=True)
    requester    = Column(String(255), nullable=False, index=True)
    ttl_seconds  = Column(Integer, nullable=False)
    reason       = Column(Text)
    phase        = Column(String(50), nullable=False, index=True)
    approved_by  = Column(String(255))
    denial_reason= Column(Text)
    created_at   = Column(DateTime(timezone=True), nullable=False, index=True)
    approved_at  = Column(DateTime(timezone=True))
    active_at    = Column(DateTime(timezone=True))
    expired_at   = Column(DateTime(timezone=True))
    denied_at    = Column(DateTime(timezone=True))
    revoked_at   = Column(DateTime(timezone=True))
    service_account = Column(String(255))
    token_secret    = Column(String(255))
    expires_at      = Column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    request_name = Column(String(255), nullable=False, index=True)
    event        = Column(String(100), nullable=False, index=True)
    actor        = Column(String(255))
    timestamp    = Column(DateTime(timezone=True), nullable=False, index=True)
    detail       = Column(Text)


class TerminalCommand(Base):
    __tablename__ = "terminal_commands"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    request_name = Column(String(255), nullable=False, index=True)
    pod          = Column(String(255), nullable=False)
    command      = Column(Text, nullable=False)
    timestamp    = Column(DateTime(timezone=True), nullable=False, index=True)


class UserQuickCommand(Base):
    __tablename__ = "user_quick_commands"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    user_email = Column(String(255), nullable=False, index=True)
    label      = Column(String(100), nullable=False)
    command    = Column(Text, nullable=False)
    position   = Column(Integer, nullable=False, default=0)


class UserMFA(Base):
    __tablename__ = "user_mfa"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    user_email   = Column(String(255), unique=True, nullable=False, index=True)
    enabled      = Column(Boolean, nullable=False, default=False)
    totp_secret  = Column(Text, nullable=True)  # Encrypted with Fernet
    backup_codes = Column(Text, nullable=True)  # Encrypted JSON array
    created_at   = Column(DateTime(timezone=True), nullable=False)
    last_used_at = Column(DateTime(timezone=True))


class UserProfile(Base):
    __tablename__ = "user_profiles"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    user_email = Column(String(255), unique=True, nullable=False, index=True)
    name       = Column(String(100))
    photo      = Column(Text)  # Base64 data URL
    updated_at = Column(DateTime(timezone=True), nullable=False)


class LocalUser(Base):
    __tablename__ = "local_users"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    email         = Column(String(255), unique=True, nullable=False, index=True)
    name          = Column(String(100), nullable=False)
    password_hash = Column(Text, nullable=False)
    is_admin      = Column(Boolean, nullable=False, default=False)
    is_active     = Column(Boolean, nullable=False, default=True)
    created_at    = Column(DateTime(timezone=True), nullable=False)
