"""
Shared database models for K8s-Janus.
Used by both controller and webui to persist AccessRequest data.
"""
import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


class AccessRequest(Base):
    """
    Persisted AccessRequest records.
    Mirrors the Kubernetes CRD but stored in PostgreSQL for historical queries.
    """
    __tablename__ = 'access_requests'

    id = Column(Integer, primary_key=True, autoincrement=True)
    # Core fields from CRD
    name = Column(String(255), unique=True, nullable=False, index=True)
    cluster = Column(String(100), nullable=False, index=True)
    namespace = Column(String(255), nullable=False, index=True)
    pod_name = Column(String(255), nullable=False)
    container_name = Column(String(255))
    requester = Column(String(255), nullable=False, index=True)
    ttl_seconds = Column(Integer, nullable=False)

    # Status fields
    phase = Column(String(50), nullable=False, index=True)  # Pending, Approved, Denied, Active, Expired, Revoked
    approved_by = Column(String(255))
    denied_by = Column(String(255))
    revoked_by = Column(String(255))

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    approved_at = Column(DateTime)
    denied_at = Column(DateTime)
    active_at = Column(DateTime)
    expired_at = Column(DateTime)
    revoked_at = Column(DateTime)

    # Additional metadata
    service_account = Column(String(255))
    role_binding = Column(String(255))
    token_secret = Column(String(255))
    full_spec = Column(JSON)  # Store full CRD spec as JSON for reference

    def __repr__(self):
        return f"<AccessRequest(name='{self.name}', phase='{self.phase}', requester='{self.requester}')>"


class AuditLog(Base):
    """
    Audit trail for all AccessRequest state changes and actions.
    """
    __tablename__ = 'audit_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    access_request_name = Column(String(255), nullable=False, index=True)
    action = Column(String(100), nullable=False, index=True)  # created, approved, denied, activated, expired, revoked
    actor = Column(String(255), nullable=False, index=True)  # who performed the action
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    details = Column(Text)  # Additional context or reason
    audit_metadata = Column('metadata', JSON)  # Structured metadata (IP, user agent, etc.)

    def __repr__(self):
        return f"<AuditLog(request='{self.access_request_name}', action='{self.action}', actor='{self.actor}')>"


def get_database_url():
    """Construct database URL from environment variables."""
    host = os.getenv('DB_HOST', 'localhost')
    port = os.getenv('DB_PORT', '5432')
    database = os.getenv('DB_NAME', 'janus')
    username = os.getenv('DB_USER', 'janus')
    password = os.getenv('DB_PASSWORD', '')

    return f"postgresql://{username}:{password}@{host}:{port}/{database}"


def init_db():
    """Initialize database tables."""
    engine = create_engine(get_database_url())
    Base.metadata.create_all(engine)
    return engine


def get_session():
    """Get a new database session."""
    engine = create_engine(get_database_url())
    Session = sessionmaker(bind=engine)
    return Session()
