"""
AgentGuard SQLAlchemy ORM Models

These models define the database schema.
Separate from Pydantic domain models (app/core/models.py).

Tables:
  - action_events   : Every agent action intercepted by AgentGuard
  - audit_records   : Immutable-style SHA-256 chained audit trail
  - agent_profiles  : Per-agent behavioral baseline tracking
"""
from sqlalchemy import (
    Column, String, Integer, DateTime, Text, Boolean, Float, Index
)
from sqlalchemy.sql import func
from datetime import datetime, timezone
from app.database.database import Base


class ActionEvent(Base):
    """
    Represents one agent action intercepted by AgentGuard.
    
    Every action — whether ALLOWED, REVIEWED, or BLOCKED —
    is persisted here before any tool execution occurs.
    """
    __tablename__ = "action_events"

    # Identity
    id = Column(String(36), primary_key=True)          # UUID v4
    agent_id = Column(String(128), nullable=False, index=True)
    session_id = Column(String(36), nullable=False, index=True)

    # Action details
    action = Column(String(64), nullable=False)         # e.g. 'read_file'
    target = Column(Text, nullable=False)               # e.g. '.env', 'https://...'
    parameters = Column(Text, default="{}")             # JSON blob

    # Timing
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    # Security decision
    risk_score = Column(Integer, nullable=True)         # 0-100
    decision = Column(String(16), nullable=True)        # ALLOW | REVIEW | BLOCK
    reasons = Column(Text, nullable=True)               # JSON list of reason strings

    # Audit chain
    event_hash = Column(String(64), nullable=True)      # SHA-256 of this event
    previous_event_hash = Column(String(64), nullable=True)  # SHA-256 of prior event

    # Metadata
    created_at = Column(DateTime, server_default=func.now())

    __table_args__ = (
        Index("ix_action_events_agent_session", "agent_id", "session_id"),
        Index("ix_action_events_decision", "decision"),
        Index("ix_action_events_timestamp", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<ActionEvent agent={self.agent_id} action={self.action} decision={self.decision}>"


class AuditRecord(Base):
    """
    Immutable-style audit trail entry.
    
    Each record links to the previous via SHA-256 hash chaining,
    making post-hoc tampering detectable.
    
    IMPORTANT: Hash chaining provides INTEGRITY evidence only.
    It does NOT prove that an action was safe or authorized.
    """
    __tablename__ = "audit_records"

    id = Column(String(36), primary_key=True)           # UUID v4
    event_id = Column(String(36), nullable=False, index=True)  # FK to action_events.id
    agent_id = Column(String(128), nullable=False)
    action = Column(String(64), nullable=False)
    target = Column(Text, nullable=False)
    risk_score = Column(Integer, nullable=True)
    decision = Column(String(16), nullable=False)
    reasons = Column(Text, nullable=True)               # JSON list
    timestamp = Column(DateTime, nullable=False)

    # Hash chain
    event_hash = Column(String(64), nullable=False)
    previous_event_hash = Column(String(64), nullable=True)
    chain_valid = Column(Boolean, default=True)         # verified at write time

    created_at = Column(DateTime, server_default=func.now())

    def __repr__(self) -> str:
        return f"<AuditRecord event={self.event_id} decision={self.decision} hash={self.event_hash[:8]}...>"


class AgentProfile(Base):
    """
    Tracks per-agent behavioral baseline and statistics.
    
    Used by the risk engine to detect behavioral deviations:
    e.g., an agent that suddenly makes 10x more network requests
    than its historical average is anomalous.
    """
    __tablename__ = "agent_profiles"

    id = Column(String(36), primary_key=True)           # UUID v4
    agent_id = Column(String(128), nullable=False, unique=True, index=True)

    # Behavioral statistics (updated after each session)
    total_actions = Column(Integer, default=0)
    total_sessions = Column(Integer, default=0)
    total_blocks = Column(Integer, default=0)
    total_reviews = Column(Integer, default=0)
    average_risk_score = Column(Float, default=0.0)

    # Baseline behavioral rates (per session)
    avg_file_reads_per_session = Column(Float, default=0.0)
    avg_file_writes_per_session = Column(Float, default=0.0)
    avg_network_requests_per_session = Column(Float, default=0.0)
    avg_shell_commands_per_session = Column(Float, default=0.0)

    # Timestamps
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:
        return f"<AgentProfile agent={self.agent_id} actions={self.total_actions}>"
