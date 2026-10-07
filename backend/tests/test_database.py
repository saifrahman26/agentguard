"""
Tests for AgentGuard Database Layer
"""
import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import inspect as sa_inspect


def test_all_tables_created(test_engine):
    """All required tables must exist after create_all."""
    inspector = sa_inspect(test_engine)
    tables = inspector.get_table_names()
    assert "action_events" in tables
    assert "audit_records" in tables
    assert "agent_profiles" in tables


def test_action_event_insert_and_query(db_session):
    """Should be able to insert and retrieve an ActionEvent."""
    from app.database.models import ActionEvent

    event = ActionEvent(
        id=str(uuid.uuid4()),
        agent_id="test-agent-01",
        session_id=str(uuid.uuid4()),
        action="read_file",
        target=".env",
        parameters="{}",
        timestamp=datetime.now(timezone.utc),
        risk_score=91,
        decision="BLOCK",
        reasons='["Sensitive credential file"]',
    )
    db_session.add(event)
    db_session.flush()

    result = db_session.query(ActionEvent).filter_by(agent_id="test-agent-01").first()
    assert result is not None
    assert result.target == ".env"
    assert result.decision == "BLOCK"
    assert result.risk_score == 91


def test_agent_profile_insert(db_session):
    """Should be able to insert and retrieve an AgentProfile."""
    from app.database.models import AgentProfile

    profile = AgentProfile(
        id=str(uuid.uuid4()),
        agent_id="coding-agent-99",
        total_actions=10,
        average_risk_score=25.0,
    )
    db_session.add(profile)
    db_session.flush()

    result = db_session.query(AgentProfile).filter_by(agent_id="coding-agent-99").first()
    assert result is not None
    assert result.total_actions == 10
    assert result.average_risk_score == 25.0


def test_audit_record_insert(db_session):
    """Should be able to insert and retrieve an AuditRecord."""
    from app.database.models import AuditRecord
    import hashlib

    fake_hash = hashlib.sha256(b"test").hexdigest()
    record = AuditRecord(
        id=str(uuid.uuid4()),
        event_id=str(uuid.uuid4()),
        agent_id="test-agent-01",
        action="read_file",
        target=".env",
        risk_score=91,
        decision="BLOCK",
        reasons='["Sensitive credential file"]',
        timestamp=datetime.now(timezone.utc),
        event_hash=fake_hash,
        previous_event_hash=None,
        chain_valid=True,
    )
    db_session.add(record)
    db_session.flush()

    result = db_session.query(AuditRecord).filter_by(agent_id="test-agent-01").first()
    assert result is not None
    assert result.event_hash == fake_hash
    assert result.chain_valid is True
