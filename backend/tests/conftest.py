"""
AgentGuard Test Configuration

Provides shared fixtures for all test modules.
Uses in-memory SQLite so tests never touch the real database.
"""
import sys
import os
from pathlib import Path

# Ensure the app package is importable from the backend/ directory
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.database import Base


@pytest.fixture(scope="session")
def test_engine():
    """In-memory SQLite engine for the entire test session."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    # Import models so they register with Base.metadata
    from app.database import models  # noqa: F401
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(test_engine):
    """Provides a database session that rolls back after each test."""
    Session = sessionmaker(bind=test_engine)
    session = Session()
    yield session
    session.rollback()
    session.close()


@pytest.fixture(scope="session")
def settings():
    """Returns the default AgentGuard settings."""
    from app.config import get_settings
    return get_settings()
