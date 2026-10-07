"""
AgentGuard Database Layer

SQLite engine and session factory using SQLAlchemy 2.0.
Uses synchronous SQLite for simplicity — async can be layered later.
SQLite runs with check_same_thread=False for FastAPI compatibility.
"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session, DeclarativeBase
from typing import Generator
import logging

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


def get_engine(database_url: str):
    """
    Create and configure a SQLAlchemy engine.
    
    Args:
        database_url: SQLAlchemy connection string.
                      Default: 'sqlite:///./agentguard.db'
    """
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False},  # Required for SQLite + FastAPI
        echo=False,  # Set to True for SQL query logging during debug
    )
    logger.info(f"Database engine created: {database_url}")
    return engine


def get_session_factory(engine):
    """
    Create a session factory bound to the given engine.
    
    Returns:
        A sessionmaker factory. Call it to get a Session instance.
    """
    return sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )


def create_tables(engine) -> None:
    """Create all tables defined in ORM models. Safe to call multiple times."""
    from app.database import models  # noqa: F401 — import to register models
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created/verified.")


def get_db(session_factory) -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a database session per request.
    Automatically closes the session after the request.
    
    Usage:
        @app.get('/items')
        def get_items(db: Session = Depends(get_db)):
            ...
    """
    db = session_factory()
    try:
        yield db
    finally:
        db.close()
