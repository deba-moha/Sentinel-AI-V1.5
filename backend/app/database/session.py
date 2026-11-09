"""
Sentinel AI - Database Session & Lifecycle
Manages SQLite engine connections, session factories, and table initialization.
"""
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from backend.app.core.config import settings
from backend.app.core.logging_config import logger

# SQLite concurrency configuration
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=(settings.LOG_LEVEL.upper() == "DEBUG")
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for injecting database sessions per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Creates all database tables defined across SQLAlchemy models."""
    logger.info("Initializing SQLite database schema...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database schema initialized successfully.")
