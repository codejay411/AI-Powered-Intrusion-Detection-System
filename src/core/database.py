"""
Database connection and session management.
"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import StaticPool
from contextlib import contextmanager
import logging

from src.core.config import config
from src.core.models import Base

logger = logging.getLogger(__name__)


class Database:
    """Database connection manager."""

    _instance = None
    _engine = None
    _session_factory = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Initialize database connection."""
        db_type = config.db_type

        if db_type == 'sqlite':
            db_path = config.db_path
            # Ensure parent directory exists
            db_path.parent.mkdir(parents=True, exist_ok=True)

            connection_string = f"sqlite:///{db_path}"

            # SQLite-specific settings
            self._engine = create_engine(
                connection_string,
                connect_args={'check_same_thread': False},
                poolclass=StaticPool,
                echo=False
            )

            # Enable foreign keys for SQLite
            @event.listens_for(self._engine, "connect")
            def set_sqlite_pragma(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

        elif db_type == 'postgresql':
            pg_config = config.get('database.postgresql')
            connection_string = (
                f"postgresql://{pg_config['user']}:{pg_config['password']}"
                f"@{pg_config['host']}:{pg_config['port']}/{pg_config['database']}"
            )

            self._engine = create_engine(
                connection_string,
                pool_size=pg_config.get('pool_size', 10),
                max_overflow=20,
                echo=False
            )

        else:
            raise ValueError(f"Unsupported database type: {db_type}")

        # Create session factory
        self._session_factory = scoped_session(
            sessionmaker(bind=self._engine, expire_on_commit=False)
        )

        logger.info(f"Database initialized: {db_type}")

    def create_tables(self):
        """Create all tables."""
        Base.metadata.create_all(self._engine)
        logger.info("Database tables created")

    def drop_tables(self):
        """Drop all tables (use with caution)."""
        Base.metadata.drop_all(self._engine)
        logger.info("Database tables dropped")

    def get_session(self):
        """Get a new database session."""
        return self._session_factory()

    @contextmanager
    def session_scope(self):
        """
        Provide a transactional scope for database operations.

        Usage:
            with db.session_scope() as session:
                session.add(obj)
        """
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()

    def close(self):
        """Close all database connections."""
        self._session_factory.remove()
        self._engine.dispose()
        logger.info("Database connections closed")


# Global database instance
db = Database()


def init_database():
    """Initialize database and create tables if they don't exist."""
    db.create_tables()
    logger.info("Database initialization complete")
