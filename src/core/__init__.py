"""Core module initialization."""
from src.core.config import config
from src.core.database import db, init_database
from src.core.logger import setup_logging

__all__ = ['config', 'db', 'init_database', 'setup_logging']
