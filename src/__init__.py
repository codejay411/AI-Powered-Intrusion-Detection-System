"""
Main application entry point for the IDS system.
"""
import logging
from src.core import setup_logging, init_database

logger = logging.getLogger(__name__)


def initialize_system():
    """Initialize the IDS system."""
    # Setup logging
    setup_logging()
    logger.info("=" * 60)
    logger.info("AI-Powered Intrusion Detection System")
    logger.info("=" * 60)

    # Initialize database
    try:
        init_database()
        logger.info("System initialization complete")
    except Exception as e:
        logger.error(f"System initialization failed: {e}")
        raise


if __name__ == "__main__":
    initialize_system()
