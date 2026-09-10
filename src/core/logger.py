"""
Logging configuration for the IDS system.
"""
import logging
import logging.handlers
from pathlib import Path
from src.core.config import config


def setup_logging():
    """Configure logging for the application."""
    log_config = config.get('logging')
    log_level = getattr(logging, log_config.get('level', 'INFO'))
    log_format = log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Console handler
    if log_config.get('console', {}).get('enabled', True):
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_formatter = logging.Formatter(log_format)
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    # File handler
    if log_config.get('file', {}).get('enabled', True):
        log_path = config.log_path / log_config.get('file', {}).get('path', 'ids.log').split('/')[-1]
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=log_config.get('file', {}).get('max_bytes', 10485760),
            backupCount=log_config.get('file', {}).get('backup_count', 5)
        )
        file_handler.setLevel(log_level)
        file_formatter = logging.Formatter(log_format)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    logging.info("Logging configured")
