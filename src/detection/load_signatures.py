"""
Utility to load default signatures into the database.
"""
import logging

from src.core import setup_logging, init_database
from src.detection.signature_manager import signature_manager
from src.detection.default_signatures import ALL_SIGNATURES

logger = logging.getLogger(__name__)


def load_default_signatures():
    """Load all default signatures into the database."""
    logger.info("Loading default signatures...")

    loaded = 0
    skipped = 0

    for sig_data in ALL_SIGNATURES:
        try:
            # Check if signature already exists
            existing = None
            for sig in signature_manager.get_all_signatures(enabled_only=False):
                if sig.name == sig_data['name']:
                    existing = sig
                    break

            if existing:
                logger.debug(f"Signature already exists: {sig_data['name']}")
                skipped += 1
                continue

            # Add new signature
            signature_manager.add_signature(sig_data)
            loaded += 1

        except Exception as e:
            logger.error(f"Error loading signature {sig_data['name']}: {e}")

    logger.info(f"Loaded {loaded} signatures, skipped {skipped} existing")
    return loaded, skipped


if __name__ == '__main__':
    setup_logging()
    init_database()
    load_default_signatures()
