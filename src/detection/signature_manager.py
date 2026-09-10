"""
Signature/rule definitions for detecting known attack patterns.
"""
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import re
import json

from src.core.database import db
from src.core.models import Signature

logger = logging.getLogger(__name__)


class SignatureManager:
    """Manage detection signatures and rules."""

    def __init__(self):
        self.loaded_signatures = {}
        self.load_all_signatures()

    def load_all_signatures(self):
        """Load all enabled signatures from database."""
        with db.session_scope() as session:
            signatures = session.query(Signature).filter(
                Signature.enabled == True
            ).all()

            self.loaded_signatures = {
                sig.id: sig for sig in signatures
            }

            logger.info(f"Loaded {len(self.loaded_signatures)} signatures")

    def add_signature(self, signature_data: Dict) -> Signature:
        """
        Add a new signature to the database.

        Args:
            signature_data: Dictionary containing signature fields

        Returns:
            Created Signature object
        """
        with db.session_scope() as session:
            signature = Signature(
                name=signature_data['name'],
                description=signature_data.get('description', ''),
                rule_type=signature_data['rule_type'],
                rule_content=signature_data['rule_content'],
                event_type=signature_data.get('event_type'),
                conditions=signature_data.get('conditions', {}),
                severity=signature_data['severity'],
                enabled=signature_data.get('enabled', True),
                confidence=signature_data.get('confidence', 1.0),
                category=signature_data.get('category'),
                tags=signature_data.get('tags', []),
                references=signature_data.get('references', []),
                attack_tactics=signature_data.get('attack_tactics', []),
                attack_techniques=signature_data.get('attack_techniques', [])
            )

            session.add(signature)
            session.flush()
            signature_id = signature.id

        # Reload signatures
        self.load_all_signatures()

        logger.info(f"Added signature: {signature_data['name']} (ID: {signature_id})")
        return signature

    def update_signature(self, signature_id: int, updates: Dict):
        """Update an existing signature."""
        with db.session_scope() as session:
            signature = session.query(Signature).filter(
                Signature.id == signature_id
            ).first()

            if not signature:
                raise ValueError(f"Signature {signature_id} not found")

            for key, value in updates.items():
                if hasattr(signature, key):
                    setattr(signature, key, value)

            signature.updated_at = datetime.utcnow()

        # Reload signatures
        self.load_all_signatures()

        logger.info(f"Updated signature ID {signature_id}")

    def delete_signature(self, signature_id: int):
        """Delete a signature."""
        with db.session_scope() as session:
            signature = session.query(Signature).filter(
                Signature.id == signature_id
            ).first()

            if signature:
                session.delete(signature)

        # Reload signatures
        self.load_all_signatures()

        logger.info(f"Deleted signature ID {signature_id}")

    def get_signature(self, signature_id: int) -> Optional[Signature]:
        """Get a signature by ID."""
        return self.loaded_signatures.get(signature_id)

    def get_all_signatures(self, enabled_only: bool = True) -> List[Signature]:
        """Get all signatures."""
        if enabled_only:
            return list(self.loaded_signatures.values())
        else:
            with db.session_scope() as session:
                return session.query(Signature).all()

    def enable_signature(self, signature_id: int):
        """Enable a signature."""
        self.update_signature(signature_id, {'enabled': True})

    def disable_signature(self, signature_id: int):
        """Disable a signature."""
        self.update_signature(signature_id, {'enabled': False})

    def get_signatures_by_type(self, event_type: str) -> List[Signature]:
        """Get signatures for a specific event type."""
        return [
            sig for sig in self.loaded_signatures.values()
            if sig.event_type == event_type or sig.event_type is None
        ]

    def update_last_matched(self, signature_id: int):
        """Update the last matched timestamp for a signature."""
        with db.session_scope() as session:
            signature = session.query(Signature).filter(
                Signature.id == signature_id
            ).first()

            if signature:
                signature.last_matched = datetime.utcnow()


# Global signature manager instance
signature_manager = SignatureManager()
