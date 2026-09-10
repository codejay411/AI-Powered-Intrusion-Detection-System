"""
Alert generation from signature matches.
"""
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from src.core.database import db
from src.core.models import Event, Alert, Signature
from src.detection.signature_engine import signature_engine

logger = logging.getLogger(__name__)


class AlertGenerator:
    """Generate alerts from signature matches."""

    def __init__(self):
        self.signature_engine = signature_engine

    def process_event(self, event: Event) -> List[Alert]:
        """
        Process an event and generate alerts for any signature matches.

        Args:
            event: Event object to process

        Returns:
            List of generated Alert objects
        """
        alerts = []

        # Match event against signatures
        matches = self.signature_engine.match_event(event)

        if not matches:
            return alerts

        # Generate alerts for each match
        for signature, confidence, match_details in matches:
            alert = self._create_alert(event, signature, confidence, match_details)
            alerts.append(alert)

        # Store alerts in database
        if alerts:
            self._store_alerts(alerts)
            logger.info(f"Generated {len(alerts)} alerts for event {event.id}")

        return alerts

    def _create_alert(self, event: Event, signature: Signature,
                      confidence: float, match_details: Dict) -> Alert:
        """
        Create an Alert object from a signature match.

        Args:
            event: Matched event
            signature: Matched signature
            confidence: Match confidence score
            match_details: Details about the match

        Returns:
            Alert object
        """
        alert = Alert(
            event_id=event.id,
            title=signature.name,
            description=signature.description,
            severity=signature.severity,
            status='new',
            detection_type='signature',
            confidence_score=confidence,
            signature_id=signature.id,
            matched_rules={'details': match_details},
            attack_tactics=signature.attack_tactics,
            attack_techniques=signature.attack_techniques,
            created_at=datetime.utcnow()
        )

        return alert

    def _store_alerts(self, alerts: List[Alert]):
        """Store alerts in database."""
        with db.session_scope() as session:
            for alert in alerts:
                session.add(alert)

    def process_events_batch(self, events: List[Event]) -> Dict[str, int]:
        """
        Process a batch of events and generate alerts.

        Args:
            events: List of Event objects

        Returns:
            Statistics dictionary
        """
        stats = {
            'events_processed': 0,
            'alerts_generated': 0,
            'high_severity': 0,
            'critical_severity': 0
        }

        for event in events:
            alerts = self.process_event(event)
            stats['events_processed'] += 1
            stats['alerts_generated'] += len(alerts)

            for alert in alerts:
                if alert.severity == 'high':
                    stats['high_severity'] += 1
                elif alert.severity == 'critical':
                    stats['critical_severity'] += 1

        logger.info(f"Batch processing complete: {stats}")
        return stats

    def get_alert(self, alert_id: int) -> Optional[Alert]:
        """Get an alert by ID."""
        with db.session_scope() as session:
            return session.query(Alert).filter(Alert.id == alert_id).first()

    def get_alerts(self,
                   severity: Optional[str] = None,
                   status: Optional[str] = None,
                   limit: int = 100,
                   offset: int = 0) -> List[Alert]:
        """
        Retrieve alerts with filtering.

        Args:
            severity: Filter by severity
            status: Filter by status
            limit: Maximum alerts to return
            offset: Number of alerts to skip

        Returns:
            List of Alert objects
        """
        with db.session_scope() as session:
            query = session.query(Alert)

            if severity:
                query = query.filter(Alert.severity == severity)

            if status:
                query = query.filter(Alert.status == status)

            query = query.order_by(Alert.created_at.desc())
            query = query.limit(limit).offset(offset)

            return query.all()

    def get_alert_count(self,
                        severity: Optional[str] = None,
                        status: Optional[str] = None) -> int:
        """Get count of alerts with filtering."""
        with db.session_scope() as session:
            query = session.query(Alert)

            if severity:
                query = query.filter(Alert.severity == severity)

            if status:
                query = query.filter(Alert.status == status)

            return query.count()

    def update_alert_status(self, alert_id: int, status: str,
                           resolution_notes: Optional[str] = None):
        """
        Update alert status.

        Args:
            alert_id: Alert ID
            status: New status (new, investigating, resolved, false_positive)
            resolution_notes: Optional notes
        """
        with db.session_scope() as session:
            alert = session.query(Alert).filter(Alert.id == alert_id).first()

            if not alert:
                raise ValueError(f"Alert {alert_id} not found")

            alert.status = status
            alert.updated_at = datetime.utcnow()

            if status == 'investigating':
                alert.investigated_at = datetime.utcnow()
            elif status in ['resolved', 'false_positive']:
                alert.resolved_at = datetime.utcnow()
                alert.false_positive = (status == 'false_positive')

            if resolution_notes:
                alert.resolution_notes = resolution_notes

        logger.info(f"Updated alert {alert_id} status to {status}")

    def get_alert_statistics(self) -> Dict:
        """Get overall alert statistics."""
        with db.session_scope() as session:
            total = session.query(Alert).count()
            new = session.query(Alert).filter(Alert.status == 'new').count()
            investigating = session.query(Alert).filter(Alert.status == 'investigating').count()
            resolved = session.query(Alert).filter(Alert.status == 'resolved').count()

            critical = session.query(Alert).filter(Alert.severity == 'critical').count()
            high = session.query(Alert).filter(Alert.severity == 'high').count()
            medium = session.query(Alert).filter(Alert.severity == 'medium').count()
            low = session.query(Alert).filter(Alert.severity == 'low').count()

            return {
                'total': total,
                'by_status': {
                    'new': new,
                    'investigating': investigating,
                    'resolved': resolved
                },
                'by_severity': {
                    'critical': critical,
                    'high': high,
                    'medium': medium,
                    'low': low
                }
            }


# Global alert generator instance
alert_generator = AlertGenerator()
