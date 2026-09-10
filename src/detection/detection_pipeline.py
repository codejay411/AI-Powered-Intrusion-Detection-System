"""
Integrated detection pipeline - ingestion + signature detection + alerts.
"""
import logging
from typing import Dict, List, Optional
from pathlib import Path

from src.core.database import db
from src.core.models import Event
from src.ingestion.pipeline import DataPipeline
from src.detection.alert_generator import alert_generator

logger = logging.getLogger(__name__)


class DetectionPipeline:
    """Integrated pipeline: ingest -> extract features -> detect -> alert."""

    def __init__(self):
        self.data_pipeline = DataPipeline()
        self.alert_generator = alert_generator

    def run_detection_on_existing_events(self,
                                         event_type: Optional[str] = None,
                                         batch_size: int = 100) -> Dict:
        """
        Run signature detection on existing events in database.

        Args:
            event_type: Filter by event type or None for all
            batch_size: Process events in batches

        Returns:
            Statistics dictionary
        """
        logger.info("Running detection on existing events...")

        stats = {
            'events_processed': 0,
            'alerts_generated': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        offset = 0

        while True:
            # Fetch batch of events
            events = self.data_pipeline.get_events(
                event_type=event_type,
                limit=batch_size,
                offset=offset
            )

            if not events:
                break

            # Process each event
            for event in events:
                alerts = self.alert_generator.process_event(event)
                stats['events_processed'] += 1
                stats['alerts_generated'] += len(alerts)

                for alert in alerts:
                    stats[alert.severity] = stats.get(alert.severity, 0) + 1

            offset += batch_size
            logger.info(f"Processed {stats['events_processed']} events, "
                       f"generated {stats['alerts_generated']} alerts")

        logger.info(f"Detection complete: {stats}")
        return stats

    def ingest_and_detect(self,
                          sources: Optional[List[str]] = None,
                          batch_size: int = 100) -> Dict:
        """
        Ingest data and immediately run detection.

        Args:
            sources: List of sources ('network', 'host', or None for all)
            batch_size: Batch size for ingestion

        Returns:
            Combined statistics
        """
        logger.info("Starting integrated ingestion and detection...")

        # First, ingest data
        from src.ingestion.pipeline import run_ingestion
        ingestion_stats = run_ingestion(sources=sources, batch_size=batch_size)

        # Then run detection on newly ingested events
        detection_stats = self.run_detection_on_existing_events(batch_size=batch_size)

        combined_stats = {
            'ingestion': ingestion_stats,
            'detection': detection_stats
        }

        logger.info(f"Integrated pipeline complete: {combined_stats}")
        return combined_stats

    def ingest_detect_single_source(self,
                                    source_type: str,
                                    source_path: Optional[Path] = None) -> Dict:
        """
        Ingest from a single source and detect in real-time.

        Args:
            source_type: 'network' or 'host'
            source_path: Path to source file/directory

        Returns:
            Statistics dictionary
        """
        logger.info(f"Processing {source_type} source: {source_path}")

        stats = {
            'events_ingested': 0,
            'alerts_generated': 0,
            'by_severity': {}
        }

        if source_type == 'network':
            from src.ingestion.network_ingestion import NetworkIngestion
            ingestion = NetworkIngestion()

            if source_path:
                event_generator = ingestion.parse_pcap_file(source_path)
            else:
                event_generator = ingestion.parse_pcap_directory()

        elif source_type == 'host':
            from src.ingestion.host_ingestion import HostIngestion
            ingestion = HostIngestion()

            if source_path:
                event_generator = ingestion.parse_log_file(source_path)
            else:
                event_generator = ingestion.parse_log_directory()

        else:
            raise ValueError(f"Unknown source type: {source_type}")

        # Process events one by one
        batch = []
        batch_size = 100

        for event_dict in event_generator:
            # Extract features
            features = self.data_pipeline.feature_extractor.extract_features(event_dict)
            event_dict['features'] = features

            # Create Event model
            event = self.data_pipeline._create_event_model(event_dict)
            batch.append(event)

            # Store and detect in batches
            if len(batch) >= batch_size:
                self._store_and_detect_batch(batch, stats)
                batch = []

        # Process remaining events
        if batch:
            self._store_and_detect_batch(batch, stats)

        logger.info(f"Single source processing complete: {stats}")
        return stats

    def _store_and_detect_batch(self, events: List[Event], stats: Dict):
        """Store events and run detection."""
        # Store events
        self.data_pipeline._store_events(events)
        stats['events_ingested'] += len(events)

        # Run detection on each event
        for event in events:
            # Need to get the event ID after insert
            with db.session_scope() as session:
                # Re-query to get the stored event with ID
                stored_event = session.query(Event).filter(
                    Event.timestamp == event.timestamp,
                    Event.event_type == event.event_type
                ).order_by(Event.id.desc()).first()

                if stored_event:
                    alerts = self.alert_generator.process_event(stored_event)
                    stats['alerts_generated'] += len(alerts)

                    for alert in alerts:
                        severity = alert.severity
                        stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1


# Convenience function
def run_full_detection_pipeline(sources: Optional[List[str]] = None) -> Dict:
    """
    Run the full detection pipeline: ingest + detect + alert.

    Args:
        sources: List of sources to process

    Returns:
        Combined statistics
    """
    pipeline = DetectionPipeline()
    return pipeline.ingest_and_detect(sources=sources)
