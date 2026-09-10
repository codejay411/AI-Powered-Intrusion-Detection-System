"""
Data pipeline orchestrator - ingests, processes, and stores events.
"""
import logging
from typing import Dict, List, Optional, Generator
from datetime import datetime
from pathlib import Path

from src.core.database import db
from src.core.models import Event
from src.ingestion.network_ingestion import NetworkIngestion, ingest_network_traffic
from src.ingestion.host_ingestion import HostIngestion, ingest_host_logs
from src.ingestion.feature_extraction import FeatureExtractor

logger = logging.getLogger(__name__)


class DataPipeline:
    """Orchestrates data ingestion, feature extraction, and storage."""

    def __init__(self):
        self.network_ingestion = None
        self.host_ingestion = None
        self.feature_extractor = FeatureExtractor()

        # Initialize ingestors lazily
        self._init_ingestors()

    def _init_ingestors(self):
        """Initialize ingestion modules."""
        try:
            self.network_ingestion = NetworkIngestion()
        except ImportError:
            logger.warning("Network ingestion not available (scapy not installed)")

        self.host_ingestion = HostIngestion()

    def ingest_and_store_network(self, source: str = 'pcap',
                                  batch_size: int = 100) -> int:
        """
        Ingest network traffic and store in database.

        Args:
            source: Source type ('pcap', 'live', 'netflow')
            batch_size: Number of events to batch before committing

        Returns:
            Number of events processed
        """
        if not self.network_ingestion:
            logger.error("Network ingestion not available")
            return 0

        logger.info(f"Starting network ingestion from {source}")
        event_count = 0
        batch = []

        try:
            for event_dict in ingest_network_traffic(source):
                # Extract features
                features = self.feature_extractor.extract_features(event_dict)
                event_dict['features'] = features

                # Create Event model
                event = self._create_event_model(event_dict)
                batch.append(event)

                # Batch insert
                if len(batch) >= batch_size:
                    self._store_events(batch)
                    event_count += len(batch)
                    batch = []
                    logger.info(f"Processed {event_count} network events")

            # Store remaining events
            if batch:
                self._store_events(batch)
                event_count += len(batch)

            logger.info(f"Network ingestion complete: {event_count} events")
            return event_count

        except Exception as e:
            logger.error(f"Error during network ingestion: {e}")
            raise

    def ingest_and_store_host(self, directory: Optional[Path] = None,
                               batch_size: int = 100) -> int:
        """
        Ingest host logs and store in database.

        Args:
            directory: Directory containing log files
            batch_size: Number of events to batch before committing

        Returns:
            Number of events processed
        """
        logger.info(f"Starting host log ingestion from {directory or 'default directory'}")
        event_count = 0
        batch = []

        try:
            for event_dict in ingest_host_logs(str(directory) if directory else None):
                # Extract features
                features = self.feature_extractor.extract_features(event_dict)
                event_dict['features'] = features

                # Create Event model
                event = self._create_event_model(event_dict)
                batch.append(event)

                # Batch insert
                if len(batch) >= batch_size:
                    self._store_events(batch)
                    event_count += len(batch)
                    batch = []
                    logger.info(f"Processed {event_count} host events")

            # Store remaining events
            if batch:
                self._store_events(batch)
                event_count += len(batch)

            logger.info(f"Host log ingestion complete: {event_count} events")
            return event_count

        except Exception as e:
            logger.error(f"Error during host log ingestion: {e}")
            raise

    def ingest_all(self, batch_size: int = 100) -> Dict[str, int]:
        """
        Ingest all configured data sources.

        Args:
            batch_size: Number of events to batch before committing

        Returns:
            Dictionary with counts per source
        """
        results = {
            'network': 0,
            'host': 0,
            'total': 0
        }

        # Ingest network traffic
        try:
            if self.network_ingestion:
                results['network'] = self.ingest_and_store_network(
                    source='pcap',
                    batch_size=batch_size
                )
        except Exception as e:
            logger.error(f"Network ingestion failed: {e}")

        # Ingest host logs
        try:
            results['host'] = self.ingest_and_store_host(
                batch_size=batch_size
            )
        except Exception as e:
            logger.error(f"Host ingestion failed: {e}")

        results['total'] = results['network'] + results['host']

        logger.info(f"Total ingestion complete: {results}")
        return results

    def _create_event_model(self, event_dict: Dict) -> Event:
        """Create Event model instance from dictionary."""
        event = Event(
            timestamp=event_dict.get('timestamp', datetime.utcnow()),
            event_type=event_dict.get('event_type'),
            source=event_dict.get('source'),

            # Network fields
            src_ip=event_dict.get('src_ip'),
            dst_ip=event_dict.get('dst_ip'),
            src_port=event_dict.get('src_port'),
            dst_port=event_dict.get('dst_port'),
            protocol=event_dict.get('protocol'),
            bytes_sent=event_dict.get('bytes_sent'),
            bytes_received=event_dict.get('bytes_received'),
            packets_sent=event_dict.get('packets_sent'),
            packets_received=event_dict.get('packets_received'),

            # Host fields
            hostname=event_dict.get('hostname'),
            username=event_dict.get('username'),
            process_name=event_dict.get('process_name'),
            process_id=event_dict.get('process_id'),
            command_line=event_dict.get('command_line'),
            parent_process=event_dict.get('parent_process'),

            # Common fields
            raw_data=event_dict.get('raw_data'),
            features=event_dict.get('features')
        )

        return event

    def _store_events(self, events: List[Event]):
        """Store batch of events in database."""
        with db.session_scope() as session:
            session.bulk_save_objects(events)
        logger.debug(f"Stored {len(events)} events")

    def get_events(self, event_type: Optional[str] = None,
                   limit: int = 100,
                   offset: int = 0) -> List[Event]:
        """
        Retrieve events from database.

        Args:
            event_type: Filter by event type ('network', 'host', or None for all)
            limit: Maximum number of events to return
            offset: Number of events to skip

        Returns:
            List of Event objects
        """
        with db.session_scope() as session:
            query = session.query(Event)

            if event_type:
                query = query.filter(Event.event_type == event_type)

            query = query.order_by(Event.timestamp.desc())
            query = query.limit(limit).offset(offset)

            return query.all()

    def get_event_count(self, event_type: Optional[str] = None) -> int:
        """
        Get total count of events.

        Args:
            event_type: Filter by event type or None for all

        Returns:
            Count of events
        """
        with db.session_scope() as session:
            query = session.query(Event)

            if event_type:
                query = query.filter(Event.event_type == event_type)

            return query.count()

    def clear_cache(self):
        """Clear feature extractor cache."""
        self.feature_extractor.clear_cache()


# Convenience functions
def run_ingestion(sources: Optional[List[str]] = None, batch_size: int = 100) -> Dict[str, int]:
    """
    Run data ingestion pipeline.

    Args:
        sources: List of sources to ingest ('network', 'host', or None for all)
        batch_size: Batch size for database inserts

    Returns:
        Dictionary with ingestion statistics
    """
    pipeline = DataPipeline()

    if sources is None:
        return pipeline.ingest_all(batch_size=batch_size)

    results = {'total': 0}

    if 'network' in sources:
        try:
            results['network'] = pipeline.ingest_and_store_network(batch_size=batch_size)
            results['total'] += results['network']
        except Exception as e:
            logger.error(f"Network ingestion failed: {e}")
            results['network'] = 0

    if 'host' in sources:
        try:
            results['host'] = pipeline.ingest_and_store_host(batch_size=batch_size)
            results['total'] += results['host']
        except Exception as e:
            logger.error(f"Host ingestion failed: {e}")
            results['host'] = 0

    return results
