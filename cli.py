#!/usr/bin/env python3
"""
Command-line interface for the IDS system.
"""
import argparse
import logging
import sys
from pathlib import Path

from src.core import setup_logging, init_database, config
from src.ingestion import run_ingestion, DataPipeline
from src.detection import alert_generator, signature_manager, ioc_manager
from src.detection.detection_pipeline import DetectionPipeline, run_full_detection_pipeline
from src.detection.load_signatures import load_default_signatures

logger = logging.getLogger(__name__)


def cmd_init(args):
    """Initialize the system and database."""
    logger.info("Initializing IDS system...")
    init_database()
    logger.info("Initialization complete")


def cmd_ingest(args):
    """Run data ingestion."""
    sources = []

    if args.network:
        sources.append('network')
    if args.host:
        sources.append('host')

    if not sources:
        sources = None  # Ingest all sources

    logger.info(f"Starting ingestion: {sources or 'all sources'}")

    try:
        results = run_ingestion(sources=sources, batch_size=args.batch_size)
        logger.info("=" * 60)
        logger.info("Ingestion Results:")
        for source, count in results.items():
            logger.info(f"  {source}: {count} events")
        logger.info("=" * 60)
    except Exception as e:
        logger.error(f"Ingestion failed: {e}")
        sys.exit(1)


def cmd_stats(args):
    """Show database statistics."""
    pipeline = DataPipeline()

    total_events = pipeline.get_event_count()
    network_events = pipeline.get_event_count(event_type='network')
    host_events = pipeline.get_event_count(event_type='host')

    logger.info("=" * 60)
    logger.info("Database Statistics:")
    logger.info(f"  Total events: {total_events}")
    logger.info(f"  Network events: {network_events}")
    logger.info(f"  Host events: {host_events}")

    # Alert statistics
    alert_stats = alert_generator.get_alert_statistics()
    logger.info(f"\n  Total alerts: {alert_stats['total']}")
    logger.info(f"  New alerts: {alert_stats['by_status']['new']}")
    logger.info(f"  Investigating: {alert_stats['by_status']['investigating']}")
    logger.info(f"  Resolved: {alert_stats['by_status']['resolved']}")

    logger.info(f"\n  Critical: {alert_stats['by_severity']['critical']}")
    logger.info(f"  High: {alert_stats['by_severity']['high']}")
    logger.info(f"  Medium: {alert_stats['by_severity']['medium']}")
    logger.info(f"  Low: {alert_stats['by_severity']['low']}")

    # Signature statistics
    signatures = signature_manager.get_all_signatures(enabled_only=False)
    enabled_sigs = [s for s in signatures if s.enabled]
    logger.info(f"\n  Signatures: {len(enabled_sigs)}/{len(signatures)} enabled")

    # IOC statistics
    ioc_stats = ioc_manager.get_statistics()
    logger.info(f"  IOCs: {ioc_stats['active']}/{ioc_stats['total']} active")

    logger.info("=" * 60)

    if args.verbose and total_events > 0:
        logger.info("\nRecent events:")
        recent = pipeline.get_events(limit=10)
        for event in recent:
            logger.info(f"  [{event.timestamp}] {event.event_type} - {event.source}")


def cmd_load_signatures(args):
    """Load default signatures into database."""
    logger.info("Loading default signatures...")
    loaded, skipped = load_default_signatures()
    logger.info(f"Loaded {loaded} new signatures, skipped {skipped} existing")


def cmd_detect(args):
    """Run signature detection on existing events."""
    logger.info("Running detection on existing events...")

    detection_pipeline = DetectionPipeline()
    stats = detection_pipeline.run_detection_on_existing_events(
        event_type=args.event_type,
        batch_size=args.batch_size
    )

    logger.info("=" * 60)
    logger.info("Detection Results:")
    logger.info(f"  Events processed: {stats['events_processed']}")
    logger.info(f"  Alerts generated: {stats['alerts_generated']}")
    logger.info(f"  Critical: {stats.get('critical', 0)}")
    logger.info(f"  High: {stats.get('high', 0)}")
    logger.info(f"  Medium: {stats.get('medium', 0)}")
    logger.info(f"  Low: {stats.get('low', 0)}")
    logger.info("=" * 60)


def cmd_ingest_detect(args):
    """Ingest data and run detection in one step."""
    sources = []

    if args.network:
        sources.append('network')
    if args.host:
        sources.append('host')

    if not sources:
        sources = None

    logger.info(f"Running integrated pipeline: {sources or 'all sources'}")

    try:
        stats = run_full_detection_pipeline(sources=sources)

        logger.info("=" * 60)
        logger.info("Ingestion Results:")
        for source, count in stats['ingestion'].items():
            logger.info(f"  {source}: {count} events")

        logger.info("\nDetection Results:")
        logger.info(f"  Events processed: {stats['detection']['events_processed']}")
        logger.info(f"  Alerts generated: {stats['detection']['alerts_generated']}")
        logger.info(f"  Critical: {stats['detection'].get('critical', 0)}")
        logger.info(f"  High: {stats['detection'].get('high', 0)}")
        logger.info(f"  Medium: {stats['detection'].get('medium', 0)}")
        logger.info(f"  Low: {stats['detection'].get('low', 0)}")
        logger.info("=" * 60)
    except Exception as e:
        logger.error(f"Pipeline failed: {e}", exc_info=True)
        sys.exit(1)


def cmd_alerts(args):
    """Show alerts."""
    alerts = alert_generator.get_alerts(
        severity=args.severity,
        status=args.status,
        limit=args.limit
    )

    if not alerts:
        logger.info("No alerts found")
        return

    logger.info("=" * 60)
    logger.info(f"Showing {len(alerts)} alerts:")
    logger.info("=" * 60)

    for alert in alerts:
        logger.info(f"\n[{alert.severity.upper()}] {alert.title}")
        logger.info(f"  ID: {alert.id}")
        logger.info(f"  Status: {alert.status}")
        logger.info(f"  Confidence: {alert.confidence_score:.2f}")
        logger.info(f"  Created: {alert.created_at}")
        if args.verbose:
            logger.info(f"  Description: {alert.description}")
            logger.info(f"  Event ID: {alert.event_id}")


def cmd_update_iocs(args):
    """Update IOCs from threat intelligence feeds."""
    logger.info("Updating IOC feeds...")
    results = ioc_manager.update_feeds()

    logger.info("=" * 60)
    logger.info("IOC Feed Update Results:")
    for feed_name, count in results.items():
        logger.info(f"  {feed_name}: {count} IOCs")
    logger.info("=" * 60)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='AI-Powered Intrusion Detection System CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Init command
    parser_init = subparsers.add_parser('init', help='Initialize the system')
    parser_init.set_defaults(func=cmd_init)

    # Ingest command
    parser_ingest = subparsers.add_parser('ingest', help='Ingest data from sources')
    parser_ingest.add_argument(
        '--network',
        action='store_true',
        help='Ingest network traffic (PCAP files)'
    )
    parser_ingest.add_argument(
        '--host',
        action='store_true',
        help='Ingest host logs'
    )
    parser_ingest.add_argument(
        '--batch-size',
        type=int,
        default=100,
        help='Batch size for database inserts (default: 100)'
    )
    parser_ingest.set_defaults(func=cmd_ingest)

    # Stats command
    parser_stats = subparsers.add_parser('stats', help='Show database statistics')
    parser_stats.add_argument(
        '--verbose',
        action='store_true',
        help='Show recent events'
    )
    parser_stats.set_defaults(func=cmd_stats)

    # Load signatures command
    parser_load_sigs = subparsers.add_parser('load-signatures', help='Load default signatures')
    parser_load_sigs.set_defaults(func=cmd_load_signatures)

    # Detect command
    parser_detect = subparsers.add_parser('detect', help='Run detection on existing events')
    parser_detect.add_argument(
        '--event-type',
        choices=['network', 'host'],
        help='Filter by event type'
    )
    parser_detect.add_argument(
        '--batch-size',
        type=int,
        default=100,
        help='Batch size for processing (default: 100)'
    )
    parser_detect.set_defaults(func=cmd_detect)

    # Ingest and detect command
    parser_ingest_detect = subparsers.add_parser('ingest-detect', help='Ingest and detect in one step')
    parser_ingest_detect.add_argument(
        '--network',
        action='store_true',
        help='Ingest network traffic'
    )
    parser_ingest_detect.add_argument(
        '--host',
        action='store_true',
        help='Ingest host logs'
    )
    parser_ingest_detect.set_defaults(func=cmd_ingest_detect)

    # Alerts command
    parser_alerts = subparsers.add_parser('alerts', help='Show alerts')
    parser_alerts.add_argument(
        '--severity',
        choices=['low', 'medium', 'high', 'critical'],
        help='Filter by severity'
    )
    parser_alerts.add_argument(
        '--status',
        choices=['new', 'investigating', 'resolved', 'false_positive'],
        help='Filter by status'
    )
    parser_alerts.add_argument(
        '--limit',
        type=int,
        default=20,
        help='Maximum alerts to show (default: 20)'
    )
    parser_alerts.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed alert information'
    )
    parser_alerts.set_defaults(func=cmd_alerts)

    # Update IOCs command
    parser_update_iocs = subparsers.add_parser('update-iocs', help='Update IOC feeds')
    parser_update_iocs.set_defaults(func=cmd_update_iocs)

    args = parser.parse_args()

    # Setup logging
    setup_logging()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Execute command
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
