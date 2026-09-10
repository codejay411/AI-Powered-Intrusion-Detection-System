"""
IOC (Indicator of Compromise) feed management and integration.
"""
import logging
import requests
from typing import Dict, List, Optional
from datetime import datetime
import csv
from io import StringIO

from src.core.database import db
from src.core.models import IOC
from src.core.config import config

logger = logging.getLogger(__name__)


class IOCManager:
    """Manage IOC feeds and indicators."""

    def __init__(self):
        self.feeds = config.get('signatures.ioc_feeds', [])

    def add_ioc(self, ioc_data: Dict) -> IOC:
        """
        Add a single IOC to the database.

        Args:
            ioc_data: Dictionary containing IOC fields

        Returns:
            Created IOC object
        """
        with db.session_scope() as session:
            # Check if IOC already exists
            existing = session.query(IOC).filter(
                IOC.ioc_type == ioc_data['ioc_type'],
                IOC.value == ioc_data['value']
            ).first()

            if existing:
                # Update existing IOC
                existing.last_seen = datetime.utcnow()
                existing.confidence = ioc_data.get('confidence', existing.confidence)
                existing.is_active = ioc_data.get('is_active', True)
                logger.debug(f"Updated existing IOC: {ioc_data['value']}")
                return existing

            # Create new IOC
            ioc = IOC(
                ioc_type=ioc_data['ioc_type'],
                value=ioc_data['value'],
                threat_type=ioc_data.get('threat_type'),
                confidence=ioc_data.get('confidence', 0.5),
                severity=ioc_data.get('severity'),
                source=ioc_data.get('source', 'manual'),
                description=ioc_data.get('description'),
                tags=ioc_data.get('tags', []),
                is_active=ioc_data.get('is_active', True),
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow()
            )

            session.add(ioc)
            session.flush()
            ioc_id = ioc.id

        logger.info(f"Added IOC: {ioc_data['ioc_type']}:{ioc_data['value']} (ID: {ioc_id})")
        return ioc

    def add_iocs_batch(self, iocs: List[Dict]) -> int:
        """
        Add multiple IOCs in batch.

        Args:
            iocs: List of IOC dictionaries

        Returns:
            Number of IOCs added
        """
        count = 0
        for ioc_data in iocs:
            try:
                self.add_ioc(ioc_data)
                count += 1
            except Exception as e:
                logger.error(f"Error adding IOC {ioc_data.get('value')}: {e}")

        logger.info(f"Added {count} IOCs in batch")
        return count

    def get_ioc(self, ioc_type: str, value: str) -> Optional[IOC]:
        """Get an IOC by type and value."""
        with db.session_scope() as session:
            return session.query(IOC).filter(
                IOC.ioc_type == ioc_type,
                IOC.value == value,
                IOC.is_active == True
            ).first()

    def get_iocs_by_type(self, ioc_type: str, active_only: bool = True) -> List[IOC]:
        """Get all IOCs of a specific type."""
        with db.session_scope() as session:
            query = session.query(IOC).filter(IOC.ioc_type == ioc_type)

            if active_only:
                query = query.filter(IOC.is_active == True)

            return query.all()

    def check_ioc(self, ioc_type: str, value: str) -> Optional[IOC]:
        """
        Check if a value matches any known IOC.

        Args:
            ioc_type: Type of IOC (ip, domain, hash, url)
            value: Value to check

        Returns:
            Matched IOC or None
        """
        return self.get_ioc(ioc_type, value)

    def deactivate_ioc(self, ioc_id: int):
        """Deactivate an IOC."""
        with db.session_scope() as session:
            ioc = session.query(IOC).filter(IOC.id == ioc_id).first()
            if ioc:
                ioc.is_active = False
                logger.info(f"Deactivated IOC {ioc_id}")

    def update_feeds(self) -> Dict[str, int]:
        """
        Update IOCs from configured feeds.

        Returns:
            Dictionary with update statistics per feed
        """
        results = {}

        for feed in self.feeds:
            if not feed.get('enabled', False):
                continue

            feed_name = feed['name']
            feed_url = feed['url']

            try:
                logger.info(f"Updating IOC feed: {feed_name}")
                iocs = self._fetch_feed(feed_name, feed_url)
                count = self.add_iocs_batch(iocs)
                results[feed_name] = count
            except Exception as e:
                logger.error(f"Error updating feed {feed_name}: {e}")
                results[feed_name] = 0

        return results

    def _fetch_feed(self, feed_name: str, feed_url: str) -> List[Dict]:
        """
        Fetch IOCs from a threat intelligence feed.

        Args:
            feed_name: Name of the feed
            feed_url: URL to fetch from

        Returns:
            List of IOC dictionaries
        """
        iocs = []

        try:
            response = requests.get(feed_url, timeout=30)
            response.raise_for_status()

            # Parse based on feed name
            if 'abuse_ch' in feed_name.lower():
                iocs = self._parse_abuse_ch_feed(response.text)
            elif 'csv' in feed_url.lower():
                iocs = self._parse_csv_feed(response.text, feed_name)
            else:
                # Generic line-based feed
                iocs = self._parse_line_feed(response.text, feed_name)

        except Exception as e:
            logger.error(f"Error fetching feed {feed_name}: {e}")

        return iocs

    def _parse_abuse_ch_feed(self, content: str) -> List[Dict]:
        """Parse Abuse.ch SSL Blacklist format."""
        iocs = []

        for line in content.split('\n'):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Abuse.ch format: timestamp,ip,port
            parts = line.split(',')
            if len(parts) >= 2:
                ip = parts[1].strip()
                iocs.append({
                    'ioc_type': 'ip',
                    'value': ip,
                    'threat_type': 'c2',
                    'confidence': 0.8,
                    'severity': 'high',
                    'source': 'abuse_ch',
                    'description': 'SSL Blacklist - C2 server',
                    'tags': ['c2', 'ssl', 'abuse_ch']
                })

        return iocs

    def _parse_csv_feed(self, content: str, source: str) -> List[Dict]:
        """Parse generic CSV feed."""
        iocs = []

        reader = csv.DictReader(StringIO(content))

        for row in reader:
            # Try to determine IOC type from columns
            ioc_value = None
            ioc_type = None

            if 'ip' in row or 'IP' in row:
                ioc_value = row.get('ip') or row.get('IP')
                ioc_type = 'ip'
            elif 'domain' in row or 'Domain' in row:
                ioc_value = row.get('domain') or row.get('Domain')
                ioc_type = 'domain'
            elif 'hash' in row or 'Hash' in row:
                ioc_value = row.get('hash') or row.get('Hash')
                ioc_type = 'hash'

            if ioc_value and ioc_type:
                iocs.append({
                    'ioc_type': ioc_type,
                    'value': ioc_value,
                    'threat_type': row.get('threat_type', 'unknown'),
                    'confidence': 0.7,
                    'severity': row.get('severity', 'medium'),
                    'source': source,
                    'tags': [source]
                })

        return iocs

    def _parse_line_feed(self, content: str, source: str) -> List[Dict]:
        """Parse line-based feed (one IOC per line)."""
        iocs = []

        for line in content.split('\n'):
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            # Try to determine IOC type
            ioc_type = self._detect_ioc_type(line)

            if ioc_type:
                iocs.append({
                    'ioc_type': ioc_type,
                    'value': line,
                    'confidence': 0.6,
                    'severity': 'medium',
                    'source': source,
                    'tags': [source]
                })

        return iocs

    @staticmethod
    def _detect_ioc_type(value: str) -> Optional[str]:
        """Detect IOC type from value."""
        import re

        # IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return 'ip'

        # Domain
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', value):
            return 'domain'

        # Hash (MD5, SHA1, SHA256)
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return 'hash'
        if re.match(r'^[a-fA-F0-9]{40}$', value):
            return 'hash'
        if re.match(r'^[a-fA-F0-9]{64}$', value):
            return 'hash'

        # URL
        if value.startswith('http://') or value.startswith('https://'):
            return 'url'

        return None

    def get_statistics(self) -> Dict:
        """Get IOC statistics."""
        with db.session_scope() as session:
            total = session.query(IOC).count()
            active = session.query(IOC).filter(IOC.is_active == True).count()

            by_type = {}
            for ioc_type in ['ip', 'domain', 'hash', 'url']:
                count = session.query(IOC).filter(
                    IOC.ioc_type == ioc_type,
                    IOC.is_active == True
                ).count()
                by_type[ioc_type] = count

            return {
                'total': total,
                'active': active,
                'by_type': by_type
            }


# Global IOC manager instance
ioc_manager = IOCManager()
