"""
Host log ingestion from various sources (syslog, Windows Events, auditd).
"""
import logging
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Generator
import xml.etree.ElementTree as ET

from src.core.config import config

logger = logging.getLogger(__name__)


class HostIngestion:
    """Host log ingestion and parsing."""

    def __init__(self):
        self.config = config.get('ingestion.host')

    def parse_log_directory(self, directory: Optional[Path] = None) -> Generator[Dict, None, None]:
        """
        Parse all log files in a directory.

        Args:
            directory: Directory containing log files (defaults to config)

        Yields:
            Normalized host event dictionaries
        """
        if directory is None:
            directory = config.data_path / "logs"

        log_files = (
            list(directory.glob("*.log")) +
            list(directory.glob("*.json")) +
            list(directory.glob("*.evtx")) +
            list(directory.glob("*.xml"))
        )

        if not log_files:
            logger.warning(f"No log files found in {directory}")
            return

        logger.info(f"Found {len(log_files)} log files")

        for log_file in log_files:
            yield from self.parse_log_file(log_file)

    def parse_log_file(self, log_path: Path) -> Generator[Dict, None, None]:
        """
        Parse a single log file and yield normalized events.

        Args:
            log_path: Path to log file

        Yields:
            Normalized host event dictionaries
        """
        logger.info(f"Parsing log file: {log_path}")

        try:
            suffix = log_path.suffix.lower()

            if suffix == '.json':
                yield from self._parse_json_log(log_path)
            elif suffix == '.log':
                yield from self._parse_text_log(log_path)
            elif suffix in ['.evtx', '.xml']:
                yield from self._parse_windows_event_log(log_path)
            else:
                logger.warning(f"Unknown log format: {suffix}")

        except Exception as e:
            logger.error(f"Error parsing log file {log_path}: {e}")

    def _parse_json_log(self, log_path: Path) -> Generator[Dict, None, None]:
        """Parse JSON-formatted logs (one JSON object per line)."""
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    log_entry = json.loads(line)
                    event = self._normalize_json_event(log_entry, log_path.name)
                    if event:
                        yield event
                except json.JSONDecodeError as e:
                    logger.debug(f"JSON parse error at {log_path.name}:{line_num}: {e}")

    def _parse_text_log(self, log_path: Path) -> Generator[Dict, None, None]:
        """Parse text-based logs (syslog, auditd, etc.)."""
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                try:
                    # Detect log format
                    if 'type=SYSCALL' in line or 'type=EXECVE' in line:
                        event = self._parse_auditd_line(line, log_path.name)
                    elif re.match(r'^<\d+>', line):
                        event = self._parse_syslog_line(line, log_path.name)
                    else:
                        event = self._parse_generic_log_line(line, log_path.name)

                    if event:
                        yield event

                except Exception as e:
                    logger.debug(f"Error parsing line {line_num} in {log_path.name}: {e}")

    def _parse_windows_event_log(self, log_path: Path) -> Generator[Dict, None, None]:
        """Parse Windows Event Log XML format."""
        try:
            tree = ET.parse(log_path)
            root = tree.getroot()

            for event_elem in root.findall('.//Event'):
                event = self._parse_windows_event_xml(event_elem, log_path.name)
                if event:
                    yield event

        except ET.ParseError as e:
            logger.error(f"XML parse error in {log_path.name}: {e}")

    def _normalize_json_event(self, log_entry: Dict, source: str) -> Optional[Dict]:
        """Normalize JSON log entry to common format."""
        event = {
            'event_type': 'host',
            'source': source,
            'raw_data': log_entry
        }

        # Try to extract common fields
        timestamp = log_entry.get('timestamp') or log_entry.get('@timestamp') or log_entry.get('time')
        if timestamp:
            event['timestamp'] = self._parse_timestamp(timestamp)
        else:
            event['timestamp'] = datetime.utcnow()

        event['hostname'] = log_entry.get('hostname') or log_entry.get('host') or log_entry.get('computer')
        event['username'] = log_entry.get('user') or log_entry.get('username')
        event['process_name'] = log_entry.get('process') or log_entry.get('ProcessName')
        event['process_id'] = log_entry.get('pid') or log_entry.get('ProcessId')
        event['command_line'] = log_entry.get('command') or log_entry.get('CommandLine')

        return event

    def _parse_syslog_line(self, line: str, source: str) -> Optional[Dict]:
        """Parse syslog format line."""
        # Basic syslog regex: <priority>timestamp hostname process[pid]: message
        pattern = r'^<(\d+)>(\S+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.+)$'
        match = re.match(pattern, line)

        if not match:
            return None

        priority, timestamp_str, hostname, process, pid, message = match.groups()

        event = {
            'event_type': 'host',
            'timestamp': self._parse_timestamp(timestamp_str),
            'source': source,
            'hostname': hostname,
            'process_name': process,
            'process_id': int(pid) if pid else None,
            'raw_data': {
                'priority': int(priority),
                'message': message,
                'raw_line': line
            }
        }

        return event

    def _parse_auditd_line(self, line: str, source: str) -> Optional[Dict]:
        """Parse auditd log line."""
        # Extract key-value pairs from auditd log
        kv_pattern = r'(\w+)=(?:"([^"]*)"|(\S+))'
        matches = re.findall(kv_pattern, line)

        data = {}
        for key, quoted_val, unquoted_val in matches:
            data[key] = quoted_val if quoted_val else unquoted_val

        event = {
            'event_type': 'host',
            'timestamp': self._parse_timestamp(data.get('msg', '').split(':')[0]),
            'source': source,
            'hostname': data.get('hostname'),
            'username': data.get('uid'),
            'process_name': data.get('comm'),
            'process_id': int(data.get('pid')) if data.get('pid') else None,
            'command_line': data.get('a0'),  # auditd encodes args as a0, a1, etc.
            'raw_data': {
                'audit_type': data.get('type'),
                'syscall': data.get('syscall'),
                'success': data.get('success'),
                'exit': data.get('exit'),
                'all_fields': data,
                'raw_line': line
            }
        }

        return event

    def _parse_generic_log_line(self, line: str, source: str) -> Optional[Dict]:
        """Parse generic log line with minimal structure."""
        event = {
            'event_type': 'host',
            'timestamp': datetime.utcnow(),
            'source': source,
            'raw_data': {
                'message': line,
                'raw_line': line
            }
        }

        return event

    def _parse_windows_event_xml(self, event_elem: ET.Element, source: str) -> Optional[Dict]:
        """Parse Windows Event Log XML element."""
        try:
            system = event_elem.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}System')
            event_data = event_elem.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventData')

            if system is None:
                return None

            # Extract system fields
            event_id = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID').text
            time_created = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated')
            computer = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Computer')

            timestamp_str = time_created.get('SystemTime') if time_created is not None else None

            # Extract event data
            event_dict = {}
            if event_data is not None:
                for data_elem in event_data.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Data'):
                    name = data_elem.get('Name')
                    value = data_elem.text
                    if name:
                        event_dict[name] = value

            event = {
                'event_type': 'host',
                'timestamp': self._parse_timestamp(timestamp_str) if timestamp_str else datetime.utcnow(),
                'source': source,
                'hostname': computer.text if computer is not None else None,
                'username': event_dict.get('TargetUserName'),
                'process_name': event_dict.get('ProcessName'),
                'process_id': int(event_dict.get('ProcessId')) if event_dict.get('ProcessId') else None,
                'command_line': event_dict.get('CommandLine'),
                'raw_data': {
                    'event_id': event_id,
                    'event_data': event_dict,
                    'xml': ET.tostring(event_elem, encoding='unicode')
                }
            }

            return event

        except Exception as e:
            logger.debug(f"Error parsing Windows event XML: {e}")
            return None

    @staticmethod
    def _parse_timestamp(timestamp_str: str) -> datetime:
        """Parse various timestamp formats."""
        if not timestamp_str:
            return datetime.utcnow()

        # Try common formats
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',  # ISO 8601 with microseconds
            '%Y-%m-%dT%H:%M:%SZ',     # ISO 8601
            '%Y-%m-%d %H:%M:%S',      # Standard datetime
            '%b %d %H:%M:%S',         # Syslog format
            '%Y-%m-%d %H:%M:%S.%f',   # With microseconds
        ]

        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue

        # Try parsing as Unix timestamp
        try:
            return datetime.fromtimestamp(float(timestamp_str))
        except (ValueError, OSError):
            pass

        logger.debug(f"Could not parse timestamp: {timestamp_str}")
        return datetime.utcnow()


def ingest_host_logs(source: Optional[str] = None) -> Generator[Dict, None, None]:
    """
    Convenience function to ingest host logs.

    Args:
        source: Log directory path (defaults to config)

    Yields:
        Normalized host events
    """
    ingestion = HostIngestion()

    if source:
        directory = Path(source)
    else:
        directory = None

    yield from ingestion.parse_log_directory(directory)
