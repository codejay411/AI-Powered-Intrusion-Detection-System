"""
Feature extraction from normalized events for ML models.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict, Counter
import numpy as np
import hashlib

from src.core.config import config

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Extract features from normalized events for ML models."""

    def __init__(self):
        self.config = config.get('features')
        # State tracking for temporal features
        self.flow_cache = defaultdict(dict)  # Track flows for connection-based features
        self.host_cache = defaultdict(dict)  # Track host behavior over time

    def extract_network_features(self, event: Dict) -> Dict:
        """
        Extract network features from a network event.

        Args:
            event: Normalized network event

        Returns:
            Dictionary of extracted features
        """
        features = {}

        # Basic packet/flow statistics
        features['bytes_sent'] = event.get('bytes_sent', 0)
        features['bytes_received'] = event.get('bytes_received', 0)
        features['packets_sent'] = event.get('packets_sent', 0)
        features['packets_received'] = event.get('packets_received', 0)
        features['total_bytes'] = features['bytes_sent'] + features['bytes_received']
        features['total_packets'] = features['packets_sent'] + features['packets_received']

        # Average packet size
        if features['total_packets'] > 0:
            features['avg_packet_size'] = features['total_bytes'] / features['total_packets']
        else:
            features['avg_packet_size'] = 0

        # Protocol encoding
        protocol = event.get('protocol', 'unknown').upper()
        features['protocol_tcp'] = 1 if protocol == 'TCP' else 0
        features['protocol_udp'] = 1 if protocol == 'UDP' else 0
        features['protocol_icmp'] = 1 if protocol == 'ICMP' else 0
        features['protocol_other'] = 1 if protocol not in ['TCP', 'UDP', 'ICMP'] else 0

        # Port features
        src_port = event.get('src_port', 0)
        dst_port = event.get('dst_port', 0)

        features['src_port'] = src_port
        features['dst_port'] = dst_port
        features['well_known_port_src'] = 1 if src_port < 1024 else 0
        features['well_known_port_dst'] = 1 if dst_port < 1024 else 0
        features['ephemeral_port_src'] = 1 if src_port >= 49152 else 0
        features['ephemeral_port_dst'] = 1 if dst_port >= 49152 else 0

        # Common service ports (boolean flags)
        service_ports = {
            'http': [80, 8080],
            'https': [443, 8443],
            'ssh': [22],
            'ftp': [21],
            'dns': [53],
            'smtp': [25, 587],
            'telnet': [23],
            'rdp': [3389],
            'smb': [445, 139]
        }

        for service, ports in service_ports.items():
            features[f'service_{service}'] = 1 if dst_port in ports else 0

        # IP-based features
        src_ip = event.get('src_ip', '')
        dst_ip = event.get('dst_ip', '')

        features['is_private_src'] = 1 if self._is_private_ip(src_ip) else 0
        features['is_private_dst'] = 1 if self._is_private_ip(dst_ip) else 0

        # Temporal/flow-based features (requires state tracking)
        flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        features.update(self._extract_flow_features(flow_key, event))

        # TCP-specific features
        if protocol == 'TCP':
            raw_data = event.get('raw_data', {})
            tcp_flags = raw_data.get('tcp_flags', '')
            features['tcp_syn'] = 1 if 'S' in tcp_flags else 0
            features['tcp_ack'] = 1 if 'A' in tcp_flags else 0
            features['tcp_fin'] = 1 if 'F' in tcp_flags else 0
            features['tcp_rst'] = 1 if 'R' in tcp_flags else 0
            features['tcp_psh'] = 1 if 'P' in tcp_flags else 0

        return features

    def extract_host_features(self, event: Dict) -> Dict:
        """
        Extract host features from a host event.

        Args:
            event: Normalized host event

        Returns:
            Dictionary of extracted features
        """
        features = {}

        hostname = event.get('hostname', 'unknown')
        username = event.get('username', 'unknown')
        process_name = event.get('process_name', 'unknown')

        # Process-based features
        features['has_process'] = 1 if process_name != 'unknown' else 0

        # Common system processes (boolean flags)
        system_processes = ['svchost', 'explorer', 'system', 'services', 'lsass', 'csrss']
        features['is_system_process'] = 1 if any(sp in process_name.lower() for sp in system_processes) else 0

        # Shell/scripting indicators
        shell_processes = ['bash', 'sh', 'cmd', 'powershell', 'python', 'perl', 'ruby']
        features['is_shell'] = 1 if any(sh in process_name.lower() for sh in shell_processes) else 0

        # Command line features
        command_line = event.get('command_line', '')
        if command_line:
            features['cmd_length'] = len(command_line)
            features['cmd_has_pipe'] = 1 if '|' in command_line else 0
            features['cmd_has_redirect'] = 1 if '>' in command_line or '<' in command_line else 0
            features['cmd_has_background'] = 1 if '&' in command_line else 0

            # Suspicious command patterns
            suspicious_patterns = ['wget', 'curl', 'nc', 'netcat', 'powershell -enc', 'base64', 'eval']
            features['cmd_suspicious'] = 1 if any(pat in command_line.lower() for pat in suspicious_patterns) else 0
        else:
            features['cmd_length'] = 0
            features['cmd_has_pipe'] = 0
            features['cmd_has_redirect'] = 0
            features['cmd_has_background'] = 0
            features['cmd_suspicious'] = 0

        # User features
        features['has_username'] = 1 if username != 'unknown' else 0
        features['is_root'] = 1 if username in ['root', 'administrator', '0'] else 0

        # Temporal/behavioral features (requires state tracking)
        host_key = f"{hostname}:{username}"
        features.update(self._extract_host_behavior_features(host_key, event))

        # Process parent-child relationship
        parent_process = event.get('parent_process', '')
        if parent_process and process_name:
            features['unusual_parent_child'] = self._is_unusual_parent_child(parent_process, process_name)
        else:
            features['unusual_parent_child'] = 0

        return features

    def _extract_flow_features(self, flow_key: str, event: Dict) -> Dict:
        """Extract temporal features for a network flow."""
        features = {}

        current_time = event.get('timestamp', datetime.utcnow())

        if flow_key not in self.flow_cache:
            self.flow_cache[flow_key] = {
                'first_seen': current_time,
                'last_seen': current_time,
                'packet_count': 0,
                'byte_count': 0
            }
        else:
            flow = self.flow_cache[flow_key]

            # Flow duration
            duration = (current_time - flow['first_seen']).total_seconds()
            features['flow_duration'] = duration

            # Packet/byte rate
            if duration > 0:
                features['packets_per_second'] = flow['packet_count'] / duration
                features['bytes_per_second'] = flow['byte_count'] / duration
            else:
                features['packets_per_second'] = 0
                features['bytes_per_second'] = 0

            # Update flow state
            flow['last_seen'] = current_time

        # Update counters
        self.flow_cache[flow_key]['packet_count'] += event.get('packets_sent', 0)
        self.flow_cache[flow_key]['byte_count'] += event.get('bytes_sent', 0)

        return features

    def _extract_host_behavior_features(self, host_key: str, event: Dict) -> Dict:
        """Extract behavioral features for a host over time."""
        features = {}

        current_time = event.get('timestamp', datetime.utcnow())
        time_window = timedelta(minutes=5)  # 5-minute window

        if host_key not in self.host_cache:
            self.host_cache[host_key] = {
                'process_spawns': [],
                'login_attempts': [],
                'commands': []
            }

        host_state = self.host_cache[host_key]

        # Clean old entries outside time window
        cutoff_time = current_time - time_window
        host_state['process_spawns'] = [t for t in host_state['process_spawns'] if t > cutoff_time]
        host_state['login_attempts'] = [t for t in host_state['login_attempts'] if t > cutoff_time]
        host_state['commands'] = [t for t in host_state['commands'] if t > cutoff_time]

        # Process spawn rate
        if event.get('process_name'):
            host_state['process_spawns'].append(current_time)
        features['process_spawn_rate'] = len(host_state['process_spawns']) / time_window.total_seconds() * 60

        # Login frequency
        raw_data = event.get('raw_data', {})
        if 'login' in raw_data.get('message', '').lower():
            host_state['login_attempts'].append(current_time)
        features['login_frequency'] = len(host_state['login_attempts'])

        # Command execution rate
        if event.get('command_line'):
            host_state['commands'].append(current_time)
        features['command_execution_rate'] = len(host_state['commands']) / time_window.total_seconds() * 60

        return features

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP address is in private range."""
        if not ip:
            return False

        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False  # IPv6 or invalid

            first = int(parts[0])
            second = int(parts[1])

            # Private IP ranges
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:  # Loopback
                return True

            return False
        except (ValueError, IndexError):
            return False

    @staticmethod
    def _is_unusual_parent_child(parent: str, child: str) -> int:
        """Detect unusual parent-child process relationships."""
        parent = parent.lower()
        child = child.lower()

        # Common unusual patterns
        unusual_patterns = [
            ('explorer' in parent and any(x in child for x in ['cmd', 'powershell', 'bash'])),
            ('word' in parent or 'excel' in parent) and ('cmd' in child or 'powershell' in child),
            ('iexplore' in parent or 'chrome' in parent) and ('cmd' in child or 'powershell' in child),
        ]

        return 1 if any(unusual_patterns) else 0

    def extract_features(self, event: Dict) -> Dict:
        """
        Extract features based on event type.

        Args:
            event: Normalized event dictionary

        Returns:
            Dictionary of extracted features
        """
        event_type = event.get('event_type')

        if event_type == 'network':
            return self.extract_network_features(event)
        elif event_type == 'host':
            return self.extract_host_features(event)
        else:
            logger.warning(f"Unknown event type: {event_type}")
            return {}

    def clear_cache(self):
        """Clear cached state (use periodically to prevent memory growth)."""
        self.flow_cache.clear()
        self.host_cache.clear()
        logger.info("Feature extractor cache cleared")
