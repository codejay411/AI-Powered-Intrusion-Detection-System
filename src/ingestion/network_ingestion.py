"""
Network traffic ingestion from PCAP files and live capture.
"""
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Generator
import json

try:
    from scapy.all import rdpcap, sniff, IP, IPv6, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available. Install with: pip install scapy")

from src.core.config import config

logger = logging.getLogger(__name__)


class NetworkIngestion:
    """Network traffic ingestion and parsing."""

    def __init__(self):
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for network ingestion")

        self.config = config.get('ingestion.network')

    def parse_pcap_file(self, pcap_path: Path) -> Generator[Dict, None, None]:
        """
        Parse PCAP file and yield normalized events.

        Args:
            pcap_path: Path to PCAP file

        Yields:
            Normalized network event dictionaries
        """
        logger.info(f"Parsing PCAP file: {pcap_path}")

        try:
            packets = rdpcap(str(pcap_path))
            logger.info(f"Loaded {len(packets)} packets from {pcap_path.name}")

            for packet in packets:
                event = self._parse_packet(packet)
                if event:
                    yield event

        except Exception as e:
            logger.error(f"Error parsing PCAP file {pcap_path}: {e}")
            raise

    def parse_pcap_directory(self, directory: Optional[Path] = None) -> Generator[Dict, None, None]:
        """
        Parse all PCAP files in a directory.

        Args:
            directory: Directory containing PCAP files (defaults to config)

        Yields:
            Normalized network event dictionaries
        """
        if directory is None:
            directory = config.data_path / "pcaps"

        pcap_files = list(directory.glob("*.pcap")) + list(directory.glob("*.pcapng"))

        if not pcap_files:
            logger.warning(f"No PCAP files found in {directory}")
            return

        logger.info(f"Found {len(pcap_files)} PCAP files")

        for pcap_file in pcap_files:
            yield from self.parse_pcap_file(pcap_file)

    def live_capture(self, interface: str, packet_count: int = 0,
                     timeout: Optional[int] = None) -> Generator[Dict, None, None]:
        """
        Capture live network traffic.

        Args:
            interface: Network interface to capture from
            packet_count: Number of packets to capture (0 = infinite)
            timeout: Capture timeout in seconds

        Yields:
            Normalized network event dictionaries
        """
        logger.info(f"Starting live capture on interface: {interface}")

        def packet_handler(packet):
            return self._parse_packet(packet)

        try:
            packets = sniff(
                iface=interface,
                prn=packet_handler,
                count=packet_count,
                timeout=timeout,
                store=False
            )
        except Exception as e:
            logger.error(f"Error during live capture: {e}")
            raise

    def _parse_packet(self, packet) -> Optional[Dict]:
        """
        Parse a single packet into normalized event format.

        Args:
            packet: Scapy packet object

        Returns:
            Normalized event dictionary or None if packet can't be parsed
        """
        try:
            event = {
                'event_type': 'network',
                'timestamp': datetime.fromtimestamp(float(packet.time)),
                'source': 'pcap',
                'raw_data': {}
            }

            # Parse IP layer
            if IP in packet:
                ip_layer = packet[IP]
                event['src_ip'] = ip_layer.src
                event['dst_ip'] = ip_layer.dst
                event['protocol'] = self._get_protocol_name(ip_layer.proto)
                event['raw_data']['ip_version'] = 4
                event['raw_data']['ttl'] = ip_layer.ttl
                event['raw_data']['ip_len'] = ip_layer.len

            elif IPv6 in packet:
                ip_layer = packet[IPv6]
                event['src_ip'] = ip_layer.src
                event['dst_ip'] = ip_layer.dst
                event['protocol'] = self._get_protocol_name(ip_layer.nh)
                event['raw_data']['ip_version'] = 6
                event['raw_data']['hlim'] = ip_layer.hlim

            else:
                # Non-IP packet, skip
                return None

            # Parse transport layer
            if TCP in packet:
                tcp_layer = packet[TCP]
                event['src_port'] = tcp_layer.sport
                event['dst_port'] = tcp_layer.dport
                event['protocol'] = 'TCP'
                event['raw_data']['tcp_flags'] = str(tcp_layer.flags)
                event['raw_data']['seq'] = tcp_layer.seq
                event['raw_data']['ack'] = tcp_layer.ack
                event['raw_data']['window'] = tcp_layer.window

            elif UDP in packet:
                udp_layer = packet[UDP]
                event['src_port'] = udp_layer.sport
                event['dst_port'] = udp_layer.dport
                event['protocol'] = 'UDP'
                event['raw_data']['udp_len'] = udp_layer.len

            elif ICMP in packet:
                icmp_layer = packet[ICMP]
                event['protocol'] = 'ICMP'
                event['raw_data']['icmp_type'] = icmp_layer.type
                event['raw_data']['icmp_code'] = icmp_layer.code

            # Packet size information
            event['bytes_sent'] = len(packet)
            event['packets_sent'] = 1
            event['bytes_received'] = 0
            event['packets_received'] = 0

            # Store raw packet summary
            event['raw_data']['packet_summary'] = packet.summary()

            return event

        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None

    @staticmethod
    def _get_protocol_name(proto_num: int) -> str:
        """Convert protocol number to name."""
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            41: 'IPv6',
            47: 'GRE',
            50: 'ESP',
            51: 'AH',
            58: 'ICMPv6'
        }
        return protocols.get(proto_num, str(proto_num))

    def parse_netflow(self, netflow_data: Dict) -> Dict:
        """
        Parse NetFlow/IPFIX record into normalized format.

        Args:
            netflow_data: NetFlow record dictionary

        Returns:
            Normalized event dictionary
        """
        event = {
            'event_type': 'network',
            'timestamp': datetime.fromtimestamp(netflow_data.get('timestamp', datetime.utcnow().timestamp())),
            'source': 'netflow',
            'src_ip': netflow_data.get('srcaddr'),
            'dst_ip': netflow_data.get('dstaddr'),
            'src_port': netflow_data.get('srcport'),
            'dst_port': netflow_data.get('dstport'),
            'protocol': netflow_data.get('protocol'),
            'bytes_sent': netflow_data.get('bytes', 0),
            'packets_sent': netflow_data.get('packets', 0),
            'raw_data': netflow_data
        }

        return event


def ingest_network_traffic(source: str = 'pcap') -> Generator[Dict, None, None]:
    """
    Convenience function to ingest network traffic.

    Args:
        source: Source type ('pcap', 'live', 'netflow')

    Yields:
        Normalized network events
    """
    ingestion = NetworkIngestion()

    if source == 'pcap':
        yield from ingestion.parse_pcap_directory()
    elif source == 'live':
        interface = config.get('ingestion.network.live_capture.interface', 'eth0')
        yield from ingestion.live_capture(interface)
    else:
        raise ValueError(f"Unknown network source: {source}")
