"""
Signature matching engine - evaluates events against detection rules.
"""
import logging
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict

from src.core.models import Event, Signature
from src.detection.signature_manager import signature_manager

logger = logging.getLogger(__name__)


class SignatureEngine:
    """Pattern matching engine for signature-based detection."""

    def __init__(self):
        self.signature_manager = signature_manager
        # State tracking for stateful rules
        self.connection_tracker = defaultdict(list)  # Track connections per IP
        self.failed_login_tracker = defaultdict(list)  # Track failed logins
        self.scan_tracker = defaultdict(set)  # Track port scan attempts

    def match_event(self, event: Event) -> List[Tuple[Signature, float, Dict]]:
        """
        Match an event against all applicable signatures.

        Args:
            event: Event object to match

        Returns:
            List of (signature, confidence, match_details) tuples
        """
        matches = []

        # Get signatures for this event type
        signatures = self.signature_manager.get_signatures_by_type(event.event_type)

        for signature in signatures:
            match_result = self._evaluate_signature(event, signature)

            if match_result:
                confidence, details = match_result
                matches.append((signature, confidence, details))

                # Update last matched timestamp
                self.signature_manager.update_last_matched(signature.id)

        return matches

    def _evaluate_signature(self, event: Event, signature: Signature) -> Optional[Tuple[float, Dict]]:
        """
        Evaluate a single signature against an event.

        Args:
            event: Event to check
            signature: Signature rule to evaluate

        Returns:
            Tuple of (confidence, match_details) if matched, None otherwise
        """
        rule_type = signature.rule_type

        if rule_type == 'pattern':
            return self._match_pattern_rule(event, signature)
        elif rule_type == 'ioc':
            return self._match_ioc_rule(event, signature)
        elif rule_type == 'threshold':
            return self._match_threshold_rule(event, signature)
        elif rule_type == 'correlation':
            return self._match_correlation_rule(event, signature)
        else:
            logger.warning(f"Unknown rule type: {rule_type}")
            return None

    def _match_pattern_rule(self, event: Event, signature: Signature) -> Optional[Tuple[float, Dict]]:
        """Match pattern-based rules (regex, field comparisons)."""
        conditions = signature.conditions

        if not conditions:
            return None

        match_details = {}

        # Evaluate each condition
        for field, condition in conditions.items():
            # Get field value from event
            field_value = self._get_event_field(event, field)

            if field_value is None:
                return None  # Required field missing

            # Check condition type
            if isinstance(condition, dict):
                condition_type = condition.get('type')

                if condition_type == 'equals':
                    if field_value != condition['value']:
                        return None
                    match_details[field] = f"equals {condition['value']}"

                elif condition_type == 'regex':
                    pattern = condition['pattern']
                    if not re.search(pattern, str(field_value), re.IGNORECASE):
                        return None
                    match_details[field] = f"matches pattern {pattern}"

                elif condition_type == 'in':
                    if field_value not in condition['values']:
                        return None
                    match_details[field] = f"in {condition['values']}"

                elif condition_type == 'range':
                    min_val = condition.get('min')
                    max_val = condition.get('max')
                    if min_val is not None and field_value < min_val:
                        return None
                    if max_val is not None and field_value > max_val:
                        return None
                    match_details[field] = f"in range [{min_val}, {max_val}]"

                elif condition_type == 'contains':
                    if condition['value'] not in str(field_value):
                        return None
                    match_details[field] = f"contains {condition['value']}"

            else:
                # Simple equality check
                if field_value != condition:
                    return None
                match_details[field] = f"equals {condition}"

        # All conditions matched
        confidence = signature.confidence
        return (confidence, match_details)

    def _match_ioc_rule(self, event: Event, signature: Signature) -> Optional[Tuple[float, Dict]]:
        """Match IOC-based rules (malicious IPs, domains, hashes)."""
        conditions = signature.conditions
        ioc_values = conditions.get('ioc_values', [])

        match_details = {}

        # Check various IOC fields
        if event.event_type == 'network':
            # Check IPs
            if event.src_ip in ioc_values:
                match_details['src_ip'] = event.src_ip
            if event.dst_ip in ioc_values:
                match_details['dst_ip'] = event.dst_ip

        elif event.event_type == 'host':
            # Check process names, command lines, etc.
            if event.process_name and event.process_name in ioc_values:
                match_details['process_name'] = event.process_name

            if event.command_line:
                for ioc in ioc_values:
                    if ioc in event.command_line:
                        match_details['command_line'] = ioc

        if match_details:
            confidence = signature.confidence
            return (confidence, match_details)

        return None

    def _match_threshold_rule(self, event: Event, signature: Signature) -> Optional[Tuple[float, Dict]]:
        """Match threshold-based rules (e.g., N events in X seconds)."""
        conditions = signature.conditions

        threshold = conditions.get('threshold')
        time_window = conditions.get('time_window_seconds', 60)
        grouping_key = conditions.get('grouping_key', 'src_ip')

        if not threshold:
            return None

        # Get grouping value
        group_value = self._get_event_field(event, grouping_key)
        if not group_value:
            return None

        # Track events
        tracker_key = f"{signature.name}:{group_value}"
        current_time = event.timestamp or datetime.utcnow()
        cutoff_time = current_time - timedelta(seconds=time_window)

        # Get the appropriate tracker
        if 'failed_login' in signature.name.lower():
            tracker = self.failed_login_tracker
        elif 'scan' in signature.name.lower():
            tracker = self.scan_tracker
        else:
            tracker = self.connection_tracker

        # Add current event
        if isinstance(tracker[tracker_key], list):
            tracker[tracker_key].append(current_time)
            # Clean old entries
            tracker[tracker_key] = [t for t in tracker[tracker_key] if t > cutoff_time]
            event_count = len(tracker[tracker_key])
        else:
            # For set-based trackers (like port scans)
            if hasattr(event, 'dst_port') and event.dst_port:
                tracker[tracker_key].add(event.dst_port)
            event_count = len(tracker[tracker_key])

        # Check threshold
        if event_count >= threshold:
            confidence = min(1.0, signature.confidence * (event_count / threshold))
            match_details = {
                'count': event_count,
                'threshold': threshold,
                'time_window': time_window,
                'grouping': f"{grouping_key}={group_value}"
            }
            return (confidence, match_details)

        return None

    def _match_correlation_rule(self, event: Event, signature: Signature) -> Optional[Tuple[float, Dict]]:
        """Match correlation rules (multiple related events)."""
        # Placeholder for complex correlation logic
        # This would require tracking multiple event types and their relationships
        logger.debug(f"Correlation rule matching not yet implemented: {signature.name}")
        return None

    def _get_event_field(self, event: Event, field_path: str) -> Optional[any]:
        """
        Get field value from event using dot notation.

        Args:
            event: Event object
            field_path: Field path (e.g., 'src_ip' or 'features.protocol_tcp')

        Returns:
            Field value or None
        """
        parts = field_path.split('.')

        value = event
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                value = getattr(value, part, None)

            if value is None:
                return None

        return value

    def clear_trackers(self):
        """Clear all state trackers (call periodically)."""
        self.connection_tracker.clear()
        self.failed_login_tracker.clear()
        self.scan_tracker.clear()
        logger.info("Signature engine trackers cleared")


# Global signature engine instance
signature_engine = SignatureEngine()
