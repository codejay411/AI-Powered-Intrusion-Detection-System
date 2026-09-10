"""
Database models and schema definitions.
"""
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Float, Boolean,
    Text, JSON, ForeignKey, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class Event(Base):
    """Raw event storage (network + host)."""
    __tablename__ = 'events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    event_type = Column(String(50), nullable=False, index=True)  # network, host
    source = Column(String(100), nullable=False)  # IP, hostname, log file

    # Network-specific fields
    src_ip = Column(String(45))  # IPv4/IPv6
    dst_ip = Column(String(45))
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(20))
    bytes_sent = Column(Integer)
    bytes_received = Column(Integer)
    packets_sent = Column(Integer)
    packets_received = Column(Integer)

    # Host-specific fields
    hostname = Column(String(255))
    username = Column(String(255))
    process_name = Column(String(255))
    process_id = Column(Integer)
    command_line = Column(Text)
    parent_process = Column(String(255))

    # Common fields
    raw_data = Column(JSON)  # Store full raw event
    features = Column(JSON)  # Extracted features for ML

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    alerts = relationship("Alert", back_populates="event")

    # Indexes for performance
    __table_args__ = (
        Index('idx_event_timestamp', 'timestamp'),
        Index('idx_event_type', 'event_type'),
        Index('idx_event_src_ip', 'src_ip'),
        Index('idx_event_dst_ip', 'dst_ip'),
        Index('idx_event_hostname', 'hostname'),
    )


class Alert(Base):
    """Generated alerts from detection engines."""
    __tablename__ = 'alerts'

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, ForeignKey('events.id'), nullable=False)

    # Alert metadata
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False, index=True)  # low, medium, high, critical
    status = Column(String(50), default='new', index=True)  # new, investigating, resolved, false_positive

    # Detection source
    detection_type = Column(String(50), nullable=False)  # signature, anomaly, fusion
    confidence_score = Column(Float, nullable=False)

    # Signature-based fields
    signature_id = Column(Integer, ForeignKey('signatures.id'))
    matched_rules = Column(JSON)

    # ML-based fields
    anomaly_score = Column(Float)
    model_name = Column(String(100))

    # Fusion fields
    fusion_score = Column(Float)
    contributing_factors = Column(JSON)

    # Enrichment
    geoip_data = Column(JSON)
    threat_intel = Column(JSON)
    asset_criticality = Column(String(20))

    # MITRE ATT&CK mapping
    attack_tactics = Column(JSON)
    attack_techniques = Column(JSON)

    # Analyst workflow
    assigned_to = Column(String(100))
    investigated_at = Column(DateTime)
    resolved_at = Column(DateTime)
    resolution_notes = Column(Text)
    false_positive = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    event = relationship("Event", back_populates="alerts")
    signature = relationship("Signature", back_populates="alerts")
    comments = relationship("AlertComment", back_populates="alert", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index('idx_alert_severity', 'severity'),
        Index('idx_alert_status', 'status'),
        Index('idx_alert_created', 'created_at'),
        Index('idx_alert_detection_type', 'detection_type'),
    )


class Signature(Base):
    """Signature/rule definitions."""
    __tablename__ = 'signatures'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text)

    # Rule definition
    rule_type = Column(String(50), nullable=False)  # pattern, ioc, yara
    rule_content = Column(Text, nullable=False)

    # Matching criteria
    event_type = Column(String(50))  # network, host
    conditions = Column(JSON)  # Matching conditions

    # Metadata
    severity = Column(String(20), nullable=False)
    enabled = Column(Boolean, default=True, index=True)
    confidence = Column(Float, default=1.0)

    # Attribution
    category = Column(String(100))  # malware, exploit, reconnaissance, etc.
    tags = Column(JSON)
    references = Column(JSON)  # CVE, URLs, etc.

    # MITRE ATT&CK
    attack_tactics = Column(JSON)
    attack_techniques = Column(JSON)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_matched = Column(DateTime)

    # Relationships
    alerts = relationship("Alert", back_populates="signature")

    # Indexes
    __table_args__ = (
        Index('idx_signature_enabled', 'enabled'),
        Index('idx_signature_rule_type', 'rule_type'),
    )


class MLModel(Base):
    """ML model metadata and versioning."""
    __tablename__ = 'ml_models'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    version = Column(String(50), nullable=False)
    model_type = Column(String(50), nullable=False)  # isolation_forest, autoencoder, etc.

    # Model info
    file_path = Column(String(500), nullable=False)
    parameters = Column(JSON)

    # Training info
    training_dataset = Column(String(100))
    training_date = Column(DateTime, nullable=False)
    training_samples = Column(Integer)
    validation_accuracy = Column(Float)

    # Performance metrics
    precision = Column(Float)
    recall = Column(Float)
    f1_score = Column(Float)
    false_positive_rate = Column(Float)

    # Status
    is_active = Column(Boolean, default=False, index=True)
    deployed_at = Column(DateTime)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_model_active', 'is_active'),
    )


class IOC(Base):
    """Indicators of Compromise."""
    __tablename__ = 'iocs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_type = Column(String(50), nullable=False, index=True)  # ip, domain, hash, url
    value = Column(String(500), nullable=False, index=True)

    # Metadata
    threat_type = Column(String(100))  # malware, c2, phishing, etc.
    confidence = Column(Float, default=0.5)
    severity = Column(String(20))

    # Source
    source = Column(String(100))  # feed name
    description = Column(Text)
    tags = Column(JSON)

    # Status
    is_active = Column(Boolean, default=True, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index('idx_ioc_type_value', 'ioc_type', 'value'),
        Index('idx_ioc_active', 'is_active'),
    )


class AlertComment(Base):
    """Comments/annotations on alerts."""
    __tablename__ = 'alert_comments'

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey('alerts.id'), nullable=False)

    author = Column(String(100), nullable=False)
    comment = Column(Text, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    alert = relationship("Alert", back_populates="comments")


class Incident(Base):
    """Security incidents (promoted alerts)."""
    __tablename__ = 'incidents'

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)

    severity = Column(String(20), nullable=False, index=True)
    status = Column(String(50), default='open', index=True)  # open, investigating, contained, resolved

    # Related alerts
    alert_ids = Column(JSON)  # List of alert IDs

    # Workflow
    assigned_to = Column(String(100))
    opened_at = Column(DateTime, default=datetime.utcnow)
    closed_at = Column(DateTime)

    # Response
    response_actions = Column(JSON)
    resolution_notes = Column(Text)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index('idx_incident_status', 'status'),
        Index('idx_incident_severity', 'severity'),
    )
