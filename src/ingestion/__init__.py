"""Ingestion module initialization."""
from src.ingestion.network_ingestion import NetworkIngestion, ingest_network_traffic
from src.ingestion.host_ingestion import HostIngestion, ingest_host_logs
from src.ingestion.feature_extraction import FeatureExtractor
from src.ingestion.pipeline import DataPipeline, run_ingestion

__all__ = [
    'NetworkIngestion',
    'HostIngestion',
    'FeatureExtractor',
    'DataPipeline',
    'ingest_network_traffic',
    'ingest_host_logs',
    'run_ingestion'
]
