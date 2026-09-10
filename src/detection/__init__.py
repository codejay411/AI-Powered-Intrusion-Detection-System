"""Detection module initialization."""
from src.detection.signature_manager import signature_manager, SignatureManager
from src.detection.signature_engine import signature_engine, SignatureEngine
from src.detection.alert_generator import alert_generator, AlertGenerator
from src.detection.ioc_manager import ioc_manager, IOCManager

__all__ = [
    'signature_manager',
    'SignatureManager',
    'signature_engine',
    'SignatureEngine',
    'alert_generator',
    'AlertGenerator',
    'ioc_manager',
    'IOCManager'
]
