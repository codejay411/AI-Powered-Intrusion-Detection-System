"""ML module initialization."""
from src.ml.dataset_loader import dataset_manager, DatasetManager
from src.ml.preprocessor import preprocessor, DataPreprocessor
from src.ml.models import (
    IsolationForestModel,
    OneClassSVMModel,
    evaluate_model
)
from src.ml.trainer import model_trainer, ModelTrainer
from src.ml.inference import anomaly_detector, AnomalyDetector

try:
    from src.ml.models import AutoencoderModel, PYTORCH_AVAILABLE
except ImportError:
    PYTORCH_AVAILABLE = False

__all__ = [
    'dataset_manager',
    'DatasetManager',
    'preprocessor',
    'DataPreprocessor',
    'IsolationForestModel',
    'OneClassSVMModel',
    'evaluate_model',
    'model_trainer',
    'ModelTrainer',
    'anomaly_detector',
    'AnomalyDetector',
    'PYTORCH_AVAILABLE'
]

if PYTORCH_AVAILABLE:
    __all__.append('AutoencoderModel')
