"""
ML inference for real-time anomaly detection.
"""
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import numpy as np

from src.core.database import db
from src.core.models import Event, Alert, MLModel
from src.ml.preprocessor import DataPreprocessor
from src.ml.models import IsolationForestModel, OneClassSVMModel

try:
    from src.ml.models import AutoencoderModel, PYTORCH_AVAILABLE
except ImportError:
    PYTORCH_AVAILABLE = False

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Real-time anomaly detection using trained ML models."""

    def __init__(self):
        self.models = {}
        self.preprocessor = DataPreprocessor()
        self.load_active_models()

    def load_active_models(self):
        """Load all active models from database."""
        logger.info("Loading active ML models...")

        with db.session_scope() as session:
            active_models = session.query(MLModel).filter(
                MLModel.is_active == True
            ).all()

            for ml_model in active_models:
                try:
                    self._load_model(ml_model)
                except Exception as e:
                    logger.error(f"Error loading model {ml_model.name}: {e}")

        logger.info(f"Loaded {len(self.models)} active models")

    def _load_model(self, ml_model: MLModel):
        """Load a specific model."""
        model_path = Path(ml_model.file_path)

        if not model_path.exists():
            logger.warning(f"Model file not found: {model_path}")
            return

        model_type = ml_model.model_type

        if model_type == 'isolation_forest':
            model = IsolationForestModel()
            model.load(model_path)
        elif model_type == 'one_class_svm':
            model = OneClassSVMModel()
            model.load(model_path)
        elif model_type == 'autoencoder':
            if not PYTORCH_AVAILABLE:
                logger.warning("PyTorch not available, skipping autoencoder")
                return
            model = AutoencoderModel()
            # Need input_dim from somewhere - stored in parameters
            input_dim = ml_model.parameters.get('input_dim', 78)
            model.load(model_path, input_dim=input_dim)
        else:
            logger.warning(f"Unknown model type: {model_type}")
            return

        self.models[model_type] = {
            'model': model,
            'metadata': ml_model
        }

        logger.info(f"Loaded {ml_model.name} ({model_type})")

    def score_event(self, event: Event) -> Dict[str, float]:
        """
        Score an event for anomalies using all loaded models.

        Args:
            event: Event object to score

        Returns:
            Dictionary of model scores
        """
        if not event.features:
            logger.warning(f"Event {event.id} has no features")
            return {}

        scores = {}

        # Convert event features to array
        feature_array = self._event_to_feature_array(event)

        if feature_array is None:
            return {}

        # Score with each model
        for model_type, model_info in self.models.items():
            model = model_info['model']

            try:
                # Get anomaly score
                raw_score = model.score_samples(feature_array.reshape(1, -1))[0]

                # Normalize score to [0, 1] range (higher = more anomalous)
                normalized_score = self._normalize_score(raw_score, model_type)

                scores[model_type] = float(normalized_score)

            except Exception as e:
                logger.error(f"Error scoring with {model_type}: {e}")

        return scores

    def detect_anomaly(self, event: Event, threshold: float = 0.5) -> Optional[Tuple[bool, Dict]]:
        """
        Detect if an event is anomalous.

        Args:
            event: Event to check
            threshold: Anomaly threshold (0-1)

        Returns:
            Tuple of (is_anomaly, details) or None
        """
        scores = self.score_event(event)

        if not scores:
            return None

        # Aggregate scores (average)
        avg_score = np.mean(list(scores.values()))

        is_anomaly = avg_score > threshold

        details = {
            'scores': scores,
            'average_score': float(avg_score),
            'threshold': threshold,
            'is_anomaly': is_anomaly
        }

        return is_anomaly, details

    def generate_alert(self, event: Event, threshold: float = 0.5) -> Optional[Alert]:
        """
        Generate an alert if event is anomalous.

        Args:
            event: Event to check
            threshold: Anomaly threshold

        Returns:
            Alert object or None
        """
        result = self.detect_anomaly(event, threshold)

        if result is None:
            return None

        is_anomaly, details = result

        if not is_anomaly:
            return None

        # Determine severity based on score
        avg_score = details['average_score']
        if avg_score >= 0.9:
            severity = 'critical'
        elif avg_score >= 0.75:
            severity = 'high'
        elif avg_score >= 0.6:
            severity = 'medium'
        else:
            severity = 'low'

        # Create alert
        alert = Alert(
            event_id=event.id,
            title='ML Anomaly Detected',
            description=f'Anomalous behavior detected with score {avg_score:.2f}',
            severity=severity,
            status='new',
            detection_type='anomaly',
            confidence_score=avg_score,
            anomaly_score=avg_score,
            model_name=', '.join(self.models.keys()),
            contributing_factors=details['scores']
        )

        return alert

    def process_event(self, event: Event, threshold: float = 0.5) -> Optional[Alert]:
        """
        Process an event: score and generate alert if needed.

        Args:
            event: Event to process
            threshold: Anomaly threshold

        Returns:
            Alert object or None
        """
        alert = self.generate_alert(event, threshold)

        if alert:
            # Save alert to database
            with db.session_scope() as session:
                session.add(alert)

            logger.info(f"Generated ML alert for event {event.id} (score: {alert.anomaly_score:.2f})")

        return alert

    def process_events_batch(self, events: List[Event], threshold: float = 0.5) -> Dict:
        """
        Process a batch of events.

        Args:
            events: List of events
            threshold: Anomaly threshold

        Returns:
            Statistics dictionary
        """
        stats = {
            'events_processed': 0,
            'anomalies_detected': 0,
            'alerts_generated': 0
        }

        for event in events:
            alert = self.process_event(event, threshold)
            stats['events_processed'] += 1

            if alert:
                stats['anomalies_detected'] += 1
                stats['alerts_generated'] += 1

        logger.info(f"Batch processing complete: {stats}")
        return stats

    def _event_to_feature_array(self, event: Event) -> Optional[np.ndarray]:
        """Convert event features to numpy array."""
        if not event.features:
            return None

        try:
            # Get feature values in correct order
            feature_names = self.preprocessor.get_feature_names()

            if not feature_names:
                # Use event features as-is
                feature_values = list(event.features.values())
            else:
                # Ensure correct order
                feature_values = [event.features.get(name, 0) for name in feature_names]

            return np.array(feature_values, dtype=np.float32)

        except Exception as e:
            logger.error(f"Error converting event features: {e}")
            return None

    @staticmethod
    def _normalize_score(score: float, model_type: str) -> float:
        """
        Normalize anomaly score to [0, 1] range.

        Args:
            score: Raw model score
            model_type: Type of model

        Returns:
            Normalized score (higher = more anomalous)
        """
        if model_type == 'isolation_forest':
            # Isolation Forest: score in [-1, 0], lower = more anomalous
            # Normalize to [0, 1], higher = more anomalous
            normalized = 1.0 + score  # Maps [-1, 0] to [0, 1]
            return max(0.0, min(1.0, normalized))

        elif model_type == 'one_class_svm':
            # One-Class SVM: negative scores = anomaly
            # Apply sigmoid to map to [0, 1]
            import math
            normalized = 1.0 / (1.0 + math.exp(score))
            return normalized

        elif model_type == 'autoencoder':
            # Autoencoder: reconstruction error, higher = more anomalous
            # Already normalized during training
            return max(0.0, min(1.0, score / 10.0))  # Scale by expected max error

        else:
            return 0.5  # Unknown model type


# Global anomaly detector instance
anomaly_detector = AnomalyDetector()
