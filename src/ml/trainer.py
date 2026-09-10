"""
Model training orchestration.
"""
import logging
from typing import Dict, Optional, Tuple
from pathlib import Path
from datetime import datetime
import json

from src.core.config import config
from src.core.database import db
from src.core.models import MLModel
from src.ml.dataset_loader import dataset_manager
from src.ml.preprocessor import DataPreprocessor
from src.ml.models import (
    IsolationForestModel,
    OneClassSVMModel,
    evaluate_model
)

try:
    from src.ml.models import AutoencoderModel, PYTORCH_AVAILABLE
except ImportError:
    PYTORCH_AVAILABLE = False

logger = logging.getLogger(__name__)


class ModelTrainer:
    """Train and manage anomaly detection models."""

    def __init__(self):
        self.model_path = config.model_path
        self.model_path.mkdir(parents=True, exist_ok=True)
        self.preprocessor = DataPreprocessor()

    def train_isolation_forest(self,
                              dataset_name: str = 'CIC-IDS2017',
                              sample_size: Optional[int] = None,
                              contamination: float = 0.1,
                              n_estimators: int = 100) -> Dict:
        """
        Train Isolation Forest model.

        Args:
            dataset_name: Name of dataset to use
            sample_size: Number of samples to use (None = all)
            contamination: Expected proportion of outliers
            n_estimators: Number of trees

        Returns:
            Training results dictionary
        """
        logger.info("=" * 60)
        logger.info(f"Training Isolation Forest on {dataset_name}")
        logger.info("=" * 60)

        # Load dataset
        X, y = self._load_dataset(dataset_name, sample_size)

        # Prepare data
        X_train, X_test, y_train, y_test = self.preprocessor.prepare_anomaly_detection_data(
            X, y, benign_only=True
        )

        # Create and train model
        model = IsolationForestModel(
            contamination=contamination,
            n_estimators=n_estimators
        )
        model.train(X_train)

        # Evaluate
        metrics = evaluate_model(model, X_test, y_test)

        # Save model
        model_filename = f"isolation_forest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pkl"
        model_path = self.model_path / model_filename
        model.save(model_path)

        # Save to database
        self._save_model_metadata(
            model_name='Isolation Forest',
            model_type='isolation_forest',
            file_path=str(model_path),
            dataset=dataset_name,
            training_samples=len(X_train),
            metrics=metrics,
            parameters={
                'contamination': contamination,
                'n_estimators': n_estimators
            }
        )

        logger.info("=" * 60)
        logger.info("Training complete!")
        logger.info("=" * 60)

        return {
            'model_path': str(model_path),
            'metrics': metrics,
            'training_samples': len(X_train),
            'test_samples': len(X_test)
        }

    def train_one_class_svm(self,
                           dataset_name: str = 'CIC-IDS2017',
                           sample_size: Optional[int] = 10000,  # SVM is slower
                           nu: float = 0.1,
                           kernel: str = 'rbf') -> Dict:
        """
        Train One-Class SVM model.

        Args:
            dataset_name: Name of dataset to use
            sample_size: Number of samples to use (None = all, but SVM is slow)
            nu: Upper bound on training errors
            kernel: Kernel type

        Returns:
            Training results dictionary
        """
        logger.info("=" * 60)
        logger.info(f"Training One-Class SVM on {dataset_name}")
        logger.info("=" * 60)

        # Load dataset
        X, y = self._load_dataset(dataset_name, sample_size)

        # Prepare data
        X_train, X_test, y_train, y_test = self.preprocessor.prepare_anomaly_detection_data(
            X, y, benign_only=True
        )

        # Create and train model
        model = OneClassSVMModel(nu=nu, kernel=kernel)
        model.train(X_train)

        # Evaluate
        metrics = evaluate_model(model, X_test, y_test)

        # Save model
        model_filename = f"one_class_svm_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pkl"
        model_path = self.model_path / model_filename
        model.save(model_path)

        # Save to database
        self._save_model_metadata(
            model_name='One-Class SVM',
            model_type='one_class_svm',
            file_path=str(model_path),
            dataset=dataset_name,
            training_samples=len(X_train),
            metrics=metrics,
            parameters={
                'nu': nu,
                'kernel': kernel
            }
        )

        logger.info("=" * 60)
        logger.info("Training complete!")
        logger.info("=" * 60)

        return {
            'model_path': str(model_path),
            'metrics': metrics,
            'training_samples': len(X_train),
            'test_samples': len(X_test)
        }

    def train_autoencoder(self,
                         dataset_name: str = 'CIC-IDS2017',
                         sample_size: Optional[int] = None,
                         encoding_dim: int = 16,
                         epochs: int = 50,
                         batch_size: int = 32) -> Dict:
        """
        Train Autoencoder model.

        Args:
            dataset_name: Name of dataset to use
            sample_size: Number of samples to use
            encoding_dim: Dimension of encoded representation
            epochs: Number of training epochs
            batch_size: Batch size

        Returns:
            Training results dictionary
        """
        if not PYTORCH_AVAILABLE:
            raise RuntimeError("PyTorch not available. Install with: pip install torch")

        logger.info("=" * 60)
        logger.info(f"Training Autoencoder on {dataset_name}")
        logger.info("=" * 60)

        # Load dataset
        X, y = self._load_dataset(dataset_name, sample_size)

        # Prepare data
        X_train, X_test, y_train, y_test = self.preprocessor.prepare_anomaly_detection_data(
            X, y, benign_only=True
        )

        # Create and train model
        model = AutoencoderModel(
            encoding_dim=encoding_dim,
            epochs=epochs,
            batch_size=batch_size
        )
        model.train(X_train)

        # Evaluate
        metrics = evaluate_model(model, X_test, y_test)

        # Save model
        model_filename = f"autoencoder_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pt"
        model_path = self.model_path / model_filename
        model.save(model_path)

        # Save to database
        self._save_model_metadata(
            model_name='Autoencoder',
            model_type='autoencoder',
            file_path=str(model_path),
            dataset=dataset_name,
            training_samples=len(X_train),
            metrics=metrics,
            parameters={
                'encoding_dim': encoding_dim,
                'epochs': epochs,
                'batch_size': batch_size
            }
        )

        logger.info("=" * 60)
        logger.info("Training complete!")
        logger.info("=" * 60)

        return {
            'model_path': str(model_path),
            'metrics': metrics,
            'training_samples': len(X_train),
            'test_samples': len(X_test)
        }

    def _load_dataset(self, dataset_name: str, sample_size: Optional[int]) -> Tuple:
        """Load dataset by name."""
        if dataset_name == 'CIC-IDS2017':
            return dataset_manager.load_cicids2017(sample_size=sample_size)
        elif dataset_name == 'NSL-KDD':
            return dataset_manager.load_nslkdd(train=True)
        elif dataset_name == 'UNSW-NB15':
            return dataset_manager.load_unsw_nb15(train=True)
        else:
            raise ValueError(f"Unknown dataset: {dataset_name}")

    def _save_model_metadata(self,
                            model_name: str,
                            model_type: str,
                            file_path: str,
                            dataset: str,
                            training_samples: int,
                            metrics: Dict,
                            parameters: Dict) -> None:
        """Save model metadata to database."""
        with db.session_scope() as session:
            # Deactivate previous models of same type
            previous_models = session.query(MLModel).filter(
                MLModel.model_type == model_type,
                MLModel.is_active == True
            ).all()

            for prev_model in previous_models:
                prev_model.is_active = False

            # Create new model entry
            ml_model = MLModel(
                name=model_name,
                version=datetime.now().strftime('%Y%m%d_%H%M%S'),
                model_type=model_type,
                file_path=file_path,
                parameters=parameters,
                training_dataset=dataset,
                training_date=datetime.utcnow(),
                training_samples=training_samples,
                validation_accuracy=metrics.get('accuracy'),
                precision=metrics.get('precision'),
                recall=metrics.get('recall'),
                f1_score=metrics.get('f1_score'),
                false_positive_rate=metrics.get('false_positives', 0) /
                                   (metrics.get('false_positives', 0) + metrics.get('true_negatives', 1)),
                is_active=True,
                deployed_at=datetime.utcnow()
            )

            session.add(ml_model)

        logger.info(f"Model metadata saved to database")

    def list_available_datasets(self) -> Dict:
        """List available datasets."""
        datasets = ['CIC-IDS2017', 'NSL-KDD', 'UNSW-NB15']
        info = {}

        for dataset in datasets:
            info[dataset] = dataset_manager.get_dataset_info(dataset)

        return info


# Global trainer instance
model_trainer = ModelTrainer()
