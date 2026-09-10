"""
Anomaly detection models: Isolation Forest, One-Class SVM, Autoencoder.
"""
import logging
from typing import Dict, Optional, Tuple
import numpy as np
import pickle
from pathlib import Path
from datetime import datetime

from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    PYTORCH_AVAILABLE = True
except ImportError:
    PYTORCH_AVAILABLE = False
    logging.warning("PyTorch not available. Autoencoder model will not be available.")

from src.core.config import config

logger = logging.getLogger(__name__)


class IsolationForestModel:
    """Isolation Forest for anomaly detection."""

    def __init__(self, contamination: float = 0.1, n_estimators: int = 100, random_state: int = 42):
        """
        Initialize Isolation Forest model.

        Args:
            contamination: Expected proportion of outliers
            n_estimators: Number of trees
            random_state: Random seed
        """
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=-1
        )
        self.model_name = 'isolation_forest'
        self.contamination = contamination

    def train(self, X_train: np.ndarray) -> None:
        """Train the model."""
        logger.info(f"Training Isolation Forest on {len(X_train)} samples")
        self.model.fit(X_train)
        logger.info("Training complete")

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomalies (1 = normal, -1 = anomaly).

        Args:
            X: Feature array

        Returns:
            Predictions (1 = normal, -1 = anomaly)
        """
        return self.model.predict(X)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Get anomaly scores (lower = more anomalous).

        Args:
            X: Feature array

        Returns:
            Anomaly scores
        """
        return self.model.score_samples(X)

    def save(self, path: Path) -> None:
        """Save model to disk."""
        with open(path, 'wb') as f:
            pickle.dump(self.model, f)
        logger.info(f"Model saved to {path}")

    def load(self, path: Path) -> None:
        """Load model from disk."""
        with open(path, 'rb') as f:
            self.model = pickle.load(f)
        logger.info(f"Model loaded from {path}")


class OneClassSVMModel:
    """One-Class SVM for anomaly detection."""

    def __init__(self, nu: float = 0.1, kernel: str = 'rbf', gamma: str = 'auto'):
        """
        Initialize One-Class SVM model.

        Args:
            nu: Upper bound on fraction of training errors
            kernel: Kernel type
            gamma: Kernel coefficient
        """
        self.model = OneClassSVM(
            nu=nu,
            kernel=kernel,
            gamma=gamma
        )
        self.model_name = 'one_class_svm'
        self.nu = nu

    def train(self, X_train: np.ndarray) -> None:
        """Train the model."""
        logger.info(f"Training One-Class SVM on {len(X_train)} samples")
        self.model.fit(X_train)
        logger.info("Training complete")

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomalies (1 = normal, -1 = anomaly).

        Args:
            X: Feature array

        Returns:
            Predictions (1 = normal, -1 = anomaly)
        """
        return self.model.predict(X)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Get decision function values.

        Args:
            X: Feature array

        Returns:
            Decision function values
        """
        return self.model.decision_function(X)

    def save(self, path: Path) -> None:
        """Save model to disk."""
        with open(path, 'wb') as f:
            pickle.dump(self.model, f)
        logger.info(f"Model saved to {path}")

    def load(self, path: Path) -> None:
        """Load model from disk."""
        with open(path, 'rb') as f:
            self.model = pickle.load(f)
        logger.info(f"Model loaded from {path}")


if PYTORCH_AVAILABLE:
    class AutoencoderNetwork(nn.Module):
        """Autoencoder neural network."""

        def __init__(self, input_dim: int, encoding_dim: int = 16):
            super(AutoencoderNetwork, self).__init__()

            # Encoder
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, 64),
                nn.ReLU(),
                nn.Linear(64, 32),
                nn.ReLU(),
                nn.Linear(32, encoding_dim),
                nn.ReLU()
            )

            # Decoder
            self.decoder = nn.Sequential(
                nn.Linear(encoding_dim, 32),
                nn.ReLU(),
                nn.Linear(32, 64),
                nn.ReLU(),
                nn.Linear(64, input_dim)
            )

        def forward(self, x):
            encoded = self.encoder(x)
            decoded = self.decoder(encoded)
            return decoded


    class AutoencoderModel:
        """Autoencoder for anomaly detection."""

        def __init__(self, encoding_dim: int = 16, epochs: int = 50, batch_size: int = 32):
            """
            Initialize Autoencoder model.

            Args:
                encoding_dim: Dimension of encoded representation
                epochs: Number of training epochs
                batch_size: Batch size for training
            """
            self.encoding_dim = encoding_dim
            self.epochs = epochs
            self.batch_size = batch_size
            self.model = None
            self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            self.model_name = 'autoencoder'
            self.threshold = None

        def train(self, X_train: np.ndarray, X_val: Optional[np.ndarray] = None) -> None:
            """Train the model."""
            logger.info(f"Training Autoencoder on {len(X_train)} samples")
            logger.info(f"Device: {self.device}")

            input_dim = X_train.shape[1]
            self.model = AutoencoderNetwork(input_dim, self.encoding_dim).to(self.device)

            criterion = nn.MSELoss()
            optimizer = optim.Adam(self.model.parameters(), lr=0.001)

            # Prepare data
            train_dataset = TensorDataset(
                torch.FloatTensor(X_train),
                torch.FloatTensor(X_train)
            )
            train_loader = DataLoader(train_dataset, batch_size=self.batch_size, shuffle=True)

            # Training loop
            self.model.train()
            for epoch in range(self.epochs):
                total_loss = 0
                for batch_X, batch_y in train_loader:
                    batch_X = batch_X.to(self.device)
                    batch_y = batch_y.to(self.device)

                    # Forward pass
                    outputs = self.model(batch_X)
                    loss = criterion(outputs, batch_y)

                    # Backward pass
                    optimizer.zero_grad()
                    loss.backward()
                    optimizer.step()

                    total_loss += loss.item()

                avg_loss = total_loss / len(train_loader)

                if (epoch + 1) % 10 == 0:
                    logger.info(f"Epoch [{epoch+1}/{self.epochs}], Loss: {avg_loss:.6f}")

            # Calculate threshold from training reconstruction errors
            self.model.eval()
            with torch.no_grad():
                X_train_tensor = torch.FloatTensor(X_train).to(self.device)
                reconstructed = self.model(X_train_tensor)
                mse = torch.mean((X_train_tensor - reconstructed) ** 2, dim=1)
                self.threshold = torch.quantile(mse, 0.95).item()  # 95th percentile

            logger.info(f"Training complete. Threshold: {self.threshold:.6f}")

        def predict(self, X: np.ndarray) -> np.ndarray:
            """
            Predict anomalies (1 = normal, -1 = anomaly).

            Args:
                X: Feature array

            Returns:
                Predictions (1 = normal, -1 = anomaly)
            """
            scores = self.score_samples(X)
            # Convert reconstruction errors to predictions
            predictions = np.where(scores > self.threshold, -1, 1)
            return predictions

        def score_samples(self, X: np.ndarray) -> np.ndarray:
            """
            Get reconstruction errors (higher = more anomalous).

            Args:
                X: Feature array

            Returns:
                Reconstruction errors
            """
            self.model.eval()
            with torch.no_grad():
                X_tensor = torch.FloatTensor(X).to(self.device)
                reconstructed = self.model(X_tensor)
                mse = torch.mean((X_tensor - reconstructed) ** 2, dim=1)
                return mse.cpu().numpy()

        def save(self, path: Path) -> None:
            """Save model to disk."""
            torch.save({
                'model_state_dict': self.model.state_dict(),
                'encoding_dim': self.encoding_dim,
                'threshold': self.threshold
            }, path)
            logger.info(f"Model saved to {path}")

        def load(self, path: Path, input_dim: int) -> None:
            """Load model from disk."""
            checkpoint = torch.load(path, map_location=self.device)
            self.encoding_dim = checkpoint['encoding_dim']
            self.threshold = checkpoint['threshold']
            self.model = AutoencoderNetwork(input_dim, self.encoding_dim).to(self.device)
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.model.eval()
            logger.info(f"Model loaded from {path}")


def evaluate_model(model, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
    """
    Evaluate anomaly detection model.

    Args:
        model: Trained model
        X_test: Test features
        y_test: Test labels (0 = benign, 1 = attack)

    Returns:
        Dictionary of metrics
    """
    logger.info("Evaluating model...")

    # Get predictions
    predictions = model.predict(X_test)

    # Convert model predictions (-1 = anomaly, 1 = normal) to (1 = anomaly, 0 = normal)
    y_pred = np.where(predictions == -1, 1, 0)

    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    # Confusion matrix
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    metrics = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'true_positives': int(tp),
        'true_negatives': int(tn),
        'false_positives': int(fp),
        'false_negatives': int(fn)
    }

    logger.info(f"Accuracy: {accuracy:.4f}")
    logger.info(f"Precision: {precision:.4f}")
    logger.info(f"Recall: {recall:.4f}")
    logger.info(f"F1-Score: {f1:.4f}")
    logger.info(f"TP: {tp}, TN: {tn}, FP: {fp}, FN: {fn}")

    return metrics
