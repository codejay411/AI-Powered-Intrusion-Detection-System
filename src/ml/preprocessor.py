"""
Data preprocessing for ML models.
"""
import logging
from typing import Tuple, List, Optional
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)


class DataPreprocessor:
    """Preprocess datasets for ML training."""

    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_names = []

    def preprocess_features(self, X: pd.DataFrame, fit: bool = True) -> np.ndarray:
        """
        Preprocess features for ML models.

        Args:
            X: Feature DataFrame
            fit: Whether to fit the preprocessor (True for training, False for inference)

        Returns:
            Preprocessed numpy array
        """
        logger.info(f"Preprocessing {len(X)} samples with {X.shape[1]} features")

        # Make a copy
        X_processed = X.copy()

        # Handle missing values
        X_processed = self._handle_missing_values(X_processed)

        # Encode categorical features
        X_processed = self._encode_categorical(X_processed, fit=fit)

        # Remove non-numeric columns
        X_processed = self._ensure_numeric(X_processed)

        # Handle infinite values
        X_processed = X_processed.replace([np.inf, -np.inf], np.nan)
        X_processed = X_processed.fillna(0)

        # Store feature names
        if fit:
            self.feature_names = X_processed.columns.tolist()

        # Convert to numpy array
        X_array = X_processed.values

        # Scale features
        if fit:
            X_scaled = self.scaler.fit_transform(X_array)
            logger.info("Fitted scaler on training data")
        else:
            X_scaled = self.scaler.transform(X_array)

        logger.info(f"Preprocessed shape: {X_scaled.shape}")

        return X_scaled

    def preprocess_labels(self, y: pd.Series, binary: bool = True) -> np.ndarray:
        """
        Preprocess labels.

        Args:
            y: Label Series
            binary: Convert to binary (benign=0, attack=1)

        Returns:
            Preprocessed labels
        """
        logger.info(f"Preprocessing {len(y)} labels")

        # Convert to string for consistency
        y = y.astype(str).str.strip()

        if binary:
            # Binary classification: benign vs attack
            # Common benign labels
            benign_labels = ['BENIGN', 'benign', 'normal', 'Normal', '0', '0.0']

            y_binary = y.apply(lambda x: 0 if x in benign_labels else 1)

            benign_count = (y_binary == 0).sum()
            attack_count = (y_binary == 1).sum()

            logger.info(f"Binary labels: {benign_count} benign, {attack_count} attacks")

            return y_binary.values

        else:
            # Multi-class: keep attack types
            if 'label_encoder' not in self.label_encoders:
                self.label_encoders['label_encoder'] = LabelEncoder()
                y_encoded = self.label_encoders['label_encoder'].fit_transform(y)
            else:
                y_encoded = self.label_encoders['label_encoder'].transform(y)

            return y_encoded

    def _handle_missing_values(self, X: pd.DataFrame) -> pd.DataFrame:
        """Handle missing values in dataset."""
        # Fill numeric columns with median
        numeric_cols = X.select_dtypes(include=[np.number]).columns
        for col in numeric_cols:
            if X[col].isnull().any():
                X[col].fillna(X[col].median(), inplace=True)

        # Fill categorical columns with mode
        categorical_cols = X.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            if X[col].isnull().any():
                X[col].fillna(X[col].mode()[0] if not X[col].mode().empty else 'unknown', inplace=True)

        return X

    def _encode_categorical(self, X: pd.DataFrame, fit: bool = True) -> pd.DataFrame:
        """Encode categorical features."""
        categorical_cols = X.select_dtypes(include=['object']).columns

        for col in categorical_cols:
            if fit:
                # Create new label encoder
                le = LabelEncoder()
                X[col] = le.fit_transform(X[col].astype(str))
                self.label_encoders[col] = le
            else:
                # Use existing label encoder
                if col in self.label_encoders:
                    le = self.label_encoders[col]
                    # Handle unseen labels
                    X[col] = X[col].apply(lambda x: x if x in le.classes_ else 'unknown')
                    if 'unknown' not in le.classes_:
                        # Add 'unknown' class
                        le.classes_ = np.append(le.classes_, 'unknown')
                    X[col] = le.transform(X[col].astype(str))
                else:
                    # No encoder available, fill with 0
                    X[col] = 0

        return X

    def _ensure_numeric(self, X: pd.DataFrame) -> pd.DataFrame:
        """Ensure all columns are numeric."""
        # Convert all columns to numeric, coerce errors to NaN
        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors='coerce')

        # Fill any remaining NaN with 0
        X = X.fillna(0)

        return X

    def prepare_anomaly_detection_data(self, X: pd.DataFrame, y: pd.Series,
                                       benign_only: bool = True,
                                       test_size: float = 0.2,
                                       random_state: int = 42) -> Tuple:
        """
        Prepare data for anomaly detection training.

        Args:
            X: Features
            y: Labels
            benign_only: Train only on benign samples
            test_size: Test set proportion
            random_state: Random seed

        Returns:
            Tuple of (X_train, X_test, y_train, y_test)
        """
        # Preprocess labels (binary)
        y_binary = self.preprocess_labels(y, binary=True)

        if benign_only:
            # Filter to only benign samples for training
            benign_mask = y_binary == 0
            X_benign = X[benign_mask]
            y_benign = y_binary[benign_mask]

            logger.info(f"Training on {len(X_benign)} benign samples")

            # Preprocess features
            X_processed = self.preprocess_features(X_benign, fit=True)

            # Split benign data
            X_train, X_test_benign, y_train, y_test_benign = train_test_split(
                X_processed, y_benign,
                test_size=test_size,
                random_state=random_state
            )

            # Add some attack samples to test set
            attack_mask = y_binary == 1
            if attack_mask.sum() > 0:
                X_attack = X[attack_mask]
                y_attack = y_binary[attack_mask]

                # Sample attacks (limit to avoid imbalance)
                sample_size = min(len(X_attack), len(X_test_benign))
                attack_indices = np.random.choice(len(X_attack), sample_size, replace=False)
                X_attack_sample = X_attack.iloc[attack_indices]
                y_attack_sample = y_attack[attack_indices]

                # Preprocess attack samples (don't fit)
                X_attack_processed = self.preprocess_features(X_attack_sample, fit=False)

                # Combine benign and attack test samples
                X_test = np.vstack([X_test_benign, X_attack_processed])
                y_test = np.concatenate([y_test_benign, y_attack_sample])

                logger.info(f"Test set: {len(X_test_benign)} benign + {len(X_attack_processed)} attacks")
            else:
                X_test = X_test_benign
                y_test = y_test_benign

        else:
            # Use all data
            X_processed = self.preprocess_features(X, fit=True)
            X_train, X_test, y_train, y_test = train_test_split(
                X_processed, y_binary,
                test_size=test_size,
                random_state=random_state,
                stratify=y_binary
            )

        logger.info(f"Train set: {len(X_train)} samples")
        logger.info(f"Test set: {len(X_test)} samples")

        return X_train, X_test, y_train, y_test

    def get_feature_names(self) -> List[str]:
        """Get list of feature names."""
        return self.feature_names


# Global preprocessor instance
preprocessor = DataPreprocessor()
