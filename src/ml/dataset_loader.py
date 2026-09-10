"""
Dataset utilities for downloading and preprocessing IDS datasets.
"""
import logging
import requests
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import pandas as pd
import numpy as np
from tqdm import tqdm

from src.core.config import config

logger = logging.getLogger(__name__)


class DatasetManager:
    """Manage ML training datasets."""

    def __init__(self):
        self.dataset_path = config.data_path / "datasets"
        self.dataset_path.mkdir(parents=True, exist_ok=True)

    def download_file(self, url: str, destination: Path, chunk_size: int = 8192) -> bool:
        """
        Download a file with progress bar.

        Args:
            url: URL to download from
            destination: Local file path
            chunk_size: Download chunk size

        Returns:
            True if successful
        """
        try:
            logger.info(f"Downloading from {url}")
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))

            with open(destination, 'wb') as f, tqdm(
                desc=destination.name,
                total=total_size,
                unit='B',
                unit_scale=True,
                unit_divisor=1024,
            ) as bar:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    f.write(chunk)
                    bar.update(len(chunk))

            logger.info(f"Downloaded to {destination}")
            return True

        except Exception as e:
            logger.error(f"Download failed: {e}")
            return False

    def load_cicids2017(self, sample_size: Optional[int] = None) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Load CIC-IDS2017 dataset.

        Args:
            sample_size: Number of samples to load (None = all)

        Returns:
            Tuple of (features DataFrame, labels Series)
        """
        dataset_dir = self.dataset_path / "CIC-IDS2017"

        if not dataset_dir.exists():
            logger.error(f"CIC-IDS2017 dataset not found at {dataset_dir}")
            logger.info("Please download from: https://www.unb.ca/cic/datasets/ids-2017.html")
            raise FileNotFoundError(f"Dataset not found: {dataset_dir}")

        # Look for CSV files
        csv_files = list(dataset_dir.glob("*.csv"))

        if not csv_files:
            raise FileNotFoundError(f"No CSV files found in {dataset_dir}")

        logger.info(f"Found {len(csv_files)} CSV files")

        # Load and concatenate all files
        dfs = []
        for csv_file in csv_files:
            logger.info(f"Loading {csv_file.name}")
            df = pd.read_csv(csv_file, encoding='latin1', low_memory=False)
            dfs.append(df)

        # Combine all dataframes
        full_df = pd.concat(dfs, ignore_index=True)

        # Sample if requested
        if sample_size and sample_size < len(full_df):
            full_df = full_df.sample(n=sample_size, random_state=42)

        logger.info(f"Loaded {len(full_df)} samples")

        # Separate features and labels
        # CIC-IDS2017 has 'Label' column
        if 'Label' in full_df.columns:
            y = full_df['Label']
            X = full_df.drop('Label', axis=1)
        elif ' Label' in full_df.columns:
            y = full_df[' Label']
            X = full_df.drop(' Label', axis=1)
        else:
            logger.warning("No label column found, assuming all benign")
            y = pd.Series(['BENIGN'] * len(full_df))
            X = full_df

        return X, y

    def load_nslkdd(self, train: bool = True) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Load NSL-KDD dataset.

        Args:
            train: Load training set (True) or test set (False)

        Returns:
            Tuple of (features DataFrame, labels Series)
        """
        dataset_dir = self.dataset_path / "NSL-KDD"

        if not dataset_dir.exists():
            logger.error(f"NSL-KDD dataset not found at {dataset_dir}")
            logger.info("Please download from: https://www.unb.ca/cic/datasets/nsl.html")
            raise FileNotFoundError(f"Dataset not found: {dataset_dir}")

        # NSL-KDD file names
        filename = "KDDTrain+.txt" if train else "KDDTest+.txt"
        file_path = dataset_dir / filename

        if not file_path.exists():
            raise FileNotFoundError(f"Dataset file not found: {file_path}")

        logger.info(f"Loading {filename}")

        # NSL-KDD column names
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
        ]

        # Load dataset
        df = pd.read_csv(file_path, names=columns, header=None)

        # Separate features and labels
        y = df['label']
        X = df.drop(['label', 'difficulty'], axis=1)

        logger.info(f"Loaded {len(df)} samples")

        return X, y

    def load_unsw_nb15(self, train: bool = True) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Load UNSW-NB15 dataset.

        Args:
            train: Load training set (True) or test set (False)

        Returns:
            Tuple of (features DataFrame, labels Series)
        """
        dataset_dir = self.dataset_path / "UNSW-NB15"

        if not dataset_dir.exists():
            logger.error(f"UNSW-NB15 dataset not found at {dataset_dir}")
            logger.info("Please download from: https://research.unsw.edu.au/projects/unsw-nb15-dataset")
            raise FileNotFoundError(f"Dataset not found: {dataset_dir}")

        # UNSW-NB15 file names
        filename = "UNSW_NB15_training-set.csv" if train else "UNSW_NB15_testing-set.csv"
        file_path = dataset_dir / filename

        if not file_path.exists():
            raise FileNotFoundError(f"Dataset file not found: {file_path}")

        logger.info(f"Loading {filename}")

        # Load dataset
        df = pd.read_csv(file_path)

        # Separate features and labels
        # UNSW-NB15 has 'label' (0=benign, 1=attack) and 'attack_cat' columns
        if 'label' in df.columns:
            y = df['label']
            X = df.drop(['label', 'attack_cat'], axis=1, errors='ignore')
        else:
            raise ValueError("Label column not found in dataset")

        logger.info(f"Loaded {len(df)} samples")

        return X, y

    def get_dataset_info(self, dataset_name: str) -> Dict:
        """Get information about a dataset."""
        dataset_dir = self.dataset_path / dataset_name

        info = {
            'name': dataset_name,
            'path': str(dataset_dir),
            'exists': dataset_dir.exists(),
            'files': []
        }

        if dataset_dir.exists():
            info['files'] = [f.name for f in dataset_dir.iterdir() if f.is_file()]

        return info


# Global dataset manager instance
dataset_manager = DatasetManager()
