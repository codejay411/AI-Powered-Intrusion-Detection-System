"""
Configuration management module.
Loads and validates system configuration from YAML and environment variables.
"""
import os
import yaml
from pathlib import Path
from typing import Any, Dict
from dotenv import load_dotenv


class Config:
    """Singleton configuration manager."""

    _instance = None
    _config: Dict[str, Any] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self):
        """Load configuration from YAML and environment variables."""
        # Load environment variables
        load_dotenv()

        # Determine project root
        self.project_root = Path(__file__).parent.parent

        # Load YAML config
        config_path = self.project_root / "config" / "config.yaml"
        if config_path.exists():
            with open(config_path, 'r') as f:
                self._config = yaml.safe_load(f)
        else:
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        # Override with environment variables where applicable
        self._apply_env_overrides()

        # Create necessary directories
        self._ensure_directories()

    def _apply_env_overrides(self):
        """Override config values with environment variables."""
        # Database overrides
        if os.getenv('DB_TYPE'):
            self._config['database']['type'] = os.getenv('DB_TYPE')
        if os.getenv('DB_PATH'):
            self._config['database']['sqlite']['path'] = os.getenv('DB_PATH')

        # API overrides
        if os.getenv('API_HOST'):
            self._config['api']['host'] = os.getenv('API_HOST')
        if os.getenv('API_PORT'):
            self._config['api']['port'] = int(os.getenv('API_PORT'))
        if os.getenv('API_SECRET_KEY'):
            self._config['api']['authentication']['jwt_secret'] = os.getenv('API_SECRET_KEY')

        # Dashboard overrides
        if os.getenv('DASHBOARD_PORT'):
            self._config['dashboard']['port'] = int(os.getenv('DASHBOARD_PORT'))

        # Logging overrides
        if os.getenv('LOG_LEVEL'):
            self._config['logging']['level'] = os.getenv('LOG_LEVEL')

    def _ensure_directories(self):
        """Create necessary directories if they don't exist."""
        directories = [
            self.project_root / "data",
            self.project_root / "data" / "pcaps",
            self.project_root / "data" / "logs",
            self.project_root / "data" / "datasets",
            self.project_root / "logs",
            self.project_root / "models",
            self.project_root / "config" / "rules",
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

            # Create .gitkeep files
            gitkeep = directory / ".gitkeep"
            if not gitkeep.exists():
                gitkeep.touch()

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.

        Args:
            key_path: Dot-separated path (e.g., 'database.type')
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self._config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def get_all(self) -> Dict[str, Any]:
        """Get entire configuration dictionary."""
        return self._config.copy()

    @property
    def db_type(self) -> str:
        """Get database type."""
        return self.get('database.type', 'sqlite')

    @property
    def db_path(self) -> Path:
        """Get database path (for SQLite)."""
        path = self.get('database.sqlite.path', 'data/ids.db')
        return self.project_root / path

    @property
    def model_path(self) -> Path:
        """Get models directory path."""
        return self.project_root / "models"

    @property
    def data_path(self) -> Path:
        """Get data directory path."""
        return self.project_root / "data"

    @property
    def log_path(self) -> Path:
        """Get logs directory path."""
        return self.project_root / "logs"

    @property
    def rules_path(self) -> Path:
        """Get rules directory path."""
        return self.project_root / "config" / "rules"


# Global config instance
config = Config()
