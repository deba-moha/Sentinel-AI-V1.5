"""
Sentinel AI - Machine Learning Configuration
Centralized configuration for feature engineering, preprocessing, and
Isolation Forest anomaly detection.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Union


# Canonical feature names in strict order.
# All extraction, preprocessing, and training pipelines must follow this exact sequence.
ML_FEATURE_NAMES: List[str] = [
    "total_events",
    "failed_auth_count",
    "successful_auth_count",
    "unique_source_ips",
    "unique_dest_ips",
    "unique_dest_ports",
    "event_frequency",
    "avg_time_interval",
    "network_traffic_volume",
]

# Default model directory under the ml package
DEFAULT_MODEL_DIR = Path(__file__).resolve().parent / "saved_models"
DEFAULT_MODEL_PATH = DEFAULT_MODEL_DIR / "isolation_forest.joblib"


@dataclass
class IsolationForestConfig:
    """
    Configuration hyperparameters for Isolation Forest model development.
    Uses reproducible random_state and standard unsupervised anomaly parameters.
    """
    n_estimators: int = 100
    contamination: float = 0.05
    max_samples: Union[int, float, str] = "auto"
    max_features: float = 1.0
    bootstrap: bool = False
    random_state: int = 42
    n_jobs: int = -1
    anomaly_threshold: float = 0.0  # Decision function cutoff (< 0 indicates anomaly in scikit-learn)


@dataclass
class MLConfig:
    """
    Global ML module configuration container.
    """
    feature_names: List[str] = field(default_factory=lambda: list(ML_FEATURE_NAMES))
    isolation_forest: IsolationForestConfig = field(default_factory=IsolationForestConfig)
    default_impute_value: float = 0.0
    default_window_seconds: int = 60
    model_version: str = "1.5.0"
    model_dir: Path = DEFAULT_MODEL_DIR
    model_path: Path = DEFAULT_MODEL_PATH


# Central configuration instance
ml_config = MLConfig()
