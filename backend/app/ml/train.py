"""
Sentinel AI - ML Model Training Interface (Phase 2)
Provides an independent, manual entry point to generate baseline normal training data,
fit Scikit-learn's Isolation Forest, and persist the model artifact.

Note: This training interface is standalone and never runs automatically on FastAPI startup.
"""
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union
import numpy as np

from backend.app.ml.config import (
    ML_FEATURE_NAMES,
    DEFAULT_MODEL_PATH,
    IsolationForestConfig,
    ml_config
)
from backend.app.ml.model import IsolationForestModel
from backend.app.ml.model_store import save_model
from backend.app.ml.preprocessing import validate_feature_matrix
from backend.app.ml.training_data import generate_normal_training_data


def train_model(
    n_samples: int = 250,
    save_path: Optional[Union[str, Path]] = None,
    seed: Optional[int] = None,
    verbose: bool = True
) -> Tuple[IsolationForestModel, Path, Dict[str, Any]]:
    """
    Executes the end-to-end Isolation Forest training workflow:
    1. Generates reproducible synthetic normal baseline data.
    2. Validates numerical feature matrix dimensions and finiteness.
    3. Fits Scikit-learn's IsolationForest on the 9 canonical features.
    4. Serializes the model and metadata via Joblib.
    5. Returns the trained model wrapper, saved path, and summary dictionary.

    Args:
        n_samples: Number of normal baseline feature records to generate.
        save_path: Destination path for Joblib artifact (defaults to ml_config.model_path).
        seed: Random seed for reproducible generation and model training.
        verbose: When True, prints a formatted summary to stdout.

    Returns:
        Tuple of (IsolationForestModel, Path to saved artifact, summary dictionary).
    """
    random_seed = seed if seed is not None else ml_config.isolation_forest.random_state

    # 1. Generate normal training baseline
    X_train = generate_normal_training_data(n_samples=n_samples, seed=random_seed)

    # 2. Validate feature matrix
    validate_feature_matrix(X_train, expected_features=len(ML_FEATURE_NAMES))

    # 3. Configure and fit Isolation Forest
    config = IsolationForestConfig(
        n_estimators=ml_config.isolation_forest.n_estimators,
        contamination=ml_config.isolation_forest.contamination,
        max_samples=ml_config.isolation_forest.max_samples,
        max_features=ml_config.isolation_forest.max_features,
        bootstrap=ml_config.isolation_forest.bootstrap,
        random_state=random_seed,
        n_jobs=ml_config.isolation_forest.n_jobs,
        anomaly_threshold=ml_config.isolation_forest.anomaly_threshold
    )
    model = IsolationForestModel(config=config)
    model.fit(X_train)

    # 4. Save model artifact
    target_path = Path(save_path) if save_path is not None else DEFAULT_MODEL_PATH
    saved_path = save_model(model, filepath=target_path)

    # 5. Build summary
    summary: Dict[str, Any] = {
        "status": "SUCCESS",
        "model_type": "IsolationForest",
        "model_version": ml_config.model_version,
        "n_samples": int(X_train.shape[0]),
        "n_features": int(X_train.shape[1]),
        "feature_names": list(ML_FEATURE_NAMES),
        "saved_path": str(saved_path),
        "random_seed": random_seed,
        "n_estimators": config.n_estimators,
        "contamination": config.contamination
    }

    if verbose:
        print("=" * 64)
        print("      SENTINEL-AI V1.5 - ISOLATION FOREST MODEL TRAINING        ")
        print("=" * 64)
        print(f" * Model Type:         {summary['model_type']} (Scikit-learn)")
        print(f" * Model Version:      {summary['model_version']}")
        print(f" * Training Samples:   {summary['n_samples']} normal baseline records")
        print(f" * Features ({summary['n_features']}):        {', '.join(summary['feature_names'][:4])}...")
        print(f" * Estimators:         {summary['n_estimators']} trees")
        print(f" * Contamination:      {summary['contamination']}")
        print(f" * Random Seed:        {summary['random_seed']}")
        print(f" * Saved Artifact:     {summary['saved_path']}")
        print(f" * Training Status:    {summary['status']}")
        print("=" * 64)

    return model, saved_path, summary


if __name__ == "__main__":
    train_model(verbose=True)

