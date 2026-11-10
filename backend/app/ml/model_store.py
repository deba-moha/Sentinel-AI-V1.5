"""
Sentinel AI - ML Model Store & Persistence (Phase 2)
Provides secure, validated serialization and deserialization for Isolation Forest models
using Joblib. Guarantees feature-schema compatibility checks before loading.
"""
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union
import joblib

from backend.app.ml.config import (
    ML_FEATURE_NAMES,
    DEFAULT_MODEL_DIR,
    DEFAULT_MODEL_PATH,
    ml_config
)
from backend.app.ml.model import IsolationForestModel


class ModelStoreError(Exception):
    """Base exception for model persistence and validation errors."""
    pass


class ModelNotFoundError(ModelStoreError, FileNotFoundError):
    """Raised when an expected model artifact is missing from disk."""
    pass


class ModelValidationError(ModelStoreError, ValueError):
    """Raised when a loaded model fails schema or configuration validation."""
    pass


def get_model_directory() -> Path:
    """Returns the configured model directory, ensuring it exists."""
    model_dir = Path(ml_config.model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    return model_dir


def model_exists(filepath: Optional[Union[str, Path]] = None) -> bool:
    """Checks whether a valid, non-empty model file exists at the specified path."""
    target_path = Path(filepath) if filepath is not None else Path(ml_config.model_path)
    return target_path.is_file() and target_path.stat().st_size > 0


def save_model(
    model: IsolationForestModel,
    filepath: Optional[Union[str, Path]] = None
) -> Path:
    """
    Serializes a trained IsolationForestModel to disk using Joblib.
    Bundles the estimator with schema metadata, training timestamp, and configuration.

    Raises:
        ValueError: If the model has not been trained (.fit() not called).
    """
    if not isinstance(model, IsolationForestModel):
        raise TypeError(f"Expected IsolationForestModel instance, got {type(model).__name__}")

    if not model.is_fitted:
        raise ValueError("Cannot save an unfitted model. Train the model using .fit() before saving.")

    target_path = Path(filepath) if filepath is not None else Path(ml_config.model_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    metadata = model.get_metadata()
    artifact: Dict[str, Any] = {
        "estimator": model._clf,
        "feature_names": list(model.feature_names),
        "feature_count": len(model.feature_names),
        "model_version": ml_config.model_version,
        "config": model.config,
        "metadata": metadata,
        "saved_at": datetime.now(timezone.utc).isoformat()
    }

    joblib.dump(artifact, target_path)
    return target_path


def load_model(
    filepath: Optional[Union[str, Path]] = None,
    validate_schema: bool = True
) -> IsolationForestModel:
    """
    Loads and validates a saved Isolation Forest model from disk.

    Validation steps:
    1. Confirms file existence.
    2. Loads Joblib envelope and verifies required keys.
    3. Confirms feature names and sequence match current ML_FEATURE_NAMES.
    4. Validates feature count matches expected dimensionality.

    Raises:
        ModelNotFoundError: If the file does not exist on disk.
        ModelValidationError: If the artifact is corrupted or feature schema does not match.
    """
    target_path = Path(filepath) if filepath is not None else Path(ml_config.model_path)

    if not target_path.is_file():
        raise ModelNotFoundError(
            f"No trained ML model found at: {target_path}. "
            f"Train and save a model first using backend.app.ml.train.train_model()."
        )

    try:
        artifact = joblib.load(target_path)
    except Exception as e:
        raise ModelValidationError(f"Failed to deserialise model artifact from {target_path}: {e}") from e

    if not isinstance(artifact, dict) or "estimator" not in artifact:
        raise ModelValidationError(
            f"Invalid model artifact structure at {target_path}: missing 'estimator' payload."
        )

    # Schema & feature compatibility check
    if validate_schema:
        stored_features = artifact.get("feature_names")
        if stored_features != ML_FEATURE_NAMES:
            raise ModelValidationError(
                f"Model feature mismatch in {target_path}.\n"
                f"Expected features ({len(ML_FEATURE_NAMES)}): {ML_FEATURE_NAMES}\n"
                f"Stored features ({len(stored_features) if stored_features else 0}): {stored_features}"
            )

    # Reconstruct the IsolationForestModel wrapper
    config = artifact.get("config", ml_config.isolation_forest)
    model = IsolationForestModel(config=config)
    model._clf = artifact["estimator"]
    model.is_fitted = True

    meta = artifact.get("metadata", {})
    model.sample_count = meta.get("sample_count", 0)
    model.trained_at = meta.get("trained_at")

    return model


def get_model_metadata(
    filepath: Optional[Union[str, Path]] = None
) -> Dict[str, Any]:
    """Reads metadata from a saved model artifact without instantiating the full model wrapper."""
    target_path = Path(filepath) if filepath is not None else Path(ml_config.model_path)
    if not target_path.is_file():
        raise ModelNotFoundError(f"Model file not found at: {target_path}")

    try:
        artifact = joblib.load(target_path)
        if isinstance(artifact, dict) and "metadata" in artifact:
            return artifact["metadata"]
        return {"status": "unrecognized_artifact_format"}
    except Exception as e:
        raise ModelValidationError(f"Could not read metadata from {target_path}: {e}") from e

