"""
Sentinel AI - ML Preprocessing Pipeline (Phase 1)
Prepares numerical feature vectors for downstream ML estimators (such as Isolation Forest).
Guarantees consistent column ordering, safe missing-value imputation,
and elimination of NaN/inf values using pure NumPy and standard Python structures.
Note: Operates without Pandas to avoid Windows Application Control DLL load issues.
"""
import math
from typing import Any, Dict, List, Optional, Sequence, Union
import numpy as np
from backend.app.ml.config import ML_FEATURE_NAMES, ml_config


def clean_numerical_value(val: Any, default: float = 0.0) -> float:
    """
    Safely sanitizes a scalar value into a valid, finite Python float.
    Replaces None, NaN, positive infinity, negative infinity, and invalid strings
    with the safe fallback default (0.0).
    """
    if val is None:
        return default

    if isinstance(val, (int, float)):
        if math.isnan(val) or math.isinf(val):
            return default
        return float(val)

    if isinstance(val, (str, bytes)):
        try:
            parsed = float(val)
            if math.isnan(parsed) or math.isinf(parsed):
                return default
            return parsed
        except (ValueError, TypeError):
            return default

    # Fallback for unexpected complex/boolean/object types
    try:
        parsed = float(val)
        if math.isnan(parsed) or math.isinf(parsed):
            return default
        return parsed
    except (ValueError, TypeError):
        return default


def preprocess_feature_dict(
    feature_dict: Optional[Dict[str, Any]],
    feature_names: Optional[Sequence[str]] = None,
    default_value: float = 0.0
) -> np.ndarray:
    """
    Transforms a single feature dictionary into a sanitized 2D NumPy array
    of shape (1, n_features) with strictly ordered columns.

    Missing keys or invalid numerical values are imputed safely.
    """
    names = feature_names if feature_names is not None else ML_FEATURE_NAMES
    source = feature_dict or {}

    row = [clean_numerical_value(source.get(name), default=default_value) for name in names]
    matrix = np.array([row], dtype=np.float64)
    return matrix


def preprocess_feature_batch(
    feature_dicts: Optional[Sequence[Dict[str, Any]]],
    feature_names: Optional[Sequence[str]] = None,
    default_value: float = 0.0
) -> np.ndarray:
    """
    Transforms a sequence of feature dictionaries into a sanitized 2D NumPy array
    of shape (n_samples, n_features).

    Guarantees:
    - Fixed column ordering matching feature_names.
    - Zero NaN, +Inf, or -Inf values.
    - Safe handling of empty batch (returns (0, n_features) shape).
    """
    names = feature_names if feature_names is not None else ML_FEATURE_NAMES
    num_features = len(names)

    if not feature_dicts:
        return np.empty((0, num_features), dtype=np.float64)

    rows: List[List[float]] = []
    for f_dict in feature_dicts:
        source = f_dict or {}
        row = [clean_numerical_value(source.get(name), default=default_value) for name in names]
        rows.append(row)

    matrix = np.array(rows, dtype=np.float64)
    # Extra safety guarantee: double-clean any stray numpy NaN/Inf
    matrix = np.nan_to_num(matrix, nan=default_value, posinf=default_value, neginf=default_value)
    return matrix


def preprocess_to_records(
    feature_dicts: Optional[Sequence[Dict[str, Any]]],
    feature_names: Optional[Sequence[str]] = None,
    default_value: float = 0.0
) -> List[Dict[str, float]]:
    """
    Transforms a sequence of feature dictionaries into sanitized, strictly-ordered
    dictionaries (records) using standard Python data structures.
    Useful for inspecting or serializing features without Pandas.
    """
    names = list(feature_names) if feature_names is not None else list(ML_FEATURE_NAMES)
    matrix = preprocess_feature_batch(feature_dicts, feature_names=names, default_value=default_value)
    return [{name: float(row[i]) for i, name in enumerate(names)} for row in matrix]


def validate_feature_matrix(
    matrix: np.ndarray,
    expected_features: Optional[int] = None
) -> bool:
    """
    Validates that a feature matrix meets all ML input constraints:
    - 2-dimensional array.
    - Matches expected feature count (column count).
    - Contains no NaN, positive infinity, or negative infinity.

    Raises ValueError if validation fails; returns True otherwise.
    """
    if not isinstance(matrix, np.ndarray):
        raise TypeError(f"Expected numpy.ndarray, got {type(matrix).__name__}")

    if matrix.ndim != 2:
        raise ValueError(f"Feature matrix must be 2-dimensional (samples, features), got ndim={matrix.ndim}")

    target_features = expected_features if expected_features is not None else len(ML_FEATURE_NAMES)
    if matrix.shape[1] != target_features:
        raise ValueError(
            f"Feature matrix column count mismatch: expected {target_features}, got {matrix.shape[1]}"
        )

    if np.isnan(matrix).any():
        raise ValueError("Feature matrix contains invalid NaN values")

    if np.isinf(matrix).any():
        raise ValueError("Feature matrix contains invalid Infinite values")

    return True
