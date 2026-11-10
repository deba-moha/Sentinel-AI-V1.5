"""
Sentinel AI - Unit Tests for ML Preprocessing Pipeline (Phase 1)
Tests numerical conversion, missing value imputation, NaN/Inf sanitization,
strict feature-column ordering, and matrix validation using pure NumPy.
Verifies that the entire ML package operates without Pandas.
"""
import sys
import numpy as np
import pytest
from backend.app.ml.config import (
    ML_FEATURE_NAMES,
    IsolationForestConfig,
    MLConfig,
    ml_config
)
from backend.app.ml.preprocessing import (
    clean_numerical_value,
    preprocess_feature_dict,
    preprocess_feature_batch,
    preprocess_to_records,
    validate_feature_matrix
)


def test_no_pandas_dependency():
    """Verify that importing ML modules does not import Pandas into sys.modules."""
    import backend.app.ml
    import backend.app.ml.features
    import backend.app.ml.preprocessing
    import backend.app.ml.config

    assert "pandas" not in sys.modules, "Pandas must not be imported anywhere in the ML pipeline"


def test_clean_numerical_value():
    """Verify scalar sanitization against invalid, non-finite, and null inputs."""
    # Standard valid values
    assert clean_numerical_value(0) == 0.0
    assert clean_numerical_value(42.5) == 42.5
    assert clean_numerical_value("123.45") == 123.45

    # Null and empty
    assert clean_numerical_value(None) == 0.0
    assert clean_numerical_value("", default=5.0) == 5.0

    # Non-finite floats
    assert clean_numerical_value(float("nan")) == 0.0
    assert clean_numerical_value(float("inf")) == 0.0
    assert clean_numerical_value(float("-inf")) == 0.0
    assert clean_numerical_value(np.nan) == 0.0
    assert clean_numerical_value(np.inf) == 0.0
    assert clean_numerical_value(-np.inf) == 0.0

    # Unparseable strings and arbitrary types
    assert clean_numerical_value("not_a_number") == 0.0
    assert clean_numerical_value(["list"]) == 0.0
    assert clean_numerical_value({"key": "val"}) == 0.0


def test_empty_input_preprocessing():
    """Verify preprocessing of empty inputs returns properly dimensioned structures."""
    num_features = len(ML_FEATURE_NAMES)

    # Empty dictionary -> (1, n_features) all zeros
    arr_single = preprocess_feature_dict({})
    assert arr_single.shape == (1, num_features)
    assert arr_single.dtype == np.float64
    assert np.all(arr_single == 0.0)

    # None dictionary -> (1, n_features) all zeros
    arr_none = preprocess_feature_dict(None)
    assert arr_none.shape == (1, num_features)
    assert np.all(arr_none == 0.0)

    # Empty batch -> (0, n_features)
    arr_batch_empty = preprocess_feature_batch([])
    assert arr_batch_empty.shape == (0, num_features)
    assert arr_batch_empty.dtype == np.float64

    # None batch -> (0, n_features)
    arr_batch_none = preprocess_feature_batch(None)
    assert arr_batch_none.shape == (0, num_features)

    # Empty records list
    records_empty = preprocess_to_records([])
    assert records_empty == []


def test_missing_optional_keys_imputation():
    """Verify that feature dictionaries with missing keys are safely imputed with 0.0."""
    partial_features = {
        "total_events": 10.0,
        "failed_auth_count": 3.0,
        # Other 7 features omitted
    }

    arr = preprocess_feature_dict(partial_features)
    assert arr.shape == (1, len(ML_FEATURE_NAMES))
    assert arr[0, 0] == 10.0  # total_events
    assert arr[0, 1] == 3.0   # failed_auth_count
    # All omitted keys must default to 0.0
    for idx in range(2, len(ML_FEATURE_NAMES)):
        assert arr[0, idx] == 0.0


def test_invalid_numerical_values_sanitization():
    """Verify that NaN, Infs, and strings in feature dictionaries are neutralized."""
    corrupted_features = {
        "total_events": float("nan"),
        "failed_auth_count": float("inf"),
        "successful_auth_count": float("-inf"),
        "unique_source_ips": None,
        "unique_dest_ips": "corrupted_text",
        "unique_dest_ports": 22.0,
        "event_frequency": np.nan,
        "avg_time_interval": np.inf,
        "network_traffic_volume": 1024.0,
    }

    arr = preprocess_feature_dict(corrupted_features)

    assert not np.isnan(arr).any(), "Array must not contain any NaN"
    assert not np.isinf(arr).any(), "Array must not contain any Inf"
    assert arr[0, 0] == 0.0  # nan -> 0.0
    assert arr[0, 1] == 0.0  # inf -> 0.0
    assert arr[0, 2] == 0.0  # -inf -> 0.0
    assert arr[0, 3] == 0.0  # None -> 0.0
    assert arr[0, 4] == 0.0  # string -> 0.0
    assert arr[0, 5] == 22.0
    assert arr[0, 6] == 0.0
    assert arr[0, 7] == 0.0
    assert arr[0, 8] == 1024.0

    # Validation must pass after sanitization
    assert validate_feature_matrix(arr) is True


def test_consistent_feature_column_ordering():
    """Verify that features are always emitted in the identical canonical order regardless of dict order."""
    # Reverse ordered dictionary
    reversed_features = {name: float(i + 1) for i, name in enumerate(reversed(ML_FEATURE_NAMES))}

    arr = preprocess_feature_dict(reversed_features)

    for i, name in enumerate(ML_FEATURE_NAMES):
        expected_val = reversed_features[name]
        assert arr[0, i] == expected_val, f"Mismatch at index {i} for feature {name}"

    # Verify batch ordering and records conversion
    records = preprocess_to_records([reversed_features])
    assert len(records) == 1
    assert list(records[0].keys()) == ML_FEATURE_NAMES
    for name in ML_FEATURE_NAMES:
        assert records[0][name] == reversed_features[name]


def test_validate_feature_matrix_constraints():
    """Verify that validate_feature_matrix enforces dimensionality, column count, and finiteness."""
    valid_matrix = np.zeros((5, len(ML_FEATURE_NAMES)), dtype=np.float64)
    assert validate_feature_matrix(valid_matrix) is True

    # 1D array should fail
    with pytest.raises(ValueError, match="Feature matrix must be 2-dimensional"):
        validate_feature_matrix(np.zeros((5,)))

    # Wrong column count should fail
    with pytest.raises(ValueError, match="Feature matrix column count mismatch"):
        validate_feature_matrix(np.zeros((5, 3)))

    # NaN presence should fail
    nan_matrix = np.zeros((2, len(ML_FEATURE_NAMES)))
    nan_matrix[0, 1] = np.nan
    with pytest.raises(ValueError, match="contains invalid NaN values"):
        validate_feature_matrix(nan_matrix)

    # Inf presence should fail
    inf_matrix = np.zeros((2, len(ML_FEATURE_NAMES)))
    inf_matrix[1, 2] = np.inf
    with pytest.raises(ValueError, match="contains invalid Infinite values"):
        validate_feature_matrix(inf_matrix)

    # Non-numpy input should fail
    with pytest.raises(TypeError, match="Expected numpy.ndarray"):
        validate_feature_matrix([[1, 2, 3]])  # type: ignore


def test_ml_configuration_structure_and_no_active_model():
    """Verify configuration parameters for future Isolation Forest and ensure no model is loaded."""
    config = ml_config
    assert isinstance(config, MLConfig)
    assert config.feature_names == ML_FEATURE_NAMES
    assert len(config.feature_names) == 9

    iso_cfg = config.isolation_forest
    assert isinstance(iso_cfg, IsolationForestConfig)
    assert iso_cfg.n_estimators == 100
    assert iso_cfg.contamination == 0.05
    assert iso_cfg.random_state == 42
    assert iso_cfg.n_jobs == -1

    # Verify that scikit-learn is available but no model instance is active or persisted
    import sklearn
    assert hasattr(sklearn, "__version__")

    # Confirm that neither config nor ml package exposes an active trained model object
    import backend.app.ml as ml_pkg
    assert not hasattr(ml_pkg, "trained_model")
    assert not hasattr(ml_pkg, "active_model")
    assert not hasattr(ml_pkg, "clf")
    assert not hasattr(ml_pkg, "isolation_forest_model")
