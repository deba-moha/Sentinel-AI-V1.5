"""
Sentinel AI - Unit Tests for Isolation Forest ML Model & Store (Phase 2)
Tests model initialization, training reproducibility, normal and anomaly prediction,
score generation, Joblib persistence, schema validation, and missing model handling.
Uses temporary directories (tmp_path) to ensure zero project file pollution.
"""
from pathlib import Path
import sys
import joblib
import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from backend.app.ml.config import ML_FEATURE_NAMES, ml_config
from backend.app.ml.model import IsolationForestModel
from backend.app.ml.model_store import (
    save_model,
    load_model,
    model_exists,
    get_model_metadata,
    ModelNotFoundError,
    ModelValidationError
)
from backend.app.ml.training_data import (
    generate_normal_training_data,
    generate_synthetic_anomaly_samples
)
from backend.app.ml.train import train_model


def test_no_pandas_imported_in_phase2():
    """Verify that importing ML model modules does not introduce Pandas."""
    import backend.app.ml.model
    import backend.app.ml.model_store
    import backend.app.ml.training_data
    import backend.app.ml.train

    assert "pandas" not in sys.modules, "Pandas must not be imported anywhere in Phase 2"


def test_synthetic_normal_training_data_properties():
    """Verify normal synthetic dataset dimensionality, reproducibility, and constraints."""
    data_1 = generate_normal_training_data(n_samples=100, seed=42)
    data_2 = generate_normal_training_data(n_samples=100, seed=42)

    assert data_1.shape == (100, len(ML_FEATURE_NAMES))
    assert data_1.dtype == np.float64
    assert np.array_equal(data_1, data_2), "Identical seed must produce identical matrices"

    # Verify no brute force or port scan anomalies in normal data
    # feature 1 = failed_auth_count (< 5), feature 5 = unique_dest_ports (< 5)
    assert np.all(data_1[:, 1] < 5.0), "Normal traffic must never contain brute force (>= 5)"
    assert np.all(data_1[:, 5] < 5.0), "Normal traffic must never contain port scans (>= 5)"


def test_model_training_with_valid_matrix():
    """Verify IsolationForestModel training updates internal state and metadata."""
    X_train = generate_normal_training_data(n_samples=150, seed=42)
    model = IsolationForestModel()

    assert model.is_fitted is False
    assert model.sample_count == 0

    model.fit(X_train)

    assert model.is_fitted is True
    assert model.sample_count == 150
    assert model.trained_at is not None

    meta = model.get_metadata()
    assert meta["model_type"] == "IsolationForest"
    assert meta["sample_count"] == 150
    assert meta["feature_count"] == 9


def test_reproducible_training():
    """Verify that two models trained on the same data with the same seed yield identical outputs."""
    X_train = generate_normal_training_data(n_samples=100, seed=42)
    X_test = generate_normal_training_data(n_samples=20, seed=99)

    model_a = IsolationForestModel().fit(X_train)
    model_b = IsolationForestModel().fit(X_train)

    preds_a = model_a.predict_raw(X_test)
    preds_b = model_b.predict_raw(X_test)
    assert np.array_equal(preds_a, preds_b), "Predictions must be bitwise identical"

    scores_a = model_a.decision_function(X_test)
    scores_b = model_b.decision_function(X_test)
    assert np.allclose(scores_a, scores_b), "Decision scores must match identically"


def test_normal_sample_prediction():
    """Verify that normal synthetic samples are predominantly classified as NORMAL."""
    X_train = generate_normal_training_data(n_samples=250, seed=42)
    model = IsolationForestModel().fit(X_train)

    # Test with new normal samples
    X_normal_test = generate_normal_training_data(n_samples=50, seed=123)
    results = model.predict(X_normal_test)

    assert len(results) == 50
    normal_count = sum(1 for r in results if r["prediction"] == "NORMAL")
    # With 0.05 contamination, at least 90% of unseen normal samples should be predicted NORMAL
    assert normal_count >= 45, f"Expected >= 45 normal predictions, got {normal_count}"

    for r in results:
        assert isinstance(r["is_anomaly"], bool)
        assert isinstance(r["raw_score"], float)
        assert 0.0 <= r["anomaly_score"] <= 1.0
        assert "interpretation" in r


def test_anomaly_prediction_with_unusual_samples():
    """Verify that deliberately abnormal samples are classified as ANOMALY."""
    X_train = generate_normal_training_data(n_samples=250, seed=42)
    model = IsolationForestModel().fit(X_train)

    # Generate severe synthetic attack samples (brute-force, port scan, DDoS)
    X_anomalies = generate_synthetic_anomaly_samples(n_samples=12, seed=888)
    results = model.predict(X_anomalies)

    assert len(results) == 12
    anomaly_count = sum(1 for r in results if r["prediction"] == "ANOMALY")
    # Severe attacks should reliably be detected as statistical anomalies
    assert anomaly_count >= 10, f"Expected >= 10 anomalies, got {anomaly_count}"

    # Verify score direction for detected anomalies
    for r in results:
        if r["is_anomaly"]:
            assert r["prediction"] == "ANOMALY"
            assert r["raw_score"] < 0.0, "Anomaly raw_score must be negative"
            assert r["anomaly_score"] >= 0.5, "Anomaly score must be >= 0.5"


def test_predict_single_with_feature_dictionary():
    """Verify predict_single accepts a feature dictionary directly."""
    X_train = generate_normal_training_data(n_samples=100, seed=42)
    model = IsolationForestModel().fit(X_train)

    normal_dict = {
        "total_events": 15.0,
        "failed_auth_count": 0.0,
        "successful_auth_count": 2.0,
        "unique_source_ips": 2.0,
        "unique_dest_ips": 1.0,
        "unique_dest_ports": 2.0,
        "event_frequency": 0.5,
        "avg_time_interval": 2.0,
        "network_traffic_volume": 3500.0
    }

    res = model.predict_single(normal_dict)
    assert res["prediction"] == "NORMAL"
    assert res["is_anomaly"] is False
    assert res["raw_score"] >= 0.0


def test_unfitted_model_prediction_raises_runtime_error():
    """Verify that predicting on an unfitted model raises RuntimeError."""
    model = IsolationForestModel()
    with pytest.raises(RuntimeError, match="IsolationForestModel is not fitted"):
        model.predict({"total_events": 10})

    with pytest.raises(RuntimeError, match="IsolationForestModel is not fitted"):
        model.predict_raw(np.zeros((1, 9)))


def test_invalid_feature_dimensions_raises_error():
    """Verify that feature matrices with incorrect column count raise ValueError."""
    model = IsolationForestModel()
    wrong_dim_matrix = np.zeros((10, 5))  # 5 features instead of 9

    with pytest.raises(ValueError, match="Feature matrix column count mismatch"):
        model.fit(wrong_dim_matrix)


def test_model_persistence_save_and_load(tmp_path: Path):
    """Verify saving to and loading from disk produces identical predictions."""
    X_train = generate_normal_training_data(n_samples=120, seed=42)
    model = IsolationForestModel().fit(X_train)

    save_file = tmp_path / "test_iso_forest.joblib"
    assert not model_exists(save_file)

    saved_path = save_model(model, filepath=save_file)
    assert saved_path == save_file
    assert model_exists(save_file)

    # Load model back
    loaded_model = load_model(filepath=save_file)
    assert loaded_model.is_fitted is True
    assert loaded_model.sample_count == 120

    # Compare predictions on unseen test data
    X_test = generate_normal_training_data(n_samples=15, seed=77)
    orig_preds = model.predict(X_test)
    loaded_preds = loaded_model.predict(X_test)

    for i in range(len(orig_preds)):
        assert orig_preds[i]["prediction"] == loaded_preds[i]["prediction"]
        assert orig_preds[i]["raw_score"] == loaded_preds[i]["raw_score"]
        assert orig_preds[i]["anomaly_score"] == loaded_preds[i]["anomaly_score"]

    # Verify metadata retrieval
    metadata = get_model_metadata(save_file)
    assert metadata["sample_count"] == 120
    assert metadata["feature_count"] == 9


def test_saving_unfitted_model_raises_error(tmp_path: Path):
    """Verify attempting to save an unfitted model raises ValueError."""
    model = IsolationForestModel()
    with pytest.raises(ValueError, match="Cannot save an unfitted model"):
        save_model(model, filepath=tmp_path / "unfitted.joblib")


def test_missing_model_handling(tmp_path: Path):
    """Verify attempting to load a non-existent file raises ModelNotFoundError."""
    non_existent = tmp_path / "missing_model.joblib"
    with pytest.raises(ModelNotFoundError, match="No trained ML model found at"):
        load_model(filepath=non_existent)


def test_feature_order_validation_on_load(tmp_path: Path):
    """Verify that a model with mismatched stored features is rejected on load."""
    corrupted_file = tmp_path / "corrupted_model.joblib"

    # Save a fake artifact with missing/wrong feature names
    fake_artifact = {
        "estimator": IsolationForest(),
        "feature_names": ["wrong_feature_1", "wrong_feature_2"],
        "metadata": {}
    }
    joblib.dump(fake_artifact, corrupted_file)

    with pytest.raises(ModelValidationError, match="Model feature mismatch"):
        load_model(filepath=corrupted_file, validate_schema=True)


def test_train_interface_end_to_end(tmp_path: Path):
    """Verify train_model() entry point runs, fits, saves, and returns summary."""
    target_joblib = tmp_path / "pipeline_model.joblib"

    model, path, summary = train_model(
        n_samples=80,
        save_path=target_joblib,
        seed=42,
        verbose=False
    )

    assert path == target_joblib
    assert target_joblib.is_file()
    assert summary["status"] == "SUCCESS"
    assert summary["n_samples"] == 80
    assert summary["n_features"] == 9
    assert model.is_fitted is True

    # Confirm loaded model works
    loaded = load_model(target_joblib)
    result = loaded.predict_single({"total_events": 10.0})
    assert result["prediction"] in ("NORMAL", "ANOMALY")
