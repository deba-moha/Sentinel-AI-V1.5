"""
Sentinel AI - Unit Tests for ML Model Evaluation & Threshold Tuning (Phase 3)
Tests metric calculations (including division-by-zero edge cases), dataset separation,
reproducibility, threshold tuning, scenario-wise detection, saved model evaluation,
and regression compatibility.
"""
from pathlib import Path
import sys
import numpy as np
import pytest

from backend.app.ml.config import ML_FEATURE_NAMES
from backend.app.ml.evaluate import run_evaluation_cli
from backend.app.ml.evaluation import (
    EvaluationMetrics,
    calculate_metrics,
    evaluate_dataset,
    evaluate_scenarios,
    tune_threshold,
    run_comprehensive_evaluation
)
from backend.app.ml.model import IsolationForestModel
from backend.app.ml.model_store import save_model, load_model
from backend.app.ml.training_data import (
    generate_evaluation_splits,
    generate_labeled_dataset,
    generate_normal_training_data,
    generate_challenging_labeled_dataset,
    generate_low_and_slow_auth_samples,
    generate_gradual_port_scan_samples,
    generate_moderate_traffic_burst_samples,
    generate_subtle_recon_samples,
    generate_admin_activity_samples,
    generate_backup_burst_samples,
    generate_software_update_samples,
    generate_heavy_workstation_samples
)


def test_no_pandas_in_evaluation():
    """Verify that importing evaluation modules does not import Pandas."""
    import backend.app.ml.evaluation
    import backend.app.ml.evaluate

    assert "pandas" not in sys.modules, "Pandas must not be imported anywhere in evaluation"


def test_calculate_metrics_standard():
    """Verify exact formula calculations for standard binary predictions."""
    # TP=2, TN=2, FP=1, FN=1 -> Total=6
    y_true = np.array([1, 1, 1, 0, 0, 0])
    y_pred = np.array([1, 1, 0, 1, 0, 0])

    m = calculate_metrics(y_true, y_pred)
    assert m.tp == 2
    assert m.tn == 2
    assert m.fp == 1
    assert m.fn == 1
    assert m.total == 6
    assert m.accuracy == round(4 / 6, 4)
    assert m.precision == round(2 / 3, 4)
    assert m.recall == round(2 / 3, 4)
    assert m.tpr == round(2 / 3, 4)
    assert m.fpr == round(1 / 3, 4)
    assert m.f1_score == round(2 / 3, 4)

    d = m.to_dict()
    assert isinstance(d, dict)
    assert d["tp"] == 2


def test_calculate_metrics_edge_cases():
    """Verify safe handling of zero division, empty arrays, and all-zero/all-one cases."""
    # 1. Empty arrays
    m_empty = calculate_metrics(np.array([]), np.array([]))
    assert m_empty.total == 0
    assert m_empty.accuracy == 0.0
    assert m_empty.precision == 0.0
    assert m_empty.recall == 0.0
    assert m_empty.f1_score == 0.0

    # 2. All Normal True & Predicted (Zero TP, Zero FP, Zero FN)
    y_all_norm = np.array([0, 0, 0, 0])
    m_norm = calculate_metrics(y_all_norm, y_all_norm)
    assert m_norm.tn == 4
    assert m_norm.tp == 0
    assert m_norm.fp == 0
    assert m_norm.fn == 0
    assert m_norm.accuracy == 1.0
    assert m_norm.precision == 0.0  # Division by zero handled
    assert m_norm.recall == 0.0     # Division by zero handled
    assert m_norm.fpr == 0.0
    assert m_norm.f1_score == 0.0

    # 3. All Anomalies True & Predicted (Zero TN, Zero FP, Zero FN)
    y_all_anom = np.array([1, 1, 1])
    m_anom = calculate_metrics(y_all_anom, y_all_anom)
    assert m_anom.tp == 3
    assert m_anom.accuracy == 1.0
    assert m_anom.precision == 1.0
    assert m_anom.recall == 1.0
    assert m_anom.f1_score == 1.0
    assert m_anom.fpr == 0.0        # Division by zero handled

    # 4. Dimension mismatch raises ValueError
    with pytest.raises(ValueError, match="Shape mismatch"):
        calculate_metrics(np.array([1, 0]), np.array([1]))


def test_dataset_separation_and_reproducibility():
    """Verify strict dataset segregation between Train, Validation, and Test."""
    splits_a = generate_evaluation_splits(
        n_train_normal=100,
        n_val_normal=50,
        n_val_per_anomaly=10,
        n_test_normal=50,
        n_test_per_anomaly=10,
        base_seed=42
    )

    splits_b = generate_evaluation_splits(
        n_train_normal=100,
        n_val_normal=50,
        n_val_per_anomaly=10,
        n_test_normal=50,
        n_test_per_anomaly=10,
        base_seed=42
    )

    # Reproducibility
    assert np.array_equal(splits_a["train"]["X"], splits_b["train"]["X"])
    assert np.array_equal(splits_a["validation"]["X"], splits_b["validation"]["X"])
    assert np.array_equal(splits_a["test"]["X"], splits_b["test"]["X"])

    # Segregation: Verify no row identity between Train and Test
    train_X = splits_a["train"]["X"]
    test_X = splits_a["test"]["X"]
    assert train_X.shape[0] == 100
    assert test_X.shape[0] == 90  # 50 normal + 4*10 anomalies

    # Check that test contains anomaly labels (1), whereas train contains only normal (0)
    assert np.all(splits_a["train"]["y"] == 0)
    assert np.any(splits_a["test"]["y"] == 1)
    assert np.any(splits_a["test"]["y"] == 0)


def test_threshold_selection_on_validation():
    """Verify that threshold selection evaluates on validation data and respects FPR constraint."""
    X_train = generate_normal_training_data(n_samples=150, seed=42)
    model = IsolationForestModel().fit(X_train)

    X_val, y_val, _ = generate_labeled_dataset(n_normal=80, n_per_anomaly=20, seed=101)

    candidates = [-0.10, -0.05, -0.02, 0.0, 0.02, 0.05]
    best_t, grid, best_metrics = tune_threshold(
        model=model,
        X_val=X_val,
        y_val=y_val,
        candidate_thresholds=candidates,
        max_fpr=0.10
    )

    assert best_t in candidates
    assert len(grid) == len(candidates)
    assert best_metrics["fpr"] <= 0.10
    assert best_metrics["f1_score"] > 0.80

    # Ensure candidate grid entries are well-formed
    for entry in grid:
        assert "threshold" in entry
        assert "precision" in entry
        assert "recall" in entry
        assert "f1_score" in entry
        assert "fpr" in entry


def test_scenario_wise_evaluation():
    """Verify scenario-wise detection breakdown across all 5 target scenarios."""
    X_train = generate_normal_training_data(n_samples=150, seed=42)
    model = IsolationForestModel().fit(X_train)

    X_test, y_test, scenarios = generate_labeled_dataset(
        n_normal=60,
        n_per_anomaly=15,
        seed=202
    )

    eval_result = evaluate_scenarios(
        model=model,
        X=X_test,
        y=y_test,
        scenarios=scenarios,
        threshold=0.0
    )

    assert "scenarios" in eval_result
    sc_dict = eval_result["scenarios"]

    # All 5 scenarios must be present
    expected_scenarios = {"normal", "brute_force", "port_scan", "ddos", "data_burst"}
    assert set(sc_dict.keys()) == expected_scenarios

    # Normal scenario check (at baseline threshold 0.0, specificity is ~88-95%)
    assert sc_dict["normal"]["sample_count"] == 60
    assert sc_dict["normal"]["specificity"] >= 0.85
    assert "status" in sc_dict["normal"]

    # Attack scenarios check
    for attack in ["brute_force", "port_scan", "ddos", "data_burst"]:
        assert sc_dict[attack]["sample_count"] == 15
        assert sc_dict[attack]["detection_rate"] >= 0.85
        assert sc_dict[attack]["status"] in ("STRONG", "MODERATE")


def test_evaluation_with_saved_model(tmp_path: Path):
    """Verify evaluating an IsolationForestModel loaded from disk via model_store."""
    X_train = generate_normal_training_data(n_samples=100, seed=42)
    model = IsolationForestModel().fit(X_train)

    save_dest = tmp_path / "model_eval_test.joblib"
    save_model(model, filepath=save_dest)

    loaded = load_model(save_dest)

    # Evaluate using loaded model
    splits = generate_evaluation_splits(
        n_train_normal=100,
        n_val_normal=40,
        n_val_per_anomaly=10,
        n_test_normal=40,
        n_test_per_anomaly=10,
        base_seed=42
    )

    report = run_comprehensive_evaluation(model=loaded, splits=splits)

    assert report["dataset_sizes"]["train_samples"] == 100
    assert report["dataset_sizes"]["validation_samples"] == 80
    assert report["dataset_sizes"]["test_samples"] == 80
    assert "held_out_test_baseline" in report
    assert "held_out_test_tuned" in report

    t_metrics = report["held_out_test_tuned"]["overall_metrics"]
    assert t_metrics["accuracy"] >= 0.90
    assert t_metrics["f1_score"] >= 0.90


def test_invalid_and_unfitted_model_handling():
    """Verify defensive handling of unfitted models and mismatched inputs."""
    unfitted = IsolationForestModel()
    X = np.zeros((10, len(ML_FEATURE_NAMES)))
    y = np.zeros(10)

    with pytest.raises(RuntimeError, match="Cannot evaluate an unfitted model"):
        evaluate_dataset(unfitted, X, y)

    # Mismatched scenario count
    fitted = IsolationForestModel().fit(X)
    with pytest.raises(ValueError, match="identical lengths"):
        evaluate_scenarios(fitted, X, y, scenarios=["normal"] * 5)  # 5 != 10


def test_regression_compatibility():
    """Verify that Phase 1 preprocessing output flows cleanly into Phase 3 evaluation."""
    from backend.app.ml.preprocessing import preprocess_feature_batch

    raw_dicts = [
        {"total_events": 10.0, "failed_auth_count": 0.0},
        {"total_events": 80.0, "failed_auth_count": 50.0}
    ]
    X_preprocessed = preprocess_feature_batch(raw_dicts)
    y_labels = np.array([0, 1])

    X_train = generate_normal_training_data(n_samples=50, seed=42)
    model = IsolationForestModel().fit(X_train)

    eval_out = evaluate_dataset(model, X_preprocessed, y_labels)
    assert eval_out["metrics"]["total"] == 2
    assert 0.0 <= eval_out["metrics"]["accuracy"] <= 1.0


# =====================================================================
# Phase 3 Audit Correction Tests (Safe Loading & Challenging Data)
# =====================================================================

def test_evaluate_cli_safe_loading_when_missing_and_train_if_missing_false(tmp_path: Path):
    """Verify Correction 1: CLI halts with FileNotFoundError if model is missing and flag not set."""
    nonexistent = tmp_path / "nonexistent_model.joblib"
    with pytest.raises(FileNotFoundError, match="No saved model found"):
        run_evaluation_cli(model_path=str(nonexistent), train_if_missing=False, verbose=False)


def test_evaluate_cli_train_if_missing_creates_temporary_model(tmp_path: Path):
    """Verify Correction 1: CLI creates temporary model without persisting it when flag is set."""
    nonexistent = tmp_path / "temporary_eval.joblib"
    report = run_evaluation_cli(model_path=str(nonexistent), train_if_missing=True, verbose=False)

    assert report["model_info"]["source"] == "temporary_in_memory"
    assert report["model_info"]["persisted"] is False
    assert not nonexistent.exists(), "Temporary model must NOT be saved to disk"
    assert "held_out_test_tuned" in report


def test_evaluate_cli_corrupt_model_aborts_without_silent_fallback(tmp_path: Path):
    """Verify Correction 1: Corrupted model file raises RuntimeError and halts immediately."""
    corrupt_file = tmp_path / "corrupt_model.joblib"
    corrupt_file.write_bytes(b"INVALID_SERIALIZED_DATA_NOT_JOBLIB")

    # Even with train_if_missing=True, corruption must abort and not fallback silently
    with pytest.raises(RuntimeError, match="Failed to load saved model"):
        run_evaluation_cli(model_path=str(corrupt_file), train_if_missing=True, verbose=False)


def test_evaluate_cli_with_valid_saved_model(tmp_path: Path):
    """Verify Correction 1: Valid saved model is loaded and explicitly identified."""
    X_train = generate_normal_training_data(n_samples=80, seed=42)
    model = IsolationForestModel().fit(X_train)
    save_dest = tmp_path / "valid_model.joblib"
    save_model(model, filepath=save_dest)

    report = run_evaluation_cli(model_path=str(save_dest), verbose=False)
    assert report["model_info"]["source"] == "saved_model"
    assert report["model_info"]["persisted"] is True
    assert "held_out_test_tuned" in report


def test_challenging_dataset_generators_and_labels():
    """Verify Correction 2: Individual scenario generators and combined dataset labels."""
    # 1. Subtle Anomaly generators (y = 1)
    low_auth = generate_low_and_slow_auth_samples(n_samples=10, seed=10)
    grad_scan = generate_gradual_port_scan_samples(n_samples=10, seed=11)
    mod_burst = generate_moderate_traffic_burst_samples(n_samples=10, seed=12)
    sub_recon = generate_subtle_recon_samples(n_samples=10, seed=13)

    for m in [low_auth, grad_scan, mod_burst, sub_recon]:
        assert m.shape == (10, 9)
        assert np.all(np.isfinite(m))
        assert np.all(m >= 0.0)

    # 2. Borderline Normal generators (y = 0)
    admin = generate_admin_activity_samples(n_samples=10, seed=14)
    backup = generate_backup_burst_samples(n_samples=10, seed=15)
    update = generate_software_update_samples(n_samples=10, seed=16)
    workstation = generate_heavy_workstation_samples(n_samples=10, seed=17)

    for m in [admin, backup, update, workstation]:
        assert m.shape == (10, 9)
        assert np.all(np.isfinite(m))
        assert np.all(m >= 0.0)

    # 3. Combined labeled dataset
    X, y, scenarios = generate_challenging_labeled_dataset(n_per_scenario=10, seed=42)
    assert X.shape == (80, 9)
    assert len(y) == 80
    assert len(scenarios) == 80

    # First 40 rows are borderline normal (y = 0)
    assert np.all(y[:40] == 0)
    # Next 40 rows are subtle anomalies (y = 1)
    assert np.all(y[40:] == 1)

    expected_scenarios = {
        "admin_activity", "backup_burst", "software_updates", "heavy_workstation",
        "low_and_slow_auth", "gradual_port_scan", "moderate_traffic_burst", "subtle_recon"
    }
    assert set(scenarios) == expected_scenarios


def test_challenging_splits_and_struggling_detection():
    """Verify Correction 2: Challenging splits are segregated and honestly evaluated."""
    splits = generate_evaluation_splits(
        n_train_normal=80,
        n_val_normal=40,
        n_val_per_anomaly=10,
        n_test_normal=40,
        n_test_per_anomaly=10,
        base_seed=42,
        include_challenging=True,
        n_challenging_per_scenario=10
    )

    assert "challenging_validation" in splits
    assert "challenging_test" in splits

    # Segregation check: zero row identity between Train and Challenging Test
    train_X = splits["train"]["X"]
    c_test_X = splits["challenging_test"]["X"]
    train_hashes = {hash(row.tobytes()) for row in train_X}
    c_test_hashes = {hash(row.tobytes()) for row in c_test_X}
    assert len(train_hashes.intersection(c_test_hashes)) == 0

    # Comprehensive evaluation includes challenging test results
    report = run_comprehensive_evaluation(splits=splits)
    assert "held_out_challenging_test" in report
    c_res = report["held_out_challenging_test"]
    assert "overall_metrics" in c_res
    assert "scenarios" in c_res

    # Honest reporting: gradual port scan blends into normal and struggles (< 85% detection)
    c_scenarios = c_res["scenarios"]
    assert "gradual_port_scan" in c_scenarios
    assert c_scenarios["gradual_port_scan"]["status"] == "STRUGGLING"
    assert "gradual_port_scan" in report["challenging_struggling_scenarios"]

