"""
Sentinel AI - ML Anomaly Rule Unit Tests (Phase 4 Step 5)
Verifies MLAnomalyRule behavior in complete isolation:
- Disabled and missing/corrupt model safety
- Minimum event count pre-filter guard
- Prediction scoring, threshold boundary, and fixed MEDIUM severity
- Deterministic source and destination attribution policies
- target_user is strictly None
- Non-causal explanation formatting and non-probability disclaimers
- Diagnostic performance profiling without brittle pass/fail assertions
"""
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock
import numpy as np
import pytest

from backend.app.core.config import settings
from backend.app.models.security_log import SecurityLog
from backend.app.models.alert import Alert
from backend.app.detection.rules import MLAnomalyRule
from backend.app.ml.model import IsolationForestModel
from backend.app.ml.config import IsolationForestConfig, ML_FEATURE_NAMES
from backend.app.ml.training_data import generate_normal_training_data
from backend.app.ml.model_store import save_model


@pytest.fixture
def controlled_test_model(tmp_path):
    """
    Creates a temporary, fitted IsolationForestModel persisted in tmp_path.
    Cleaned up automatically by pytest.
    """
    normal_data = generate_normal_training_data(n_samples=50, seed=42)
    cfg = IsolationForestConfig(n_estimators=20, random_state=42)
    model = IsolationForestModel(config=cfg)
    model.fit(normal_data)

    model_path = tmp_path / "test_model.joblib"
    save_model(model, filepath=model_path)
    return model, model_path


def test_ml_rule_disabled_and_missing_or_corrupt_model(db_session, tmp_path):
    """Verifies that disabled, missing, or corrupt models leave ML detection dormant."""
    # 1. Disabled via setting or attribute
    rule_disabled = MLAnomalyRule()
    rule_disabled.enabled = False
    log = SecurityLog(timestamp=datetime.now(timezone.utc), source_ip="192.168.1.1")
    assert rule_disabled.evaluate(log, db_session) is None

    # 2. Missing model file
    non_existent = tmp_path / "does_not_exist.joblib"
    rule_missing = MLAnomalyRule(model_path=str(non_existent))
    assert rule_missing.model is None
    assert rule_missing.evaluate(log, db_session) is None

    # 3. Corrupted model artifact on disk
    corrupt_file = tmp_path / "corrupt.joblib"
    corrupt_file.write_bytes(b"MALFORMED_JOB_LIB_HEADER_DATA_12345")
    rule_corrupt = MLAnomalyRule(model_path=str(corrupt_file))
    assert rule_corrupt.model is None
    assert rule_corrupt.evaluate(log, db_session) is None


def test_ml_rule_minimum_event_count_guard(db_session, controlled_test_model):
    """Inference is skipped when the window event count is below ML_MIN_EVENTS (5)."""
    _, model_path = controlled_test_model
    rule = MLAnomalyRule(model_path=str(model_path), min_events=5, threshold=1.0)
    now = datetime.now(timezone.utc)

    # Insert 4 events (< 5)
    logs = []
    for i in range(4):
        log = SecurityLog(
            timestamp=now - timedelta(seconds=i),
            source_ip="192.168.1.100",
            event_type="HTTP_REQUEST",
            message="Test"
        )
        db_session.add(log)
        logs.append(log)
    db_session.commit()

    # Must return None (skipped due to pre-filter count query)
    assert rule.evaluate(logs[-1], db_session) is None

    # Insert 5th event (>= 5)
    log_5 = SecurityLog(
        timestamp=now,
        source_ip="192.168.1.100",
        event_type="HTTP_REQUEST",
        message="Test 5"
    )
    db_session.add(log_5)
    db_session.commit()

    # With threshold=1.0, prediction trips
    res = rule.evaluate(log_5, db_session)
    assert res is not None
    assert res["rule_id"] == "RULE-ML-ANOMALY-IFOREST"


def test_ml_rule_normal_and_anomalous_predictions(db_session):
    """Verifies handling of normal (cleared) vs anomalous predictions."""
    rule = MLAnomalyRule(min_events=5)
    now = datetime.now(timezone.utc)

    # Insert 5 events in chronological ascending order
    logs = []
    for i in range(5):
        log = SecurityLog(
            timestamp=now - timedelta(seconds=10 - i),
            source_ip="10.0.0.1",
            event_type="HTTP_REQUEST",
            message="Test"
        )
        db_session.add(log)
        logs.append(log)
    db_session.commit()

    mock_model = MagicMock()
    rule.model = mock_model

    # Case A: Normal prediction
    mock_model.predict_single.return_value = {
        "is_anomaly": False,
        "raw_score": 0.05,
        "anomaly_score": 0.40
    }
    assert rule.evaluate(logs[-1], db_session) is None

    # Case B: Anomalous prediction
    mock_model.predict_single.return_value = {
        "is_anomaly": True,
        "raw_score": -0.06,
        "anomaly_score": 0.85
    }
    alert = rule.evaluate(logs[-1], db_session)
    assert alert is not None
    assert alert["rule_id"] == "RULE-ML-ANOMALY-IFOREST"
    assert alert["severity"] == "MEDIUM"


def test_ml_rule_threshold_boundary_evaluation(db_session):
    """
    Tests threshold boundary behavior immediately above and below -0.0200.
    - raw_score = -0.0199 (>= -0.0200) -> NOT anomalous -> returns None
    - raw_score = -0.0201 (< -0.0200) -> ANOMALOUS -> returns Alert
    """
    rule = MLAnomalyRule(threshold=-0.0200, min_events=5)
    now = datetime.now(timezone.utc)

    logs = []
    for i in range(5):
        log = SecurityLog(
            timestamp=now - timedelta(seconds=10 - i),
            source_ip="192.168.1.100",
            event_type="HTTP_REQUEST",
            message="Test"
        )
        db_session.add(log)
        logs.append(log)
    db_session.commit()

    mock_model = MagicMock()
    rule.model = mock_model

    # Boundary Case 1: Immediately above cutoff (-0.0199 >= -0.0200)
    mock_model.predict_single.return_value = {
        "is_anomaly": False,
        "raw_score": -0.0199,
        "anomaly_score": 0.49
    }
    assert rule.evaluate(logs[-1], db_session) is None

    # Boundary Case 2: Immediately below cutoff (-0.0201 < -0.0200)
    mock_model.predict_single.return_value = {
        "is_anomaly": True,
        "raw_score": -0.0201,
        "anomaly_score": 0.51
    }
    res = rule.evaluate(logs[-1], db_session)
    assert res is not None
    assert res["rule_id"] == "RULE-ML-ANOMALY-IFOREST"
    assert res["severity"] == "MEDIUM"


def test_ml_rule_fixed_severity_and_rule_id(db_session):
    """Confirms every ML alert strictly uses MEDIUM severity and RULE-ML-ANOMALY-IFOREST."""
    rule = MLAnomalyRule(min_events=5)
    now = datetime.now(timezone.utc)

    logs = []
    for i in range(5):
        log = SecurityLog(
            timestamp=now - timedelta(seconds=10 - i),
            source_ip="10.0.0.50",
            event_type="AUTH_FAILURE",
            message="Test"
        )
        db_session.add(log)
        logs.append(log)
    db_session.commit()

    mock_model = MagicMock()
    mock_model.predict_single.return_value = {
        "is_anomaly": True,
        "raw_score": -0.10,
        "anomaly_score": 0.95
    }
    rule.model = mock_model

    payload = rule.evaluate(logs[-1], db_session)
    assert payload["rule_id"] == "RULE-ML-ANOMALY-IFOREST"
    assert payload["severity"] == "MEDIUM"
    assert payload["title"] == "Machine Learning Anomaly Detected"


def test_ml_rule_source_and_destination_attribution_policies(db_session):
    """
    Tests the deterministic attribution policy:
    1. Dominant source (>= 60%)
    2. Distributed sources (>= 3 distinct sources, none >= 60%)
    3. Global Telemetry Window (< 3 sources, none >= 60%)
    4. Destination attribution (>= 60%; otherwise None)
    5. target_user is strictly None in all cases.
    """
    rule = MLAnomalyRule(min_events=5)
    mock_model = MagicMock()
    mock_model.predict_single.return_value = {
        "is_anomaly": True,
        "raw_score": -0.05,
        "anomaly_score": 0.70
    }
    rule.model = mock_model
    now = datetime.now(timezone.utc)

    # --- Scenario 1: Dominant source (7 of 10 events = 70% >= 60%) ---
    db_session.query(SecurityLog).delete()
    logs_dom = []
    for i in range(10):
        src = "192.168.1.100" if i < 7 else f"10.0.0.{i}"
        log = SecurityLog(
            timestamp=now - timedelta(seconds=20 - i),
            source_ip=src,
            destination_ip="10.0.0.5",
            user="alice",
            event_type="HTTP_REQUEST",
            message="Dom test"
        )
        db_session.add(log)
        logs_dom.append(log)
    db_session.commit()

    res_1 = rule.evaluate(logs_dom[-1], db_session)
    assert res_1["source_ip"] == "192.168.1.100"
    assert res_1["destination_ip"] == "10.0.0.5"  # 10/10 = 100% >= 60%
    assert res_1["target_user"] is None

    # --- Scenario 2: Distributed sources (10 distinct IPs, >= 3 sources, neither >= 60%) ---
    db_session.query(SecurityLog).delete()
    logs_dist = []
    for i in range(10):
        log = SecurityLog(
            timestamp=now - timedelta(seconds=20 - i),
            source_ip=f"198.51.100.{i}",
            destination_ip="10.0.0.5" if i < 5 else "10.0.0.6",  # 50% / 50% (< 60%)
            user=f"user_{i}",
            event_type="HTTP_REQUEST",
            message="Dist test"
        )
        db_session.add(log)
        logs_dist.append(log)
    db_session.commit()

    res_2 = rule.evaluate(logs_dist[-1], db_session)
    assert res_2["source_ip"] == "Distributed Sources"
    assert res_2["destination_ip"] is None  # Neither dest reaches 60%
    assert res_2["target_user"] is None

    # --- Scenario 3: Global Telemetry Window (2 sources, 50% each: < 3 sources and neither >= 60%) ---
    db_session.query(SecurityLog).delete()
    logs_diff = []
    for i in range(10):
        src = "10.0.0.1" if i < 5 else "10.0.0.2"
        log = SecurityLog(
            timestamp=now - timedelta(seconds=20 - i),
            source_ip=src,
            destination_ip=None,
            user=None,
            event_type="HTTP_REQUEST",
            message="Diff test"
        )
        db_session.add(log)
        logs_diff.append(log)
    db_session.commit()

    res_3 = rule.evaluate(logs_diff[-1], db_session)
    assert res_3["source_ip"] == "Global Telemetry Window"
    assert res_3["destination_ip"] is None
    assert res_3["target_user"] is None


def test_ml_rule_description_formatting_and_disclaimers(db_session):
    """Verifies that the alert description includes metrics, non-probability, and non-causal statements."""
    rule = MLAnomalyRule(min_events=5)
    mock_model = MagicMock()
    mock_model.predict_single.return_value = {
        "is_anomaly": True,
        "raw_score": -0.0450,
        "anomaly_score": 0.6800
    }
    rule.model = mock_model
    now = datetime.now(timezone.utc)

    logs = []
    for i in range(5):
        log = SecurityLog(
            timestamp=now - timedelta(seconds=10 - i),
            source_ip="192.168.1.1",
            event_type="HTTP_REQUEST",
            message="Desc test"
        )
        db_session.add(log)
        logs.append(log)
    db_session.commit()

    payload = rule.evaluate(logs[-1], db_session)
    desc = payload["description"]

    # Verify key tokens
    assert "Normalized Anomaly Score = 0.6800" in desc
    assert "Raw Score = -0.0450" in desc
    assert "Decision Cutoff: -0.0200" in desc
    assert "Window Telemetry (60s): 5 total events" in desc
    assert "geometric isolation path lengths" in desc
    assert "not probabilities or confirmed severity" in desc
    assert "does not perform causal feature attribution" in desc


def test_ml_rule_diagnostic_performance_profiling(db_session, controlled_test_model):
    """
    Diagnostic profiling of ML feature extraction, inference, and rule evaluation.
    Measures and reports mean, p95, and maximum observed latencies.
    Contains ZERO pass/fail timing threshold assertions.
    """
    _, model_path = controlled_test_model
    rule = MLAnomalyRule(model_path=str(model_path), min_events=5)
    now = datetime.now(timezone.utc)

    # Insert 10 events for evaluation window
    logs = []
    for i in range(10):
        log = SecurityLog(
            timestamp=now - timedelta(seconds=i),
            source_ip=f"192.168.1.{10 + (i % 3)}",
            destination_ip="10.0.0.5",
            destination_port=80,
            event_type="HTTP_REQUEST",
            message=f"Perf event {i}"
        )
        db_session.add(log)
        logs.append(log)
    db_session.commit()

    iterations = 25
    eval_times = []

    # Run diagnostic iterations
    for _ in range(iterations):
        t0 = time.perf_counter()
        rule.evaluate(logs[-1], db_session)
        eval_times.append((time.perf_counter() - t0) * 1000.0)  # ms

    mean_lat = np.mean(eval_times)
    p95_lat = np.percentile(eval_times, 95)
    max_lat = np.max(eval_times)

    print(f"\n[Diagnostic Performance Profiling - MLAnomalyRule (n={iterations})]")
    print(f" * Mean Latency:  {mean_lat:.3f} ms")
    print(f" * p95 Latency:   {p95_lat:.3f} ms")
    print(f" * Max Latency:   {max_lat:.3f} ms")

    # Pure diagnostic validity check: times were successfully recorded
    assert len(eval_times) == iterations
    assert all(t > 0 for t in eval_times)
