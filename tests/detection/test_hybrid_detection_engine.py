"""
Sentinel AI - Hybrid Detection Engine Integration Tests (Phase 4 Step 5)
Verifies integration between deterministic rules and ML anomaly detection:
- Conditional registration of MLAnomalyRule based on ENABLE_ML_DETECTION
- Independent deterministic detection when ML is dormant or inactive
- Independent ML detection when deterministic rules do not trigger
- Dual alerting (both deterministic and ML alerts triggered in the same evaluation)
- Active incident deduplication and trigger_count tracking
- Alert resolution lifecycle (RESOLVED alert allows fresh incident)
- Failure isolation: ML persistence exception triggers rollback without affecting committed deterministic alert
- Database isolation: verifies operations remain strictly in-memory
"""
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
import pytest

from backend.app.core.config import settings
from backend.app.models.security_log import SecurityLog
from backend.app.models.alert import Alert
from backend.app.detection.engine import DetectionEngine
from backend.app.detection.rules import MLAnomalyRule


def test_conditional_registration(monkeypatch):
    """
    Confirms DetectionEngine registers 5 rules when ENABLE_ML_DETECTION=False,
    and 6 rules when ENABLE_ML_DETECTION=True.
    """
    # 1. Disabled
    monkeypatch.setattr(settings, "ENABLE_ML_DETECTION", False)
    engine_disabled = DetectionEngine()
    assert len(engine_disabled.rules) == 5
    assert [r.id for r in engine_disabled.rules] == [
        "RULE-AUTH-BRUTEFORCE",
        "RULE-NET-PORTSCAN",
        "RULE-AUTH-ROOT-LOGIN",
        "RULE-NET-DDOS-AGGREGATE",
        "RULE-ANOMALOUS-SPIKE"
    ]

    # 2. Enabled
    monkeypatch.setattr(settings, "ENABLE_ML_DETECTION", True)
    engine_enabled = DetectionEngine()
    assert len(engine_enabled.rules) == 6
    assert engine_enabled.rules[5].id == "RULE-ML-ANOMALY-IFOREST"


def test_deterministic_rule_detection_independent_of_ml(db_session, monkeypatch):
    """
    Confirms deterministic rules generate alerts normally when ML detection is dormant.
    """
    monkeypatch.setattr(settings, "ENABLE_ML_DETECTION", True)
    engine = DetectionEngine()

    # Ensure ML rule is dormant (no model)
    ml_rule = [r for r in engine.rules if r.id == "RULE-ML-ANOMALY-IFOREST"][0]
    ml_rule.model = None

    attacker = "192.168.1.50"
    now = datetime.now(timezone.utc)

    generated = []
    for i in range(5):
        log = SecurityLog(
            timestamp=now - timedelta(seconds=10 - i),
            source_ip=attacker,
            destination_ip="10.0.0.1",
            destination_port=22,
            event_type="AUTHENTICATION_FAILED",
            message=f"Attempt {i + 1}"
        )
        db_session.add(log)
        db_session.commit()
        alerts = engine.evaluate_log(log, db_session)
        generated.extend(alerts)

    # Deterministic BruteForceRule triggered on 5th attempt
    assert len(generated) == 1
    assert generated[0].rule_id == "RULE-AUTH-BRUTEFORCE"
    assert generated[0].severity == "HIGH"

    # Confirm in database
    db_alerts = db_session.query(Alert).all()
    assert len(db_alerts) == 1
    assert db_alerts[0].rule_id == "RULE-AUTH-BRUTEFORCE"


def test_ml_anomaly_detection_independent_of_deterministic_rules(db_session, monkeypatch):
    """
    Confirms MLAnomalyRule generates an alert when traffic does NOT trip any deterministic rule.
    """
    monkeypatch.setattr(settings, "ENABLE_ML_DETECTION", True)
    engine = DetectionEngine()

    # Configure controlled ML model on the ML rule
    ml_rule = [r for r in engine.rules if r.id == "RULE-ML-ANOMALY-IFOREST"][0]
    mock_model = MagicMock()
    mock_model.predict_single.return_value = {
        "is_anomaly": True,
        "raw_score": -0.0650,
        "anomaly_score": 0.8200
    }
    ml_rule.model = mock_model
    ml_rule.min_events = 5

    now = datetime.now(timezone.utc)
    # Generate benign-looking HTTP GET traffic (0 failed auths, 0 port scans, 10 events total)
    # This traffic is well below deterministic spike/DDoS thresholds (which require >= 20 events)
    logs = []
    for i in range(10):
        log = SecurityLog(
            timestamp=now - timedelta(seconds=10 - i),
            source_ip=f"10.0.0.{i % 4 + 1}",
            destination_ip="10.0.0.50",
            destination_port=80,
            event_type="HTTP_REQUEST",
            message=f"GET /index.html {i}"
        )
        db_session.add(log)
        logs.append(log)
    db_session.commit()

    # Evaluate the 10th log
    alerts = engine.evaluate_log(logs[-1], db_session)

    # Exactly 1 alert: ML anomaly only (zero deterministic alerts)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-ML-ANOMALY-IFOREST"
    assert alerts[0].severity == "MEDIUM"
    assert alerts[0].source_ip == "Distributed Sources"


def test_hybrid_dual_alerts_in_single_evaluation(db_session, monkeypatch):
    """
    Verifies that when an attack pattern triggers both deterministic detection
    and ML anomaly detection, both alerts are produced in a single evaluation.
    """
    monkeypatch.setattr(settings, "ENABLE_ML_DETECTION", True)
    engine = DetectionEngine()

    # Controlled model to guarantee deterministic anomaly prediction without false-negative ambiguity
    ml_rule = [r for r in engine.rules if r.id == "RULE-ML-ANOMALY-IFOREST"][0]
    mock_model = MagicMock()
    mock_model.predict_single.return_value = {
        "is_anomaly": True,
        "raw_score": -0.0800,
        "anomaly_score": 0.9100
    }
    ml_rule.model = mock_model
    ml_rule.min_events = 5

    attacker = "198.51.100.99"
    now = datetime.now(timezone.utc)

    # Ingest 4 failed attempts
    for i in range(4):
        log = SecurityLog(
            timestamp=now - timedelta(seconds=10 - i),
            source_ip=attacker,
            destination_ip="10.0.0.1",
            destination_port=22,
            event_type="AUTHENTICATION_FAILED",
            message=f"Failed SSH attempt {i + 1}"
        )
        db_session.add(log)
    db_session.commit()

    # Ingest 5th failed attempt (trips BruteForceRule AND reaches ML min_events=5)
    log_5 = SecurityLog(
        timestamp=now,
        source_ip=attacker,
        destination_ip="10.0.0.1",
        destination_port=22,
        event_type="AUTHENTICATION_FAILED",
        message="Failed SSH attempt 5"
    )
    db_session.add(log_5)
    db_session.commit()

    alerts = engine.evaluate_log(log_5, db_session)

    # Both alerts must be returned in the same evaluation
    assert len(alerts) == 2
    rule_ids = {a.rule_id for a in alerts}
    assert rule_ids == {"RULE-AUTH-BRUTEFORCE", "RULE-ML-ANOMALY-IFOREST"}

    # Severities must be preserved
    severities = {a.rule_id: a.severity for a in alerts}
    assert severities["RULE-AUTH-BRUTEFORCE"] == "HIGH"
    assert severities["RULE-ML-ANOMALY-IFOREST"] == "MEDIUM"

    # Both alerts exist in database
    db_alerts = db_session.query(Alert).all()
    assert len(db_alerts) == 2


def test_active_ml_alert_deduplication_and_trigger_count(db_session, monkeypatch):
    """
    Confirms ongoing ML anomalies update existing active alerts (trigger_count, description)
    without creating duplicate records.
    """
    monkeypatch.setattr(settings, "ENABLE_ML_DETECTION", True)
    engine = DetectionEngine()

    ml_rule = [r for r in engine.rules if r.id == "RULE-ML-ANOMALY-IFOREST"][0]
    mock_model = MagicMock()
    mock_model.predict_single.return_value = {
        "is_anomaly": True,
        "raw_score": -0.05,
        "anomaly_score": 0.75
    }
    ml_rule.model = mock_model
    ml_rule.min_events = 5

    now = datetime.now(timezone.utc)
    attacker = "192.168.1.200"

    # Step 1: Feed 5 events -> 1st ML alert raised
    logs = []
    for i in range(5):
        log = SecurityLog(
            timestamp=now - timedelta(seconds=10 - i),
            source_ip=attacker,
            destination_ip="10.0.0.1",
            destination_port=80,
            event_type="HTTP_REQUEST",
            message=f"Event {i}"
        )
        db_session.add(log)
        logs.append(log)
    db_session.commit()

    alerts_1 = engine.evaluate_log(logs[-1], db_session)
    ml_alert_1 = [a for a in alerts_1 if a.rule_id == "RULE-ML-ANOMALY-IFOREST"][0]
    assert ml_alert_1.status == "NEW"
    assert ml_alert_1.trigger_count == 5
    assert db_session.query(Alert).filter(Alert.rule_id == "RULE-ML-ANOMALY-IFOREST").count() == 1

    # Step 2: Feed 6th event -> Aggregates ongoing incident (does not create 2nd alert)
    log_6 = SecurityLog(
        timestamp=now + timedelta(seconds=1),
        source_ip=attacker,
        destination_ip="10.0.0.1",
        destination_port=80,
        event_type="HTTP_REQUEST",
        message="Event 6"
    )
    db_session.add(log_6)
    db_session.commit()

    alerts_2 = engine.evaluate_log(log_6, db_session)
    ml_alert_2 = [a for a in alerts_2 if a.rule_id == "RULE-ML-ANOMALY-IFOREST"][0]

    # Same alert ID, updated count
    assert ml_alert_2.id == ml_alert_1.id
    assert ml_alert_2.trigger_count == 6
    assert db_session.query(Alert).filter(Alert.rule_id == "RULE-ML-ANOMALY-IFOREST").count() == 1


def test_resolved_alert_lifecycle_behavior(db_session, monkeypatch):
    """
    Confirms that when an active ML alert is marked RESOLVED, a subsequent anomalous
    window opens a fresh NEW incident.
    """
    monkeypatch.setattr(settings, "ENABLE_ML_DETECTION", True)
    engine = DetectionEngine()

    ml_rule = [r for r in engine.rules if r.id == "RULE-ML-ANOMALY-IFOREST"][0]
    mock_model = MagicMock()
    mock_model.predict_single.return_value = {
        "is_anomaly": True,
        "raw_score": -0.05,
        "anomaly_score": 0.75
    }
    ml_rule.model = mock_model
    ml_rule.min_events = 5

    now = datetime.now(timezone.utc)
    attacker = "192.168.1.222"

    # 1. Raise initial incident
    logs_1 = []
    for i in range(5):
        log = SecurityLog(
            timestamp=now - timedelta(seconds=10 - i),
            source_ip=attacker,
            destination_ip="10.0.0.1",
            destination_port=80,
            event_type="HTTP_REQUEST",
            message=f"Burst 1 - event {i}"
        )
        db_session.add(log)
        logs_1.append(log)
    db_session.commit()

    alerts_1 = engine.evaluate_log(logs_1[-1], db_session)
    alert_1 = [a for a in alerts_1 if a.rule_id == "RULE-ML-ANOMALY-IFOREST"][0]
    assert alert_1.status == "NEW"

    # 2. Analyst marks alert_1 as RESOLVED
    alert_1.status = "RESOLVED"
    db_session.commit()

    # 3. New anomaly occurs 1 hour later
    later = now + timedelta(hours=1)
    logs_2 = []
    for i in range(5):
        log = SecurityLog(
            timestamp=later - timedelta(seconds=10 - i),
            source_ip=attacker,
            destination_ip="10.0.0.1",
            destination_port=80,
            event_type="HTTP_REQUEST",
            message=f"Burst 2 - event {i}"
        )
        db_session.add(log)
        logs_2.append(log)
    db_session.commit()

    alerts_2 = engine.evaluate_log(logs_2[-1], db_session)
    alert_2 = [a for a in alerts_2 if a.rule_id == "RULE-ML-ANOMALY-IFOREST"][0]

    # Fresh alert created with distinct ID
    assert alert_2.id != alert_1.id
    assert alert_2.status == "NEW"

    # Exactly 2 alerts in DB: one RESOLVED, one NEW
    all_alerts = db_session.query(Alert).filter(Alert.rule_id == "RULE-ML-ANOMALY-IFOREST").all()
    assert len(all_alerts) == 2
    statuses = {a.status for a in all_alerts}
    assert statuses == {"RESOLVED", "NEW"}


def test_failure_isolation_rollback_preserves_deterministic_alert(db_session, monkeypatch):
    """
    Simulates a database failure during ML alert persistence and confirms that:
    1. The per-rule exception handler executes db.rollback().
    2. The previously committed deterministic alert remains persisted and safe.
    3. The application does not crash.
    """
    monkeypatch.setattr(settings, "ENABLE_ML_DETECTION", True)
    engine = DetectionEngine()

    ml_rule = [r for r in engine.rules if r.id == "RULE-ML-ANOMALY-IFOREST"][0]
    mock_model = MagicMock()
    mock_model.predict_single.return_value = {
        "is_anomaly": True,
        "raw_score": -0.05,
        "anomaly_score": 0.75
    }
    ml_rule.model = mock_model
    ml_rule.min_events = 5

    # Monkeypatch _record_or_update_alert so it succeeds for deterministic rules
    # but fails with a simulated exception when persisting the ML rule alert
    orig_record = engine._record_or_update_alert

    def faulty_record(payload, db):
        if payload.get("rule_id") == "RULE-ML-ANOMALY-IFOREST":
            raise RuntimeError("Simulated database failure during ML alert recording")
        return orig_record(payload, db)

    monkeypatch.setattr(engine, "_record_or_update_alert", faulty_record)

    attacker = "192.168.1.88"
    now = datetime.now(timezone.utc)

    # Ingest 5 failed authentications (trips BruteForceRule)
    logs = []
    for i in range(5):
        log = SecurityLog(
            timestamp=now - timedelta(seconds=10 - i),
            source_ip=attacker,
            destination_ip="10.0.0.1",
            destination_port=22,
            event_type="AUTHENTICATION_FAILED",
            message=f"Attempt {i}"
        )
        db_session.add(log)
        logs.append(log)
    db_session.commit()

    # Evaluate the 5th log
    alerts = engine.evaluate_log(logs[-1], db_session)

    # Deterministic alert is returned; ML alert raised an exception and was caught
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-AUTH-BRUTEFORCE"
    assert alerts[0].severity == "HIGH"

    # Confirmed in database: deterministic alert is safely persisted despite ML rollback
    db_alerts = db_session.query(Alert).all()
    assert len(db_alerts) == 1
    assert db_alerts[0].rule_id == "RULE-AUTH-BRUTEFORCE"


def test_database_isolation_from_real_sentinel_db(db_session):
    """
    Verifies that the test database session uses SQLite in-memory and does not
    touch or modify the real sentinel.db file on disk.
    """
    bind_url = str(db_session.get_bind().url)
    assert "sqlite" in bind_url
    assert "memory" in bind_url or bind_url == "sqlite://"

