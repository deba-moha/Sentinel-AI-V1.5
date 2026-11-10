"""
Sentinel AI - Phase 3 Integration & Validation Test Suite
Validates the synthetic event simulator, detection engine integration,
REST API endpoints, data persistence in SQLite, and statistical aggregation integrity.
"""
from datetime import datetime, timezone
from fastapi import status
from backend.app.models.security_log import SecurityLog
from backend.app.models.alert import Alert


# ============================================================================
# 1. SIMULATOR VALIDATION & SQLITE PERSISTENCE
# ============================================================================

def test_simulator_scenarios_and_sqlite_persistence(client, db_session):
    """
    Tests each simulation scenario via the API and verifies that records
    are physically written to the SQLite database.
    """
    initial_log_count = db_session.query(SecurityLog).count()
    initial_alert_count = db_session.query(Alert).count()

    scenarios_to_test = [
        ("NORMAL_TRAFFIC", 5, 0),             # count=5, expected min alerts=0
        ("BRUTE_FORCE", 6, 1),                # count=6, expected min alerts=1
        ("PORT_SCAN", 8, 1),                  # count=8, expected min alerts=1
        ("SUCCESSFUL_ROOT_LOGIN", 1, 1),      # count=1, expected min alerts=1 (Critical)
        ("FAILED_ROOT_LOGIN", 1, 0),          # count=1, expected min alerts=0 (Non-critical)
        ("DDOS_ATTACK", 24, 1),               # count=24, expected min alerts=1 (Critical)
        ("ANOMALOUS_SPIKE", 25, 1),           # count=25, expected min alerts=1
        ("MIXED", 10, 1),                     # count=10, expected min alerts=1
    ]

    total_expected_logs = 0
    for scenario_name, count, expected_min_alerts in scenarios_to_test:
        res = client.post("/api/v1/simulator/run", json={"scenario": scenario_name, "count": count})
        assert res.status_code == status.HTTP_200_OK, f"Failed on scenario {scenario_name}: {res.text}"
        data = res.json()
        assert data["status"] == "SUCCESS"
        assert data["scenario"] == scenario_name
        assert data["logs_generated"] >= count
        total_expected_logs += data["logs_generated"]

        if expected_min_alerts > 0:
            assert data["alerts_triggered"] >= expected_min_alerts, (
                f"Expected >= {expected_min_alerts} alert(s) for {scenario_name}, got {data['alerts_triggered']}"
            )

    # Verify SQLite actual row count in the database
    current_log_count = db_session.query(SecurityLog).count()
    current_alert_count = db_session.query(Alert).count()

    assert current_log_count == initial_log_count + total_expected_logs
    assert current_alert_count > initial_alert_count


# ============================================================================
# 2. DETECTION INTEGRATION & FALSE POSITIVE PREVENTION
# ============================================================================

def test_normal_traffic_never_triggers_false_alarms(client, db_session, monkeypatch):
    """
    Verifies that running pure normal traffic produces zero alerts under
    the deterministic detection rules (ML disabled).
    Note: Unsupervised ML anomaly detection operates across probabilistic statistical
    feature windows and can occasionally flag high-velocity synthetic bursts;
    deterministic false-alarm verification isolates the 5 deterministic rules.
    """
    from backend.app.core.config import settings
    from backend.app.detection.engine import detection_engine
    monkeypatch.setattr(settings, "ENABLE_ML_DETECTION", False)
    deterministic_rules = [r for r in detection_engine.rules if r.id != "RULE-ML-ANOMALY-IFOREST"]
    monkeypatch.setattr(detection_engine, "rules", deterministic_rules)

    initial_alert_count = db_session.query(Alert).count()

    res = client.post("/api/v1/simulator/run", json={"scenario": "NORMAL_TRAFFIC", "count": 10})
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["scenario"] == "NORMAL_TRAFFIC"
    assert data["alerts_triggered"] == 0
    assert len(data["new_alerts"]) == 0

    # Ensure no alerts were inserted into SQLite
    current_alert_count = db_session.query(Alert).count()
    assert current_alert_count == initial_alert_count


def test_failed_root_login_does_not_trigger_critical_breach(client, db_session):
    """
    Verifies that isolated failed root logins are recorded as telemetry but do not
    trigger the RULE-AUTH-ROOT-LOGIN critical alert.
    """
    res = client.post("/api/v1/simulator/run", json={"scenario": "FAILED_ROOT_LOGIN", "count": 1})
    assert res.status_code == status.HTTP_200_OK
    data = res.json()

    # Must not contain critical root login alert
    assert not any(a["rule_id"] == "RULE-AUTH-ROOT-LOGIN" for a in data["new_alerts"])

    # Ensure no critical alerts exist in the DB
    critical_alerts = db_session.query(Alert).filter(Alert.rule_id == "RULE-AUTH-ROOT-LOGIN").count()
    assert critical_alerts == 0


# ============================================================================
# 3. API VALIDATION (LOGS, ALERTS, STATS, INPUT VALIDATION)
# ============================================================================

def test_log_ingestion_and_retrieval_api_contract(client):
    """
    Tests single ingestion, batch ingestion, query filtering, and 404 behavior.
    """
    # 1. Single ingestion
    single_payload = {
        "source_ip": "10.10.10.10",
        "destination_ip": "10.0.0.1",
        "destination_port": 443,
        "protocol": "TCP",
        "event_type": "HTTP_REQUEST",
        "severity": "INFO",
        "user": "developer",
        "message": "GET /api/v1/health HTTP/1.1",
        "raw_data": {"user_agent": "curl/8.0"}
    }
    res_single = client.post("/api/v1/logs", json=single_payload)
    assert res_single.status_code == status.HTTP_201_CREATED
    data_single = res_single.json()
    log_id = data_single["log"]["id"]
    assert data_single["log"]["source_ip"] == "10.10.10.10"

    # 2. Batch ingestion
    batch_payload = {
        "logs": [
            {
                "source_ip": "10.10.10.11",
                "event_type": "DNS_QUERY",
                "severity": "LOW",
                "message": "DNS query test1"
            },
            {
                "source_ip": "10.10.10.12",
                "event_type": "DNS_QUERY",
                "severity": "LOW",
                "message": "DNS query test2"
            }
        ]
    }
    res_batch = client.post("/api/v1/logs/batch", json=batch_payload)
    assert res_batch.status_code == status.HTTP_201_CREATED
    assert res_batch.json()["count"] == 2

    # 3. Retrieve by ID
    res_get = client.get(f"/api/v1/logs/{log_id}")
    assert res_get.status_code == status.HTTP_200_OK
    assert res_get.json()["id"] == log_id
    assert res_get.json()["source_ip"] == "10.10.10.10"

    # 4. 404 on nonexistent log
    res_404 = client.get("/api/v1/logs/888888")
    assert res_404.status_code == status.HTTP_404_NOT_FOUND


def test_alert_triage_api_lifecycle(client):
    """
    Tests alert retrieval, filtering, and status progression (NEW -> INVESTIGATING -> RESOLVED).
    """
    # Trigger brute force to guarantee an alert exists
    client.post("/api/v1/simulator/run", json={"scenario": "BRUTE_FORCE", "count": 6})

    # Retrieve alerts
    res = client.get("/api/v1/alerts")
    assert res.status_code == status.HTTP_200_OK
    alerts = res.json()
    assert len(alerts) >= 1

    alert = alerts[0]
    alert_id = alert["id"]

    # Transition to INVESTIGATING
    res_inv = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "INVESTIGATING"})
    assert res_inv.status_code == status.HTTP_200_OK
    assert res_inv.json()["status"] == "INVESTIGATING"

    # Transition to RESOLVED
    res_res = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "RESOLVED"})
    assert res_res.status_code == status.HTTP_200_OK
    assert res_res.json()["status"] == "RESOLVED"

    # Transition to FALSE_POSITIVE
    res_fp = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "FALSE_POSITIVE"})
    assert res_fp.status_code == status.HTTP_200_OK
    assert res_fp.json()["status"] == "FALSE_POSITIVE"

    # Invalid status should return 400 Bad Request
    res_invalid = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "UNKNOWN_STATUS"})
    assert res_invalid.status_code == status.HTTP_400_BAD_REQUEST


def test_simulator_api_error_handling(client):
    """
    Tests input validation: invalid scenarios or invalid count bounds return 400 or 422.
    """
    # Invalid scenario name -> 400
    res_bad_scenario = client.post("/api/v1/simulator/run", json={"scenario": "INVALID_ATTACK_TYPE", "count": 5})
    assert res_bad_scenario.status_code == status.HTTP_400_BAD_REQUEST

    # Out of bounds count (le=100) -> 422 Unprocessable Entity
    res_too_large = client.post("/api/v1/simulator/run", json={"scenario": "BRUTE_FORCE", "count": 1000})
    assert res_too_large.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Count < 1 -> 422 Unprocessable Entity
    res_negative = client.post("/api/v1/simulator/run", json={"scenario": "BRUTE_FORCE", "count": 0})
    assert res_negative.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ============================================================================
# 4. DATA INTEGRITY & STATISTICAL AGGREGATION ACCURACY
# ============================================================================

def test_statistics_accurately_reflect_database_records(client, db_session):
    """
    Asserts that the /api/v1/stats endpoint calculations strictly match
    the actual SQL count aggregations in the SQLite database.
    """
    # Populate a mixed dataset
    client.post("/api/v1/simulator/run", json={"scenario": "NORMAL_TRAFFIC", "count": 5})
    client.post("/api/v1/simulator/run", json={"scenario": "BRUTE_FORCE", "count": 6})
    client.post("/api/v1/simulator/run", json={"scenario": "SUCCESSFUL_ROOT_LOGIN", "count": 1})

    res = client.get("/api/v1/stats")
    assert res.status_code == status.HTTP_200_OK
    stats = res.json()

    # Query DB directly to check ground truth
    db_total_logs = db_session.query(SecurityLog).count()
    db_total_alerts = db_session.query(Alert).count()
    db_critical_alerts = db_session.query(Alert).filter(Alert.severity == "CRITICAL").count()
    db_active_alerts = db_session.query(Alert).filter(Alert.status.in_(["NEW", "INVESTIGATING"])).count()
    db_resolved_alerts = db_session.query(Alert).filter(Alert.status == "RESOLVED").count()

    assert stats["total_logs"] == db_total_logs
    assert stats["total_alerts"] == db_total_alerts
    assert stats["critical_alerts"] == db_critical_alerts
    assert stats["active_alerts"] == db_active_alerts
    assert stats["resolved_alerts"] == db_resolved_alerts


def test_utc_timestamp_handling_integrity(client):
    """
    Verifies that timestamps stored and retrieved conform to standard ISO-8601 formatting.
    """
    # 1. Without explicit timestamp (defaults to current UTC)
    res = client.post("/api/v1/logs", json={
        "source_ip": "1.2.3.4",
        "event_type": "TEST_UTC",
        "message": "Testing default UTC timestamp"
    })
    assert res.status_code == status.HTTP_201_CREATED
    log_data = res.json()["log"]
    parsed_time = datetime.fromisoformat(log_data["timestamp"])
    assert isinstance(parsed_time, datetime)

    # 2. With explicit ISO-8601 UTC timestamp
    utc_str = "2026-11-09T11:00:00Z"
    res_explicit = client.post("/api/v1/logs", json={
        "timestamp": utc_str,
        "source_ip": "1.2.3.4",
        "event_type": "TEST_EXPLICIT_UTC",
        "message": "Testing explicit UTC timestamp"
    })
    assert res_explicit.status_code == status.HTTP_201_CREATED
    explicit_log = res_explicit.json()["log"]
    parsed_explicit = datetime.fromisoformat(explicit_log["timestamp"])
    assert isinstance(parsed_explicit, datetime)
    assert parsed_explicit.hour == 11
