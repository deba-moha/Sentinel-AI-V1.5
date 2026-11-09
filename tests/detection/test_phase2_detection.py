"""
Sentinel AI - Phase 2 Comprehensive Detection & Business Services Test Suite
Validates detection engine rules, threshold limits, time-window expirations,
multi-source/destination isolation, de-duplication, and invalid data handling.
"""
from datetime import datetime, timedelta, timezone
import pytest
from backend.app.core.config import settings
from backend.app.models.security_log import SecurityLog
from backend.app.models.alert import Alert
from backend.app.detection.rules import (
    BruteForceRule,
    PortScanRule,
    RootLoginRule,
    DDoSAggregateRule,
    AnomalousSpikeRule
)
from backend.app.detection.engine import DetectionEngine


# ============================================================================
# 1. BRUTE FORCE RULE TESTS (RULE-AUTH-BRUTEFORCE)
# ============================================================================

def test_brute_force_below_and_above_threshold(db_session):
    rule = BruteForceRule()
    ip = "198.51.100.10"
    now = datetime.now(timezone.utc)

    # 4 attempts (threshold is 5) -> NO alert
    for i in range(settings.BRUTE_FORCE_THRESHOLD - 1):
        log = SecurityLog(
            timestamp=now + timedelta(seconds=i),
            source_ip=ip,
            destination_ip="10.0.0.1",
            destination_port=22,
            event_type="AUTHENTICATION_FAILED",
            severity="MEDIUM",
            message=f"Attempt {i+1}"
        )
        db_session.add(log)
        db_session.commit()
        assert rule.evaluate(log, db_session) is None

    # 5th attempt -> MUST trigger alert
    log_trigger = SecurityLog(
        timestamp=now + timedelta(seconds=settings.BRUTE_FORCE_THRESHOLD),
        source_ip=ip,
        destination_ip="10.0.0.1",
        destination_port=22,
        event_type="AUTHENTICATION_FAILED",
        severity="MEDIUM",
        message="5th Attempt"
    )
    db_session.add(log_trigger)
    db_session.commit()

    alert = rule.evaluate(log_trigger, db_session)
    assert alert is not None
    assert alert["rule_id"] == "RULE-AUTH-BRUTEFORCE"
    assert alert["severity"] == "HIGH"
    assert alert["trigger_count"] == settings.BRUTE_FORCE_THRESHOLD


def test_brute_force_time_window_expiry(db_session):
    """
    Events outside the 60s sliding window must not be counted.
    """
    rule = BruteForceRule()
    ip = "198.51.100.20"
    now = datetime.now(timezone.utc)
    expired_time = now - timedelta(seconds=settings.BRUTE_FORCE_WINDOW_SECONDS + 15)

    # Ingest 4 failed attempts in the past (expired)
    for i in range(4):
        log = SecurityLog(
            timestamp=expired_time + timedelta(seconds=i),
            source_ip=ip,
            destination_ip="10.0.0.1",
            destination_port=22,
            event_type="AUTHENTICATION_FAILED",
            severity="MEDIUM",
            message="Expired attempt"
        )
        db_session.add(log)
    db_session.commit()

    # Ingest 1 current attempt
    current_log = SecurityLog(
        timestamp=now,
        source_ip=ip,
        destination_ip="10.0.0.1",
        destination_port=22,
        event_type="AUTHENTICATION_FAILED",
        severity="MEDIUM",
        message="Current attempt"
    )
    db_session.add(current_log)
    db_session.commit()

    # Total within window is only 1 -> NO alert
    assert rule.evaluate(current_log, db_session) is None


# ============================================================================
# 2. PORT SCAN RULE TESTS (RULE-NET-PORTSCAN)
# ============================================================================

def test_port_scan_below_and_above_threshold(db_session):
    rule = PortScanRule()
    ip = "203.0.113.30"
    now = datetime.now(timezone.utc)
    ports = [21, 22, 23, 80, 443]

    # Probes to 4 distinct ports (below threshold 5) -> NO alert
    for idx, p in enumerate(ports[:-1]):
        log = SecurityLog(
            timestamp=now + timedelta(seconds=idx),
            source_ip=ip,
            destination_ip="10.0.0.2",
            destination_port=p,
            event_type="PORT_SCAN_PROBE",
            message=f"Probe port {p}"
        )
        db_session.add(log)
        db_session.commit()
        assert rule.evaluate(log, db_session) is None

    # Probe to 5th distinct port -> Alert triggers
    trigger_log = SecurityLog(
        timestamp=now + timedelta(seconds=len(ports)),
        source_ip=ip,
        destination_ip="10.0.0.2",
        destination_port=ports[-1],
        event_type="PORT_SCAN_PROBE",
        message=f"Probe port {ports[-1]}"
    )
    db_session.add(trigger_log)
    db_session.commit()

    alert = rule.evaluate(trigger_log, db_session)
    assert alert is not None
    assert alert["rule_id"] == "RULE-NET-PORTSCAN"
    assert alert["trigger_count"] == 5


def test_port_scan_time_window_expiry(db_session):
    """
    Port scan probes outside the 30s window must expire.
    """
    rule = PortScanRule()
    ip = "203.0.113.40"
    now = datetime.now(timezone.utc)
    expired_time = now - timedelta(seconds=settings.PORT_SCAN_WINDOW_SECONDS + 20)

    # 4 distinct ports probed in expired window
    for p in [21, 22, 23, 25]:
        log = SecurityLog(
            timestamp=expired_time,
            source_ip=ip,
            destination_ip="10.0.0.2",
            destination_port=p,
            event_type="PORT_SCAN_PROBE",
            message="Old probe"
        )
        db_session.add(log)
    db_session.commit()

    # 1 current probe to port 80
    current_log = SecurityLog(
        timestamp=now,
        source_ip=ip,
        destination_ip="10.0.0.2",
        destination_port=80,
        event_type="PORT_SCAN_PROBE",
        message="New probe"
    )
    db_session.add(current_log)
    db_session.commit()

    # Distinct ports within window is only 1 -> NO alert
    assert rule.evaluate(current_log, db_session) is None


# ============================================================================
# 3. ROOT LOGIN RULE TESTS (RULE-AUTH-ROOT-LOGIN)
# ============================================================================

def test_root_login_failed_vs_successful_vs_local(db_session):
    rule = RootLoginRule()

    # Case 1: Failed root login -> NO critical alert
    failed_log = SecurityLog(
        source_ip="185.220.101.5",
        user="root",
        event_type="AUTHENTICATION_FAILED",
        message="Failed password attempt for root"
    )
    db_session.add(failed_log)
    db_session.commit()
    assert rule.evaluate(failed_log, db_session) is None

    # Case 2: Localhost root login -> NO critical alert
    local_log = SecurityLog(
        source_ip="127.0.0.1",
        user="root",
        event_type="AUTHENTICATION_SUCCESS",
        message="Local console root login"
    )
    db_session.add(local_log)
    db_session.commit()
    assert rule.evaluate(local_log, db_session) is None

    # Case 3: Successful unauthorized remote root login -> CRITICAL alert
    remote_log = SecurityLog(
        source_ip="185.220.101.5",
        destination_ip="10.0.0.5",
        user="root",
        event_type="AUTHENTICATION_SUCCESS",
        message="Successful remote root login"
    )
    db_session.add(remote_log)
    db_session.commit()

    alert = rule.evaluate(remote_log, db_session)
    assert alert is not None
    assert alert["rule_id"] == "RULE-AUTH-ROOT-LOGIN"
    assert alert["severity"] == "CRITICAL"


# ============================================================================
# 4. DDOS AGGREGATE RULE TESTS (RULE-NET-DDOS-AGGREGATE)
# ============================================================================

def test_ddos_aggregate_conditions_and_thresholds(db_session):
    rule = DDoSAggregateRule()
    target_server = "10.0.0.50"
    now = datetime.now(timezone.utc)
    sources = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]

    # 19 events (threshold is 20) -> NO alert
    for i in range(settings.DDOS_MIN_EVENTS - 1):
        src = sources[i % len(sources)]
        log = SecurityLog(
            timestamp=now + timedelta(seconds=i % 10),
            source_ip=src,
            destination_ip=target_server,
            event_type="HTTP_REQUEST",
            message="Probe"
        )
        db_session.add(log)
    db_session.commit()

    # 20th event targeting target_server
    trigger_log = SecurityLog(
        timestamp=now + timedelta(seconds=15),
        source_ip=sources[0],
        destination_ip=target_server,
        event_type="HTTP_REQUEST",
        message="20th Probe"
    )
    db_session.add(trigger_log)
    db_session.commit()

    alert = rule.evaluate(trigger_log, db_session)
    assert alert is not None
    assert alert["rule_id"] == "RULE-NET-DDOS-AGGREGATE"
    assert alert["severity"] == "CRITICAL"
    assert alert["destination_ip"] == target_server


def test_ddos_aggregate_requires_minimum_distinct_sources(db_session):
    """
    Even with 25 events, if they only originate from 2 distinct sources (minimum is 3),
    RULE-NET-DDOS-AGGREGATE must NOT trigger.
    """
    rule = DDoSAggregateRule()
    target_server = "10.0.0.60"
    now = datetime.now(timezone.utc)
    only_two_sources = ["198.51.100.1", "198.51.100.2"]

    last_log = None
    for i in range(25):
        src = only_two_sources[i % 2]
        log = SecurityLog(
            timestamp=now + timedelta(seconds=i % 10),
            source_ip=src,
            destination_ip=target_server,
            event_type="HTTP_REQUEST",
            message="Request"
        )
        db_session.add(log)
        last_log = log
    db_session.commit()

    # Only 2 sources -> NO DDoS alert
    assert rule.evaluate(last_log, db_session) is None


# ============================================================================
# 5. ANOMALOUS SPIKE RULE TESTS (RULE-ANOMALOUS-SPIKE)
# ============================================================================

def test_anomalous_spike_below_and_above_threshold(db_session):
    rule = AnomalousSpikeRule()
    ip = "198.51.100.70"
    now = datetime.now(timezone.utc)

    # 19 events (threshold 20) -> NO alert
    for i in range(settings.ANOMALOUS_SPIKE_THRESHOLD - 1):
        log = SecurityLog(
            timestamp=now + timedelta(seconds=i % 20),
            source_ip=ip,
            event_type="HTTP_REQUEST",
            message="Spike probe"
        )
        db_session.add(log)
    db_session.commit()

    # 20th event -> alert triggers
    trigger_log = SecurityLog(
        timestamp=now + timedelta(seconds=21),
        source_ip=ip,
        event_type="HTTP_REQUEST",
        message="20th request"
    )
    db_session.add(trigger_log)
    db_session.commit()

    alert = rule.evaluate(trigger_log, db_session)
    assert alert is not None
    assert alert["rule_id"] == "RULE-ANOMALOUS-SPIKE"
    assert alert["trigger_count"] == settings.ANOMALOUS_SPIKE_THRESHOLD


# ============================================================================
# 6. MULTI-SOURCE & MULTI-DESTINATION ISOLATION
# ============================================================================

def test_multi_source_ips_are_not_erroneously_merged(db_session):
    """
    Ensure 3 failed logins on IP A and 3 failed logins on IP B do NOT trigger
    brute-force (neither IP reached threshold of 5).
    """
    rule = BruteForceRule()
    now = datetime.now(timezone.utc)

    for i in range(3):
        db_session.add(SecurityLog(
            timestamp=now,
            source_ip="192.168.1.10",
            event_type="AUTHENTICATION_FAILED",
            message="IP A attempt"
        ))
        db_session.add(SecurityLog(
            timestamp=now,
            source_ip="192.168.1.20",
            event_type="AUTHENTICATION_FAILED",
            message="IP B attempt"
        ))
    db_session.commit()

    last_log_a = db_session.query(SecurityLog).filter(SecurityLog.source_ip == "192.168.1.10").first()
    assert rule.evaluate(last_log_a, db_session) is None


def test_multi_destination_ddos_are_not_erroneously_merged(db_session):
    """
    Ensure traffic targeting Server X is not combined with traffic targeting Server Y.
    """
    rule = DDoSAggregateRule()
    now = datetime.now(timezone.utc)
    sources = ["1.1.1.1", "1.1.1.2", "1.1.1.3"]

    # 12 events to Server X, 12 events to Server Y (total 24, but neither reached 20)
    for i in range(12):
        src = sources[i % 3]
        db_session.add(SecurityLog(
            timestamp=now,
            source_ip=src,
            destination_ip="10.0.0.100",
            event_type="HTTP_REQUEST",
            message="Server X"
        ))
        db_session.add(SecurityLog(
            timestamp=now,
            source_ip=src,
            destination_ip="10.0.0.200",
            event_type="HTTP_REQUEST",
            message="Server Y"
        ))
    db_session.commit()

    test_log_x = db_session.query(SecurityLog).filter(SecurityLog.destination_ip == "10.0.0.100").first()
    assert rule.evaluate(test_log_x, db_session) is None


# ============================================================================
# 7. DE-DUPLICATION & LIFECYCLE PRESERVATION
# ============================================================================

def test_ongoing_incident_deduplication_and_trigger_count(db_session):
    """
    When an attack continues, the active Alert must be updated rather than duplicated.
    """
    engine = DetectionEngine()
    attacker = "198.51.100.99"
    now = datetime.now(timezone.utc)

    # 5 failed attempts -> 1st alert generated
    for i in range(5):
        log = SecurityLog(
            timestamp=now + timedelta(seconds=i),
            source_ip=attacker,
            event_type="AUTHENTICATION_FAILED",
            message=f"Attempt {i+1}"
        )
        db_session.add(log)
        db_session.commit()
        engine.evaluate_log(log, db_session)

    alerts = db_session.query(Alert).filter(Alert.source_ip == attacker).all()
    assert len(alerts) == 1
    assert alerts[0].trigger_count == 5
    assert alerts[0].status == "NEW"

    # Attacker continues with 3 more attempts
    for i in range(5, 8):
        log = SecurityLog(
            timestamp=now + timedelta(seconds=i),
            source_ip=attacker,
            event_type="AUTHENTICATION_FAILED",
            message=f"Attempt {i+1}"
        )
        db_session.add(log)
        db_session.commit()
        engine.evaluate_log(log, db_session)

    # Still exactly ONE alert, trigger count updated to 8
    alerts_after = db_session.query(Alert).filter(Alert.source_ip == attacker).all()
    assert len(alerts_after) == 1
    assert alerts_after[0].trigger_count == 8


def test_resolved_alert_allows_new_incident_on_fresh_attack(db_session):
    """
    If an existing alert is RESOLVED, a subsequent attack pattern opens a fresh alert.
    """
    engine = DetectionEngine()
    attacker = "198.51.100.111"
    now = datetime.now(timezone.utc)

    # Generate initial alert
    for i in range(5):
        log = SecurityLog(
            timestamp=now + timedelta(seconds=i),
            source_ip=attacker,
            event_type="AUTHENTICATION_FAILED",
            message=f"Attack 1: {i}"
        )
        db_session.add(log)
        db_session.commit()
        engine.evaluate_log(log, db_session)

    alert_1 = db_session.query(Alert).filter(Alert.source_ip == attacker).first()
    assert alert_1 is not None

    # Mark alert as RESOLVED
    alert_1.status = "RESOLVED"
    db_session.commit()

    # Attacker attacks again 2 hours later
    fresh_time = now + timedelta(hours=2)
    for i in range(5):
        log = SecurityLog(
            timestamp=fresh_time + timedelta(seconds=i),
            source_ip=attacker,
            event_type="AUTHENTICATION_FAILED",
            message=f"Attack 2: {i}"
        )
        db_session.add(log)
        db_session.commit()
        engine.evaluate_log(log, db_session)

    # There should now be TWO alerts: one RESOLVED and one NEW
    all_alerts = db_session.query(Alert).filter(Alert.source_ip == attacker).all()
    assert len(all_alerts) == 2
    statuses = [a.status for a in all_alerts]
    assert "RESOLVED" in statuses
    assert "NEW" in statuses


# ============================================================================
# 8. BENIGN DATASET & SAFE INVALID DATA HANDLING
# ============================================================================

def test_benign_traffic_generates_zero_alerts(db_session):
    engine = DetectionEngine()
    now = datetime.now(timezone.utc)

    benign_events = [
        {"ip": "10.0.0.10", "type": "HTTP_REQUEST", "port": 443, "msg": "GET /api/v1/user 200"},
        {"ip": "10.0.0.11", "type": "DNS_QUERY", "port": 53, "msg": "Query internal.db"},
        {"ip": "10.0.0.12", "type": "AUTHENTICATION_SUCCESS", "port": 443, "msg": "User alice login ok"},
        {"ip": "10.0.0.13", "type": "AUTHENTICATION_FAILED", "port": 22, "msg": "Single mistype for bob"}
    ]

    for b in benign_events:
        log = SecurityLog(
            timestamp=now,
            source_ip=b["ip"],
            event_type=b["type"],
            destination_port=b["port"],
            message=b["msg"]
        )
        db_session.add(log)
        db_session.commit()
        alerts = engine.evaluate_log(log, db_session)
        assert len(alerts) == 0


def test_safe_handling_of_incomplete_and_invalid_event_data(db_session):
    """
    Incomplete/corrupt event fields (missing IP, missing port, None event_type, None timestamp)
    must fail gracefully without unhandled exceptions.
    """
    engine = DetectionEngine()

    invalid_logs = [
        SecurityLog(source_ip=None, event_type=None, message="Empty log"),
        SecurityLog(source_ip="1.2.3.4", event_type=None, destination_port=None, message="No event type"),
        SecurityLog(source_ip="", event_type="PORT_SCAN_PROBE", destination_port=22, message="Empty IP"),
        SecurityLog(source_ip="1.2.3.4", destination_ip=None, event_type="HTTP_REQUEST", message="No dest IP"),
        SecurityLog(source_ip="1.2.3.4", user=None, event_type="AUTHENTICATION_SUCCESS", message="No user"),
        None
    ]

    for log in invalid_logs:
        # Must evaluate safely and return empty list (no crash)
        alerts = engine.evaluate_log(log, db_session)
        assert isinstance(alerts, list)
        assert len(alerts) == 0
