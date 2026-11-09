"""
Sentinel AI - Detection Rules & Dataset Benchmark Suite
Evaluates detection rules against predefined benign and malicious event datasets.
Note: Avoids claiming guaranteed zero false positives; tests empirical behavior against defined baselines.
"""
from datetime import datetime, timezone
from backend.app.models.security_log import SecurityLog
from backend.app.detection.rules import (
    BruteForceRule,
    PortScanRule,
    RootLoginRule,
    DDoSAggregateRule,
    AnomalousSpikeRule
)
from backend.app.detection.engine import DetectionEngine


# ==========================================
# PREDEFINED DATASETS FOR VALIDATION
# ==========================================

BENIGN_EVENT_DATASET = [
    {
        "source_ip": "192.168.1.15",
        "destination_ip": "10.0.0.5",
        "destination_port": 443,
        "protocol": "TCP",
        "event_type": "HTTP_REQUEST",
        "severity": "INFO",
        "user": "jdoe",
        "message": "GET /api/v1/profile HTTP/1.1 200 OK"
    },
    {
        "source_ip": "192.168.1.28",
        "destination_ip": "10.0.0.5",
        "destination_port": 53,
        "protocol": "UDP",
        "event_type": "DNS_QUERY",
        "severity": "INFO",
        "user": None,
        "message": "Standard internal DNS lookup for db.sentinel.internal"
    },
    {
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.5",
        "destination_port": 22,
        "protocol": "TCP",
        "event_type": "AUTHENTICATION_FAILED",
        "severity": "LOW",
        "user": "bob",
        "message": "Single isolated password mistype for user 'bob'"
    },
    {
        "source_ip": "198.51.100.99",
        "destination_ip": "10.0.0.5",
        "destination_port": 22,
        "protocol": "TCP",
        "event_type": "AUTHENTICATION_FAILED",
        "severity": "LOW",
        "user": "root",
        "message": "Isolated failed password attempt for user 'root'"
    }
]


def test_benign_dataset_does_not_trigger_false_alarms(db_session):
    """
    Feeds normal operational traffic (including an isolated failed root login)
    and verifies that no spurious critical or brute force alerts are raised.
    """
    engine = DetectionEngine()

    for item in BENIGN_EVENT_DATASET:
        log = SecurityLog(
            timestamp=datetime.now(timezone.utc),
            source_ip=item["source_ip"],
            destination_ip=item["destination_ip"],
            destination_port=item["destination_port"],
            protocol=item["protocol"],
            event_type=item["event_type"],
            severity=item["severity"],
            user=item.get("user"),
            message=item["message"]
        )
        db_session.add(log)
        db_session.commit()

        alerts = engine.evaluate_log(log, db_session)
        assert len(alerts) == 0, f"False alarm triggered on benign event: {item['message']}"


def test_root_login_distinguishes_failed_from_successful(db_session):
    """
    Verifies that:
    1. An isolated failed root login attempt does NOT trigger a critical alert.
    2. A successful remote root login MUST trigger a CRITICAL alert.
    """
    rule = RootLoginRule()

    # 1. Failed root login attempt
    failed_root_log = SecurityLog(
        timestamp=datetime.now(timezone.utc),
        source_ip="198.51.100.55",
        destination_ip="10.0.0.5",
        destination_port=22,
        protocol="TCP",
        event_type="AUTHENTICATION_FAILED",
        severity="LOW",
        user="root",
        message="Failed password attempt for root"
    )
    db_session.add(failed_root_log)
    db_session.commit()

    # Must NOT trigger critical root alert
    assert rule.evaluate(failed_root_log, db_session) is None

    # 2. Successful remote root login
    successful_root_log = SecurityLog(
        timestamp=datetime.now(timezone.utc),
        source_ip="198.51.100.55",
        destination_ip="10.0.0.5",
        destination_port=22,
        protocol="TCP",
        event_type="AUTHENTICATION_SUCCESS",
        severity="CRITICAL",
        user="root",
        message="Successful remote root login"
    )
    db_session.add(successful_root_log)
    db_session.commit()

    critical_alert = rule.evaluate(successful_root_log, db_session)
    assert critical_alert is not None
    assert critical_alert["rule_id"] == "RULE-AUTH-ROOT-LOGIN"
    assert critical_alert["severity"] == "CRITICAL"


def test_brute_force_dataset_detection(db_session):
    """
    Verifies that a malicious sequence of 5 failed logins triggers high severity alert.
    """
    rule = BruteForceRule(threshold=5, window_seconds=60)
    attacker_ip = "198.51.100.77"

    for i in range(5):
        log = SecurityLog(
            timestamp=datetime.now(timezone.utc),
            source_ip=attacker_ip,
            destination_ip="10.0.0.5",
            destination_port=22,
            protocol="TCP",
            event_type="AUTHENTICATION_FAILED",
            severity="MEDIUM",
            user="alice",
            message=f"Brute force attempt {i + 1}"
        )
        db_session.add(log)
        db_session.commit()
        alert = rule.evaluate(log, db_session)
        if i < 4:
            assert alert is None
        else:
            assert alert is not None
            assert alert["rule_id"] == "RULE-AUTH-BRUTEFORCE"
            assert alert["severity"] == "HIGH"


def test_port_scan_dataset_detection(db_session):
    """
    Verifies that scanning distinct destination ports triggers port scan alert.
    """
    rule = PortScanRule(threshold=5, window_seconds=30)
    scanner_ip = "203.0.113.55"
    scanned_ports = [21, 22, 23, 80, 443]

    for idx, port in enumerate(scanned_ports):
        log = SecurityLog(
            timestamp=datetime.now(timezone.utc),
            source_ip=scanner_ip,
            destination_ip="10.0.0.5",
            destination_port=port,
            protocol="TCP",
            event_type="PORT_SCAN_PROBE",
            severity="LOW",
            message=f"Port probe {port}"
        )
        db_session.add(log)
        db_session.commit()
        alert = rule.evaluate(log, db_session)
        if idx < 4:
            assert alert is None
        else:
            assert alert is not None
            assert alert["rule_id"] == "RULE-NET-PORTSCAN"


def test_ddos_aggregate_detection_across_multiple_source_ips(db_session):
    """
    Verifies that multi-source aggregate traffic spikes targeting the same destination
    triggers the RULE-NET-DDOS-AGGREGATE critical alert.
    """
    rule = DDoSAggregateRule(min_events=20, min_distinct_sources=3, window_seconds=30)
    target_destination = "10.0.0.5"
    sources = ["198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"]

    # Ingest 20 events distributed across the 4 sources
    last_log = None
    for i in range(20):
        src = sources[i % len(sources)]
        log = SecurityLog(
            timestamp=datetime.now(timezone.utc),
            source_ip=src,
            destination_ip=target_destination,
            destination_port=80,
            protocol="TCP",
            event_type="HTTP_REQUEST",
            severity="LOW",
            message=f"DDoS probe request {i + 1}"
        )
        db_session.add(log)
        db_session.commit()
        last_log = log

    alert = rule.evaluate(last_log, db_session)
    assert alert is not None
    assert alert["rule_id"] == "RULE-NET-DDOS-AGGREGATE"
    assert alert["severity"] == "CRITICAL"
    assert "20 requests" in alert["description"]
