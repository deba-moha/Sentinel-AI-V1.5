"""
Sentinel AI - Unit Tests for ML Feature Extraction (Phase 1)
Tests extraction from synthetic logs, handling of empty inputs, normal logs,
failed authentication, multiple IPs/ports, and missing optional values.
"""
from datetime import datetime, timedelta, timezone
import pytest
from backend.app.ml.config import ML_FEATURE_NAMES
from backend.app.ml.features import (
    extract_features_from_logs,
    extract_features_by_source_ip,
    extract_features_batch,
    _parse_timestamp,
    _extract_volume
)
from backend.app.schemas.log import LogCreate
from backend.app.models.security_log import SecurityLog
from backend.app.simulator.generator import LogGenerator


def test_empty_input_feature_extraction():
    """Verify that empty or None inputs return safe zeroed numerical features."""
    for empty_input in ([], None, ()):
        features = extract_features_from_logs(empty_input)
        assert isinstance(features, dict)
        assert len(features) == len(ML_FEATURE_NAMES)
        for name in ML_FEATURE_NAMES:
            assert name in features
            assert features[name] == 0.0
            assert isinstance(features[name], float)

    # Empty batch and grouped extraction
    assert extract_features_by_source_ip([]) == {}
    assert extract_features_by_source_ip(None) == {}
    assert extract_features_batch([]) == []
    assert extract_features_batch(None) == []


def test_normal_security_logs_feature_extraction():
    """Verify feature extraction against normal, benign synthetic traffic."""
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    synthetic_normal = [
        LogCreate(
            timestamp=base_time + timedelta(seconds=i * 2),
            source_ip=f"192.168.1.{10 + i}",
            destination_ip="10.0.0.1",
            source_port=50000 + i,
            destination_port=443,
            protocol="TCP",
            event_type="HTTP_REQUEST" if i % 2 == 0 else "AUTHENTICATION_SUCCESS",
            severity="INFO",
            user="alice",
            message=f"Normal telemetry event {i}",
            raw_data={"status": 200, "bytes": 1024}
        )
        for i in range(5)
    ]

    features = extract_features_from_logs(synthetic_normal)

    assert features["total_events"] == 5.0
    assert features["failed_auth_count"] == 0.0
    # i=1 and i=3 are AUTHENTICATION_SUCCESS
    assert features["successful_auth_count"] == 2.0
    assert features["unique_source_ips"] == 5.0
    assert features["unique_dest_ips"] == 1.0
    assert features["unique_dest_ports"] == 1.0
    # 5 events across 8 seconds: frequency = 5 / 8 = 0.625
    assert pytest.approx(features["event_frequency"], rel=1e-3) == 5.0 / 8.0
    # 4 intervals of 2 seconds each: avg = 2.0
    assert pytest.approx(features["avg_time_interval"], rel=1e-3) == 2.0
    # 5 events * 1024 bytes = 5120.0
    assert features["network_traffic_volume"] == 5120.0


def test_failed_authentication_events():
    """Verify accurate calculation of failed authentication counts."""
    synthetic_failures = LogGenerator.generate_brute_force(count=7, attacker_ip="198.51.100.99")
    features = extract_features_from_logs(synthetic_failures)

    assert features["total_events"] == 7.0
    assert features["failed_auth_count"] == 7.0
    assert features["successful_auth_count"] == 0.0
    assert features["unique_source_ips"] == 1.0
    assert features["unique_dest_ips"] == 1.0
    assert features["unique_dest_ports"] == 1.0


def test_multiple_source_ips_and_destination_ports():
    """Verify distinct IP and port aggregation for multi-source port scan / DDoS patterns."""
    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    distinct_ports = [21, 22, 80, 443, 8080]
    distinct_sources = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]

    logs = []
    for i, port in enumerate(distinct_ports):
        src_ip = distinct_sources[i % len(distinct_sources)]
        logs.append({
            "timestamp": base_time + timedelta(seconds=i),
            "source_ip": src_ip,
            "destination_ip": "192.168.1.50",
            "destination_port": port,
            "event_type": "PORT_SCAN_PROBE",
            "severity": "LOW",
            "message": f"Probe to port {port}"
        })

    features = extract_features_from_logs(logs)

    assert features["total_events"] == 5.0
    assert features["unique_source_ips"] == 4.0
    assert features["unique_dest_ports"] == 5.0
    assert features["unique_dest_ips"] == 1.0


def test_missing_optional_values_handling():
    """Verify that logs with missing optional fields (None) are handled gracefully."""
    logs_with_nones = [
        LogCreate(
            timestamp=None,
            source_ip="192.168.1.10",
            destination_ip=None,
            source_port=None,
            destination_port=None,
            protocol="TCP",
            event_type="GENERIC_LOG",
            severity="INFO",
            user=None,
            message="Event with null optional fields",
            raw_data=None
        ),
        {
            "timestamp": None,
            "source_ip": None,
            "destination_ip": None,
            "destination_port": None,
            "event_type": None,
            "raw_data": None
        }
    ]

    features = extract_features_from_logs(logs_with_nones)

    assert features["total_events"] == 2.0
    assert features["failed_auth_count"] == 0.0
    assert features["successful_auth_count"] == 0.0
    assert features["unique_source_ips"] == 1.0  # Only "192.168.1.10" is non-None
    assert features["unique_dest_ips"] == 0.0
    assert features["unique_dest_ports"] == 0.0
    assert features["event_frequency"] == 0.0
    assert features["avg_time_interval"] == 0.0
    assert features["network_traffic_volume"] == 0.0


def test_sqlalchemy_model_compatibility():
    """Verify that extract_features_from_logs works natively with SQLAlchemy SecurityLog objects."""
    now = datetime.now(timezone.utc)
    db_logs = [
        SecurityLog(
            id=1,
            timestamp=now,
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            destination_port=22,
            event_type="AUTHENTICATION_FAILED",
            severity="MEDIUM",
            message="Failed login",
            raw_data='{"bytes": 256}'
        ),
        SecurityLog(
            id=2,
            timestamp=now + timedelta(seconds=5),
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            destination_port=22,
            event_type="LOGIN_SUCCESS",
            severity="INFO",
            message="Success login",
            raw_data='{"bytes": 512}'
        )
    ]

    features = extract_features_from_logs(db_logs)

    assert features["total_events"] == 2.0
    assert features["failed_auth_count"] == 1.0
    assert features["successful_auth_count"] == 1.0
    assert features["unique_source_ips"] == 1.0
    assert features["unique_dest_ips"] == 1.0
    assert features["unique_dest_ports"] == 1.0
    assert features["network_traffic_volume"] == 768.0
    assert pytest.approx(features["avg_time_interval"], rel=1e-3) == 5.0


def test_extract_features_by_source_ip():
    """Verify grouping and feature calculation per source IP."""
    logs = [
        {"source_ip": "1.1.1.1", "event_type": "AUTHENTICATION_FAILED"},
        {"source_ip": "1.1.1.1", "event_type": "AUTHENTICATION_FAILED"},
        {"source_ip": "2.2.2.2", "event_type": "AUTHENTICATION_SUCCESS"}
    ]

    grouped = extract_features_by_source_ip(logs)
    assert "1.1.1.1" in grouped
    assert "2.2.2.2" in grouped
    assert grouped["1.1.1.1"]["failed_auth_count"] == 2.0
    assert grouped["2.2.2.2"]["successful_auth_count"] == 1.0


def test_timestamp_parsing_helper():
    """Verify _parse_timestamp with various datetime formats and edge cases."""
    assert _parse_timestamp(None) is None
    assert _parse_timestamp("") is None
    assert _parse_timestamp("   ") is None
    assert _parse_timestamp("invalid-date-string") is None

    # Datetime instance without tzinfo
    naive_dt = datetime(2026, 5, 1, 10, 0, 0)
    parsed = _parse_timestamp(naive_dt)
    assert parsed.tzinfo == timezone.utc

    # ISO string with Z
    parsed_z = _parse_timestamp("2026-05-01T10:00:00Z")
    assert parsed_z is not None
    assert parsed_z.year == 2026

    # ISO string with offset
    parsed_offset = _parse_timestamp("2026-05-01T10:00:00+00:00")
    assert parsed_offset is not None


def test_extract_volume_helper():
    """Verify network volume extraction from dict and string raw_data."""
    assert _extract_volume(None) == 0.0
    assert _extract_volume({}) == 0.0
    assert _extract_volume({"raw_data": None}) == 0.0
    assert _extract_volume({"raw_data": "{invalid json}"}) == 0.0
    assert _extract_volume({"raw_data": '{"bytes": 1024}'}) == 1024.0
    assert _extract_volume({"raw_data": {"size": 2048}}) == 2048.0
    assert _extract_volume({"bytes": 4096}) == 4096.0

