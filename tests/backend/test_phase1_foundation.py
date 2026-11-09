"""
Sentinel AI - Phase 1 Foundation Verification Test
Verifies environment settings, SQLite database connection, SQLAlchemy models, and Pydantic schemas.
"""
from datetime import datetime, timezone
from backend.app.core.config import settings
from backend.app.database.session import Base, SessionLocal, engine
from backend.app.models.security_log import SecurityLog
from backend.app.models.alert import Alert
from backend.app.models.rule import DetectionRuleModel
from backend.app.schemas.log import LogCreate, LogResponse
from backend.app.schemas.alert import AlertResponse, AlertUpdate


def test_phase1_environment_configuration():
    """Verify that configuration settings and central detection thresholds are loaded."""
    assert settings.PROJECT_NAME == "Sentinel AI"
    assert settings.VERSION == "1.0.0"
    assert settings.DATABASE_URL.startswith("sqlite")
    # Verify centralized detection threshold configurations
    assert settings.BRUTE_FORCE_THRESHOLD >= 1
    assert settings.PORT_SCAN_THRESHOLD >= 1
    assert settings.DDOS_MIN_EVENTS >= 1
    assert settings.DDOS_MIN_SOURCES >= 1


def test_phase1_sqlite_database_and_models(db_session):
    """Verify that SQLite connection succeeds and all Phase 1 SQLAlchemy tables exist and accept records."""
    # 1. Insert and query SecurityLog
    log_entry = SecurityLog(
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        destination_port=22,
        protocol="TCP",
        event_type="AUTHENTICATION_FAILED",
        severity="MEDIUM",
        user="root",
        message="Test failed root login",
        raw_data='{"attempt": 1}'
    )
    db_session.add(log_entry)
    db_session.commit()
    db_session.refresh(log_entry)

    assert log_entry.id is not None
    assert log_entry.source_ip == "192.168.1.100"

    # 2. Insert and query Alert
    alert_entry = Alert(
        rule_id="RULE-AUTH-BRUTEFORCE",
        title="Test Brute Force Alert",
        description="Multiple failed attempts",
        severity="HIGH",
        status="NEW",
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        target_user="root",
        trigger_count=1
    )
    db_session.add(alert_entry)
    db_session.commit()
    db_session.refresh(alert_entry)

    assert alert_entry.id is not None
    assert alert_entry.status == "NEW"
    assert alert_entry.destination_ip == "10.0.0.1"

    # 3. Insert and query DetectionRuleModel
    rule_entry = DetectionRuleModel(
        id="RULE-NET-DDOS-AGGREGATE",
        name="DDoS Detection",
        description="Detects multi-source traffic spikes",
        severity="CRITICAL",
        enabled=True,
        threshold=settings.DDOS_MIN_EVENTS,
        window_seconds=settings.DDOS_WINDOW_SECONDS
    )
    db_session.add(rule_entry)
    db_session.commit()
    db_session.refresh(rule_entry)

    assert rule_entry.id == "RULE-NET-DDOS-AGGREGATE"


def test_phase1_pydantic_schemas():
    """Verify Pydantic schema validation, serialization, and typing."""
    log_in = LogCreate(
        source_ip="10.0.0.50",
        event_type="HTTP_REQUEST",
        message="GET /index.html"
    )
    assert log_in.source_ip == "10.0.0.50"
    assert log_in.protocol == "TCP"

    # Schema serialization with dummy database-like attributes
    dummy_alert = Alert(
        id=1,
        rule_id="RULE-TEST",
        title="Test Title",
        description="Test Desc",
        severity="LOW",
        status="NEW",
        source_ip="1.1.1.1",
        destination_ip="10.0.0.1",
        target_user=None,
        trigger_count=1,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    alert_resp = AlertResponse.model_validate(dummy_alert)
    assert alert_resp.id == 1
    assert alert_resp.destination_ip == "10.0.0.1"

    update_dto = AlertUpdate(status="INVESTIGATING")
    assert update_dto.status == "INVESTIGATING"

