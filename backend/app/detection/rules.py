"""
Sentinel AI - Foundational Threat Detection Rules (V1.0)
Deterministic, rule-based threat detection logic.
Thresholds are dynamically read from centralized configuration settings.
"""
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.app.core.config import settings
from backend.app.models.security_log import SecurityLog


def normalize_utc_timestamp(ts: Optional[datetime]) -> datetime:
    """Safely extracts a valid UTC datetime, defaulting to current UTC if absent."""
    if ts is None:
        return datetime.now(timezone.utc)
    return ts


class BaseRule(ABC):
    id: str
    name: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL

    @abstractmethod
    def evaluate(self, log: SecurityLog, db: Session) -> Optional[Dict[str, Any]]:
        """
        Evaluates a newly ingested log record against the database.
        Returns alert payload dictionary if triggered, or None if benign/unmatched.
        """
        pass


class BruteForceRule(BaseRule):
    """
    Detects repeated failed authentication attempts from the same source IP.
    Default threshold: 5 failed attempts within 60 seconds (configurable).
    """
    def __init__(
        self,
        threshold: Optional[int] = None,
        window_seconds: Optional[int] = None
    ):
        self.id = "RULE-AUTH-BRUTEFORCE"
        self.name = "Authentication Brute Force Detected"
        self.severity = "HIGH"
        self.threshold = threshold if threshold is not None else settings.BRUTE_FORCE_THRESHOLD
        self.window_seconds = window_seconds if window_seconds is not None else settings.BRUTE_FORCE_WINDOW_SECONDS
        self.description = (
            f"Observed {self.threshold}+ failed login attempts from a single IP "
            f"within {self.window_seconds}s."
        )

    def evaluate(self, log: SecurityLog, db: Session) -> Optional[Dict[str, Any]]:
        # Safe field validation
        if not log or not log.source_ip or not log.event_type:
            return None

        event_norm = str(log.event_type).upper()
        if event_norm not in ("AUTHENTICATION_FAILED", "AUTH_FAILURE", "LOGIN_FAILED"):
            return None

        ref_time = normalize_utc_timestamp(log.timestamp)
        window_start = ref_time - timedelta(seconds=self.window_seconds)

        failed_count = db.query(func.count(SecurityLog.id)).filter(
            SecurityLog.source_ip == log.source_ip,
            SecurityLog.event_type.in_(["AUTHENTICATION_FAILED", "AUTH_FAILURE", "LOGIN_FAILED"]),
            SecurityLog.timestamp >= window_start,
            SecurityLog.timestamp <= ref_time
        ).scalar() or 0

        if failed_count >= self.threshold:
            return {
                "rule_id": self.id,
                "title": self.name,
                "description": f"Potential brute force attack: {failed_count} failed login attempts from IP {log.source_ip}.",
                "severity": self.severity,
                "source_ip": log.source_ip,
                "destination_ip": log.destination_ip,
                "target_user": log.user or "unknown",
                "trigger_count": failed_count
            }
        return None


class PortScanRule(BaseRule):
    """
    Detects port scanning reconnaissance targeting multiple distinct destination ports.
    Default threshold: 5 distinct ports within 30 seconds (configurable).
    """
    def __init__(
        self,
        threshold: Optional[int] = None,
        window_seconds: Optional[int] = None
    ):
        self.id = "RULE-NET-PORTSCAN"
        self.name = "Port Scan Reconnaissance Detected"
        self.severity = "MEDIUM"
        self.threshold = threshold if threshold is not None else settings.PORT_SCAN_THRESHOLD
        self.window_seconds = window_seconds if window_seconds is not None else settings.PORT_SCAN_WINDOW_SECONDS
        self.description = (
            f"Single host probed {self.threshold}+ distinct destination ports "
            f"within {self.window_seconds}s."
        )

    def evaluate(self, log: SecurityLog, db: Session) -> Optional[Dict[str, Any]]:
        # Safe field validation
        if not log or not log.source_ip or log.destination_port is None or not log.event_type:
            return None

        event_norm = str(log.event_type).upper()
        relevant_events = ("PORT_SCAN_PROBE", "CONNECTION_REFUSED", "PACKET_DROP", "TCP_SYN", "FIREWALL_BLOCKED")
        if event_norm not in relevant_events:
            return None

        ref_time = normalize_utc_timestamp(log.timestamp)
        window_start = ref_time - timedelta(seconds=self.window_seconds)

        distinct_ports = db.query(func.count(func.distinct(SecurityLog.destination_port))).filter(
            SecurityLog.source_ip == log.source_ip,
            SecurityLog.timestamp >= window_start,
            SecurityLog.timestamp <= ref_time,
            SecurityLog.destination_port.isnot(None)
        ).scalar() or 0

        if distinct_ports >= self.threshold:
            return {
                "rule_id": self.id,
                "title": self.name,
                "description": f"Port scan detected: {distinct_ports} distinct destination ports targeted by {log.source_ip}.",
                "severity": self.severity,
                "source_ip": log.source_ip,
                "destination_ip": log.destination_ip,
                "target_user": None,
                "trigger_count": distinct_ports
            }
        return None


class RootLoginRule(BaseRule):
    """
    Detects unauthorized or remote root / administrative logins.
    Distinguishes between failed root login attempts and successful unauthorized root logins.
    Only successful unauthorized remote root logins trigger this CRITICAL alert.
    Isolated failed attempts are captured as normal telemetry and not marked critical.
    """
    def __init__(self):
        self.id = "RULE-AUTH-ROOT-LOGIN"
        self.name = "Unauthorized Remote Root Login Succeeded"
        self.description = "Critical incident: Remote root or administrator access was successfully authenticated."
        self.severity = "CRITICAL"

    def evaluate(self, log: SecurityLog, db: Session) -> Optional[Dict[str, Any]]:
        # Safe field validation
        if not log or not log.source_ip or not log.event_type or not log.user:
            return None

        event_norm = str(log.event_type).upper()
        # Strictly check for SUCCESSFUL authentication
        if event_norm in ("AUTHENTICATION_SUCCESS", "LOGIN_SUCCESS", "ROOT_LOGIN"):
            user_lower = str(log.user).strip().lower()
            if user_lower in ("root", "administrator", "admin"):
                # Remote access (non-localhost)
                if log.source_ip not in ("127.0.0.1", "::1", "localhost", "0.0.0.0"):
                    return {
                        "rule_id": self.id,
                        "title": self.name,
                        "description": (
                            f"Critical incident: Successful remote root/admin login from "
                            f"external IP {log.source_ip} as '{log.user}'."
                        ),
                        "severity": self.severity,
                        "source_ip": log.source_ip,
                        "destination_ip": log.destination_ip,
                        "target_user": log.user,
                        "trigger_count": 1
                    }
        # Failed root login attempts do NOT trigger critical incident
        return None


class DDoSAggregateRule(BaseRule):
    """
    Detects aggregate traffic spikes across multiple source IPs targeting the same destination.
    Default threshold: 20+ events targeting destination from >= 3 distinct IPs within 30s.
    """
    def __init__(
        self,
        min_events: Optional[int] = None,
        min_distinct_sources: Optional[int] = None,
        window_seconds: Optional[int] = None
    ):
        self.id = "RULE-NET-DDOS-AGGREGATE"
        self.name = "Distributed Denial of Service (DDoS) Spike Detected"
        self.severity = "CRITICAL"
        self.min_events = min_events if min_events is not None else settings.DDOS_MIN_EVENTS
        self.min_distinct_sources = min_distinct_sources if min_distinct_sources is not None else settings.DDOS_MIN_SOURCES
        self.window_seconds = window_seconds if window_seconds is not None else settings.DDOS_WINDOW_SECONDS
        self.description = (
            f"Aggregate traffic spike: {self.min_events}+ events targeting destination "
            f"from {self.min_distinct_sources}+ distinct IPs within {self.window_seconds}s."
        )

    def evaluate(self, log: SecurityLog, db: Session) -> Optional[Dict[str, Any]]:
        # Safe field validation: destination IP is mandatory for target correlation
        if not log or not log.destination_ip:
            return None

        ref_time = normalize_utc_timestamp(log.timestamp)
        window_start = ref_time - timedelta(seconds=self.window_seconds)

        # Count total events hitting this destination IP in the time window
        total_events = db.query(func.count(SecurityLog.id)).filter(
            SecurityLog.destination_ip == log.destination_ip,
            SecurityLog.timestamp >= window_start,
            SecurityLog.timestamp <= ref_time
        ).scalar() or 0

        if total_events < self.min_events:
            return None

        # Count distinct source IPs involved
        distinct_sources = db.query(func.count(func.distinct(SecurityLog.source_ip))).filter(
            SecurityLog.destination_ip == log.destination_ip,
            SecurityLog.timestamp >= window_start,
            SecurityLog.timestamp <= ref_time,
            SecurityLog.source_ip.isnot(None)
        ).scalar() or 0

        if distinct_sources >= self.min_distinct_sources:
            return {
                "rule_id": self.id,
                "title": self.name,
                "description": (
                    f"Distributed traffic surge: {total_events} requests targeting "
                    f"{log.destination_ip} across {distinct_sources} distinct source IPs "
                    f"within {self.window_seconds}s."
                ),
                "severity": self.severity,
                "source_ip": f"Distributed ({distinct_sources} IPs)",
                "destination_ip": log.destination_ip,
                "target_user": None,
                "trigger_count": total_events
            }
        return None


class AnomalousSpikeRule(BaseRule):
    """
    Detects single-source volumetric traffic or request spikes from a single host.
    Default threshold: 20 events within 60 seconds (configurable).
    """
    def __init__(
        self,
        threshold: Optional[int] = None,
        window_seconds: Optional[int] = None
    ):
        self.id = "RULE-ANOMALOUS-SPIKE"
        self.name = "Single-Source Traffic Spike"
        self.severity = "MEDIUM"
        self.threshold = threshold if threshold is not None else settings.ANOMALOUS_SPIKE_THRESHOLD
        self.window_seconds = window_seconds if window_seconds is not None else settings.ANOMALOUS_SPIKE_WINDOW_SECONDS
        self.description = (
            f"Single-source traffic spike: {self.threshold}+ events generated "
            f"within {self.window_seconds}s."
        )

    def evaluate(self, log: SecurityLog, db: Session) -> Optional[Dict[str, Any]]:
        # Safe field validation
        if not log or not log.source_ip:
            return None

        ref_time = normalize_utc_timestamp(log.timestamp)
        window_start = ref_time - timedelta(seconds=self.window_seconds)

        event_count = db.query(func.count(SecurityLog.id)).filter(
            SecurityLog.source_ip == log.source_ip,
            SecurityLog.timestamp >= window_start,
            SecurityLog.timestamp <= ref_time
        ).scalar() or 0

        if event_count >= self.threshold:
            return {
                "rule_id": self.id,
                "title": self.name,
                "description": f"Traffic volume spike: {event_count} events from {log.source_ip} in {self.window_seconds}s.",
                "severity": self.severity,
                "source_ip": log.source_ip,
                "destination_ip": log.destination_ip,
                "target_user": log.user,
                "trigger_count": event_count
            }
        return None
