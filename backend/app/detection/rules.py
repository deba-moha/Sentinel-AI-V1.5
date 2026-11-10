"""
Sentinel AI - Foundational Threat Detection Rules (V1.0)
Deterministic, rule-based threat detection logic.
Thresholds are dynamically read from centralized configuration settings.
"""
from abc import ABC, abstractmethod
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.app.core.config import settings
from backend.app.core.logging_config import logger
from backend.app.models.security_log import SecurityLog
from backend.app.ml.features import extract_features_from_logs
from backend.app.ml.model import IsolationForestModel
from backend.app.ml.model_store import load_model, model_exists


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


class MLAnomalyRule(BaseRule):
    """
    Detects macro-level statistical anomalies across security telemetry using
    Isolation Forest anomaly detection (Phase 4 Hybrid Engine).

    Evaluates 9 canonical numerical features over a sliding observation window.
    Strictly adheres to Phase 4 Strategy A (Zero Schema Migration):
    - severity is fixed at 'MEDIUM'
    - rule_id is 'RULE-ML-ANOMALY-IFOREST'
    - attribution uses deterministic concentration thresholds or stable entity keys:
      'Distributed Sources' for multi-source attacks and 'Global Telemetry Window' for diffuse anomalies.
    - full failure isolation: missing or corrupt model safely leaves detection dormant.
    """
    def __init__(
        self,
        threshold: Optional[float] = None,
        window_seconds: Optional[int] = None,
        min_events: Optional[int] = None,
        model_path: Optional[str] = None
    ):
        self.id = "RULE-ML-ANOMALY-IFOREST"
        self.name = "Machine Learning Anomaly Detected"
        self.severity = "MEDIUM"  # Strictly fixed at MEDIUM for Phase 4
        self.enabled = settings.ENABLE_ML_DETECTION
        self.threshold = threshold if threshold is not None else settings.ML_ANOMALY_THRESHOLD
        self.window_seconds = window_seconds if window_seconds is not None else settings.ML_WINDOW_SECONDS
        self.min_events = min_events if min_events is not None else settings.ML_MIN_EVENTS
        self.description = (
            f"Statistical outlier detection using Isolation Forest across 9 numerical features "
            f"over a sliding {self.window_seconds}s observation window."
        )
        self.model_path = model_path
        self.model: Optional[IsolationForestModel] = None
        self._load_model_safe()

    def _load_model_safe(self) -> None:
        """Attempts to load the trained model artifact. Sets self.model=None on failure."""
        if not self.enabled:
            self.model = None
            logger.info("MLAnomalyRule is disabled via ENABLE_ML_DETECTION setting.")
            return

        try:
            if model_exists(self.model_path):
                self.model = load_model(self.model_path)
                logger.info(f"MLAnomalyRule successfully loaded model from: {self.model_path or 'default model store'}")
            else:
                self.model = None
                logger.info("MLAnomalyRule model artifact not found. ML detection dormant; deterministic rules operational.")
        except Exception as exc:
            self.model = None
            logger.warning(f"MLAnomalyRule failed to load model artifact ({type(exc).__name__}: {exc}). ML detection dormant.")

    def reload_model(self, filepath: Optional[str] = None) -> bool:
        """Allows programmatic reloading of model artifact without restarting process."""
        if filepath is not None:
            self.model_path = filepath
        self._load_model_safe()
        return self.model is not None

    def evaluate(self, log: SecurityLog, db: Session) -> Optional[Dict[str, Any]]:
        # Fast guard: if disabled, model missing, or invalid log, return None in sub-microsecond time
        if not self.enabled or self.model is None or not log:
            return None

        try:
            ref_time = normalize_utc_timestamp(log.timestamp)
            window_start = ref_time - timedelta(seconds=self.window_seconds)

            # Lightweight count query to avoid unnecessary log retrieval
            event_count = db.query(func.count(SecurityLog.id)).filter(
                SecurityLog.timestamp >= window_start,
                SecurityLog.timestamp <= ref_time
            ).scalar() or 0

            if event_count < self.min_events:
                return None

            # Retrieve window logs
            window_logs = db.query(SecurityLog).filter(
                SecurityLog.timestamp >= window_start,
                SecurityLog.timestamp <= ref_time
            ).order_by(SecurityLog.timestamp.asc()).all()

            if not window_logs:
                return None

            # Extract 9 canonical features
            features = extract_features_from_logs(window_logs)

            # Run Isolation Forest prediction
            pred = self.model.predict_single(features, threshold=self.threshold)

            if not pred["is_anomaly"]:
                return None

            # Deterministic and explainable attribution policy
            # 1. Source attribution
            source_counts = Counter(l.source_ip for l in window_logs if l.source_ip)
            top_src, top_src_cnt = source_counts.most_common(1)[0] if source_counts else (None, 0)

            if top_src and (top_src_cnt / event_count >= 0.60):
                attributed_source = top_src
            elif len(source_counts) >= 3:
                attributed_source = "Distributed Sources"
            else:
                attributed_source = "Global Telemetry Window"

            # 2. Destination attribution
            dest_counts = Counter(l.destination_ip for l in window_logs if l.destination_ip)
            top_dst, top_dst_cnt = dest_counts.most_common(1)[0] if dest_counts else (None, 0)

            if top_dst and (top_dst_cnt / event_count >= 0.60):
                attributed_dest = top_dst
            else:
                attributed_dest = None

            model_ver = getattr(getattr(self.model, "config", None), "model_version", "1.5.0")
            desc = (
                f"[ML Anomaly Detection] Statistical anomaly detected by Isolation Forest v{model_ver}. "
                f"Metrics: Normalized Anomaly Score = {pred['anomaly_score']:.4f} | "
                f"Raw Score = {pred['raw_score']:.4f} (Decision Cutoff: {self.threshold:.4f}). "
                f"Window Telemetry ({self.window_seconds}s): {int(features['total_events'])} total events, "
                f"{int(features['failed_auth_count'])} failed auths, {int(features['successful_auth_count'])} successful logins, "
                f"{int(features['unique_source_ips'])} unique source IPs, {int(features['unique_dest_ports'])} unique dest ports, "
                f"{features['event_frequency']:.2f} req/s, {features['network_traffic_volume']:.1f} bytes volume. "
                f"Note: Anomaly scores reflect geometric isolation path lengths and are not probabilities or confirmed severity. "
                f"Observed window metrics are reported for analyst triage; base Isolation Forest does not perform causal feature attribution."
            )

            return {
                "rule_id": self.id,
                "title": self.name,
                "description": desc,
                "severity": self.severity,  # Strictly fixed at "MEDIUM"
                "source_ip": attributed_source,
                "destination_ip": attributed_dest,
                "target_user": None,
                "trigger_count": event_count
            }
        except Exception as exc:
            logger.error(f"Error evaluating MLAnomalyRule: {exc}", exc_info=True)
            return None
