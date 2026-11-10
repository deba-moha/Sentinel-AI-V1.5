"""
Sentinel AI - ML Feature Extraction (Phase 1)
Extracts reusable numerical feature vectors from security log telemetry.
Operates on existing SQLAlchemy models, Pydantic schemas, or dictionaries
without altering existing database schemas or detection rules.
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Union
from backend.app.ml.config import ML_FEATURE_NAMES, ml_config


# Event types aligned with existing detection rules
FAILED_AUTH_EVENTS = frozenset({"AUTHENTICATION_FAILED", "AUTH_FAILURE", "LOGIN_FAILED"})
SUCCESSFUL_AUTH_EVENTS = frozenset({"AUTHENTICATION_SUCCESS", "LOGIN_SUCCESS", "ROOT_LOGIN"})

# Common keys that indicate network traffic volume in raw_data metadata
VOLUME_KEYS = ("bytes", "bytes_sent", "bytes_transferred", "bytes_received", "size", "packet_size", "payload_size", "volume")


def _get_field(log: Any, field_name: str, default: Any = None) -> Any:
    """Safely retrieves a field from a dict, SQLAlchemy model, or Pydantic schema."""
    if log is None:
        return default
    if isinstance(log, dict):
        return log.get(field_name, default)
    return getattr(log, field_name, default)


def _parse_timestamp(ts: Any) -> Optional[datetime]:
    """
    Parses a timestamp value into a timezone-aware UTC datetime.
    Supports datetime objects and ISO-8601 formatted strings.
    """
    if ts is None:
        return None
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts
    if isinstance(ts, str):
        clean_str = ts.strip()
        if not clean_str:
            return None
        try:
            if clean_str.endswith("Z"):
                clean_str = clean_str[:-1] + "+00:00"
            dt = datetime.fromisoformat(clean_str)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            return None
    return None


def _extract_volume(log: Any) -> float:
    """
    Extracts network traffic volume (bytes/size) if available in raw_data.
    Adheres to the existing database schema without inventing fields.
    Defaults to 0.0 when no suitable volume field is present.
    """
    # Direct field check on dictionary if present
    if isinstance(log, dict):
        for key in VOLUME_KEYS:
            val = log.get(key)
            if val is not None and isinstance(val, (int, float)):
                return float(val)

    # Check raw_data column/field (JSON string or dict)
    raw = _get_field(log, "raw_data")
    if not raw:
        return 0.0

    raw_dict: Optional[Dict[str, Any]] = None
    if isinstance(raw, dict):
        raw_dict = raw
    elif isinstance(raw, str):
        try:
            raw_dict = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return 0.0

    if isinstance(raw_dict, dict):
        for key in VOLUME_KEYS:
            val = raw_dict.get(key)
            if val is not None:
                try:
                    num_val = float(val)
                    if num_val >= 0:
                        return num_val
                except (ValueError, TypeError):
                    continue

    return 0.0


def extract_features_from_logs(logs: Optional[Sequence[Any]]) -> Dict[str, float]:
    """
    Extracts a dictionary of numerical features from a collection of security logs.

    Features computed:
    - total_events: Total count of log records in the sample window.
    - failed_auth_count: Number of failed authentication attempts.
    - successful_auth_count: Number of successful logins / root access events.
    - unique_source_ips: Count of distinct source IP addresses.
    - unique_dest_ips: Count of distinct destination IP addresses.
    - unique_dest_ports: Count of distinct destination ports probed or accessed.
    - event_frequency: Events per second across the observation window.
    - avg_time_interval: Mean elapsed seconds between consecutive events.
    - network_traffic_volume: Aggregated traffic volume (bytes) from metadata if present.

    Returns all 0.0 for empty or None inputs.
    """
    if not logs:
        return {name: 0.0 for name in ML_FEATURE_NAMES}

    total_events = len(logs)
    failed_auth = 0
    successful_auth = 0
    source_ips = set()
    dest_ips = set()
    dest_ports = set()
    total_volume = 0.0
    timestamps: List[datetime] = []

    for log in logs:
        if log is None:
            continue

        # 1. Event Type Analysis
        event_type = _get_field(log, "event_type")
        if event_type:
            event_norm = str(event_type).strip().upper()
            if event_norm in FAILED_AUTH_EVENTS:
                failed_auth += 1
            elif event_norm in SUCCESSFUL_AUTH_EVENTS:
                successful_auth += 1

        # 2. IP Address Aggregation
        src_ip = _get_field(log, "source_ip")
        if src_ip:
            source_ips.add(str(src_ip).strip())

        dst_ip = _get_field(log, "destination_ip")
        if dst_ip:
            dest_ips.add(str(dst_ip).strip())

        # 3. Port Aggregation
        dst_port = _get_field(log, "destination_port")
        if dst_port is not None:
            try:
                port_num = int(dst_port)
                if 0 <= port_num <= 65535:
                    dest_ports.add(port_num)
            except (ValueError, TypeError):
                pass

        # 4. Traffic Volume
        total_volume += _extract_volume(log)

        # 5. Timestamp Tracking
        raw_ts = _get_field(log, "timestamp")
        parsed_ts = _parse_timestamp(raw_ts)
        if parsed_ts is not None:
            timestamps.append(parsed_ts)

    # 6. Timing and Frequency Metrics
    event_frequency = 0.0
    avg_time_interval = 0.0

    if len(timestamps) >= 2:
        timestamps.sort()
        time_span = (timestamps[-1] - timestamps[0]).total_seconds()
        if time_span > 0:
            event_frequency = total_events / time_span
            avg_time_interval = time_span / (len(timestamps) - 1)
        else:
            # All events occurred within the exact same sub-second
            event_frequency = float(total_events)
            avg_time_interval = 0.0
    elif len(timestamps) == 1:
        # Single event, frequency and interval are zero
        event_frequency = 0.0
        avg_time_interval = 0.0

    return {
        "total_events": float(total_events),
        "failed_auth_count": float(failed_auth),
        "successful_auth_count": float(successful_auth),
        "unique_source_ips": float(len(source_ips)),
        "unique_dest_ips": float(len(dest_ips)),
        "unique_dest_ports": float(len(dest_ports)),
        "event_frequency": float(event_frequency),
        "avg_time_interval": float(avg_time_interval),
        "network_traffic_volume": float(total_volume),
    }


def extract_features_by_source_ip(logs: Optional[Sequence[Any]]) -> Dict[str, Dict[str, float]]:
    """
    Groups logs by source IP address and extracts a feature dictionary for each source IP.
    Useful for host-centric anomaly detection.
    """
    if not logs:
        return {}

    grouped: Dict[str, List[Any]] = {}
    for log in logs:
        if log is None:
            continue
        src = _get_field(log, "source_ip", "UNKNOWN")
        grouped.setdefault(str(src), []).append(log)

    return {ip: extract_features_from_logs(ip_logs) for ip, ip_logs in grouped.items()}


def extract_features_batch(log_batches: Optional[Sequence[Sequence[Any]]]) -> List[Dict[str, float]]:
    """
    Extracts features for a sequence of log batches (e.g. multiple time windows or sessions).
    Returns a list of feature dictionaries.
    """
    if not log_batches:
        return []
    return [extract_features_from_logs(batch) for batch in log_batches]

