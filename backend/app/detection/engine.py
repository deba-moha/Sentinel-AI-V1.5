"""
Sentinel AI - Detection Engine
Orchestrates rule evaluation, time-window grouping, and alert de-duplication.
"""
from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.models.security_log import SecurityLog
from backend.app.models.alert import Alert
from backend.app.detection.rules import (
    BaseRule,
    BruteForceRule,
    PortScanRule,
    RootLoginRule,
    DDoSAggregateRule,
    AnomalousSpikeRule,
    MLAnomalyRule
)
from backend.app.core.logging_config import logger


class DetectionEngine:
    def __init__(self):
        # All rules read default thresholds directly from settings (zero hardcoded values)
        self.rules: List[BaseRule] = [
            BruteForceRule(),
            PortScanRule(),
            RootLoginRule(),
            DDoSAggregateRule(),
            AnomalousSpikeRule()
        ]
        if settings.ENABLE_ML_DETECTION:
            self.rules.append(MLAnomalyRule())

        logger.info(f"Initialized DetectionEngine with {len(self.rules)} active rules using central settings.")

    def add_rule(self, rule: BaseRule) -> None:
        """Allows modular registration of additional detection rules."""
        self.rules.append(rule)
        logger.info(f"Registered new detection rule: {rule.id}")

    def evaluate_log(self, log: SecurityLog, db: Session) -> List[Alert]:
        """
        Evaluates a log entry against all registered detection rules.
        Creates or updates alerts while de-duplicating ongoing patterns.
        """
        generated_alerts: List[Alert] = []

        for rule in self.rules:
            try:
                alert_payload = rule.evaluate(log, db)
                if alert_payload:
                    alert = self._record_or_update_alert(alert_payload, db)
                    if alert:
                        generated_alerts.append(alert)
            except Exception as e:
                db.rollback()
                logger.error(f"Error evaluating rule {rule.id}: {e}", exc_info=True)

        return generated_alerts

    def _record_or_update_alert(self, payload: dict, db: Session) -> Optional[Alert]:
        """
        De-duplicates ongoing alerts using strict entity grouping:
        - For aggregate DDoS, groups by rule_id and destination_ip (never merging distinct destinations).
        - For host-specific attacks, groups by rule_id and source_ip (never merging distinct source IPs).
        - Increments trigger_count on existing active incidents (NEW or INVESTIGATING).
        - If a previous incident was RESOLVED or marked FALSE_POSITIVE, a new incident is created.
        """
        rule_id = payload["rule_id"]
        source_ip = payload.get("source_ip")
        destination_ip = payload.get("destination_ip")

        query = db.query(Alert).filter(
            Alert.rule_id == rule_id,
            Alert.status.in_(["NEW", "INVESTIGATING"])
        )

        if rule_id == "RULE-NET-DDOS-AGGREGATE":
            if destination_ip:
                query = query.filter(Alert.destination_ip == destination_ip)
            else:
                query = query.filter(Alert.source_ip == source_ip)
        else:
            query = query.filter(Alert.source_ip == source_ip)

        existing_alert = query.first()
        now = datetime.now(timezone.utc)

        if existing_alert:
            existing_alert.trigger_count = payload.get("trigger_count", existing_alert.trigger_count + 1)
            existing_alert.description = payload["description"]
            existing_alert.updated_at = now
            db.commit()
            db.refresh(existing_alert)
            logger.info(
                f"Aggregated ongoing incident #{existing_alert.id} ({existing_alert.rule_id}) "
                f"hits: {existing_alert.trigger_count}"
            )
            return existing_alert
        else:
            new_alert = Alert(
                rule_id=rule_id,
                title=payload["title"],
                description=payload["description"],
                severity=payload["severity"],
                status="NEW",
                source_ip=source_ip or "UNKNOWN",
                destination_ip=destination_ip,
                target_user=payload.get("target_user"),
                trigger_count=payload.get("trigger_count", 1),
                created_at=now,
                updated_at=now
            )
            db.add(new_alert)
            db.commit()
            db.refresh(new_alert)
            logger.warning(
                f"🚨 New Incident Raised [{new_alert.severity}] {new_alert.title} "
                f"(Source: {new_alert.source_ip}, Target: {new_alert.destination_ip})"
            )
            return new_alert


detection_engine = DetectionEngine()
