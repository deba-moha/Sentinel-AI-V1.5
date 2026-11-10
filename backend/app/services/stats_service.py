"""
Sentinel AI - Statistics Service
Calculates aggregated security metrics and visualization data for the dashboard.
"""
from datetime import datetime, timedelta, timezone
from typing import List
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from backend.app.models.security_log import SecurityLog
from backend.app.models.alert import Alert
from backend.app.schemas.stats import (
    DashboardStatsResponse,
    SeverityCount,
    TimelinePoint,
    TopAttacker
)

ML_RULE_ID = "RULE-ML-ANOMALY-IFOREST"

DETERMINISTIC_RULE_IDS = [
    "RULE-AUTH-BRUTEFORCE",
    "RULE-NET-PORTSCAN",
    "RULE-AUTH-ROOT-LOGIN",
    "RULE-NET-DDOS-AGGREGATE",
    "RULE-ANOMALOUS-SPIKE"
]


class StatsService:
    @staticmethod
    def get_dashboard_stats(db: Session) -> DashboardStatsResponse:
        total_logs = db.query(func.count(SecurityLog.id)).scalar() or 0
        total_alerts = db.query(func.count(Alert.id)).scalar() or 0
        critical_alerts = db.query(func.count(Alert.id)).filter(Alert.severity == "CRITICAL").scalar() or 0
        active_alerts = db.query(func.count(Alert.id)).filter(Alert.status.in_(["NEW", "INVESTIGATING"])).scalar() or 0
        resolved_alerts = db.query(func.count(Alert.id)).filter(Alert.status == "RESOLVED").scalar() or 0

        # ML-specific and Deterministic-specific alert counts (Phase 5 Step 4A)
        ml_alerts = db.query(func.count(Alert.id)).filter(Alert.rule_id == ML_RULE_ID).scalar() or 0
        rule_alerts = db.query(func.count(Alert.id)).filter(Alert.rule_id.in_(DETERMINISTIC_RULE_IDS)).scalar() or 0
        active_ml_alerts = db.query(func.count(Alert.id)).filter(
            Alert.rule_id == ML_RULE_ID,
            Alert.status.in_(["NEW", "INVESTIGATING"])
        ).scalar() or 0
        resolved_ml_alerts = db.query(func.count(Alert.id)).filter(
            Alert.rule_id == ML_RULE_ID,
            Alert.status == "RESOLVED"
        ).scalar() or 0

        # Severity breakdown for alerts
        sev_query = db.query(
            Alert.severity,
            func.count(Alert.id)
        ).group_by(Alert.severity).all()

        severities_found = {row[0].upper(): row[1] for row in sev_query}
        severity_breakdown = [
            SeverityCount(severity=sev, count=severities_found.get(sev, 0))
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        ]

        # Timeline (last 6 10-minute intervals or hourly bins)
        now = datetime.now(timezone.utc)
        timeline: List[TimelinePoint] = []
        for i in range(5, -1, -1):
            interval_end = now - timedelta(minutes=i * 10)
            interval_start = interval_end - timedelta(minutes=10)
            time_label = interval_end.strftime("%H:%M")

            ev_count = db.query(func.count(SecurityLog.id)).filter(
                SecurityLog.timestamp >= interval_start,
                SecurityLog.timestamp < interval_end
            ).scalar() or 0

            al_count = db.query(func.count(Alert.id)).filter(
                Alert.created_at >= interval_start,
                Alert.created_at < interval_end
            ).scalar() or 0

            rule_al_count = db.query(func.count(Alert.id)).filter(
                Alert.rule_id.in_(DETERMINISTIC_RULE_IDS),
                Alert.created_at >= interval_start,
                Alert.created_at < interval_end
            ).scalar() or 0

            ml_al_count = db.query(func.count(Alert.id)).filter(
                Alert.rule_id == ML_RULE_ID,
                Alert.created_at >= interval_start,
                Alert.created_at < interval_end
            ).scalar() or 0

            timeline.append(TimelinePoint(
                time_label=time_label,
                event_count=ev_count,
                alert_count=al_count,
                rule_alert_count=rule_al_count,
                ml_alert_count=ml_al_count
            ))

        # Top Attacking IPs
        top_ips_query = db.query(
            SecurityLog.source_ip,
            func.count(SecurityLog.id).label("ev_count")
        ).group_by(SecurityLog.source_ip).order_by(desc("ev_count")).limit(5).all()

        top_attackers: List[TopAttacker] = []
        for ip, ev_count in top_ips_query:
            al_count = db.query(func.count(Alert.id)).filter(Alert.source_ip == ip).scalar() or 0
            top_attackers.append(TopAttacker(
                ip=ip,
                event_count=ev_count,
                alert_count=al_count
            ))

        return DashboardStatsResponse(
            total_logs=total_logs,
            total_alerts=total_alerts,
            critical_alerts=critical_alerts,
            active_alerts=active_alerts,
            resolved_alerts=resolved_alerts,
            ml_alerts=ml_alerts,
            rule_alerts=rule_alerts,
            active_ml_alerts=active_ml_alerts,
            resolved_ml_alerts=resolved_ml_alerts,
            severity_breakdown=severity_breakdown,
            timeline=timeline,
            top_attackers=top_attackers
        )


stats_service = StatsService()

