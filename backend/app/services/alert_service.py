"""
Sentinel AI - Alert Service
Manages threat alert queries, triage workflows, and status transitions.
"""
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc
from backend.app.models.alert import Alert
from backend.app.core.logging_config import logger

VALID_STATUSES = {"NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}


class AlertService:
    @staticmethod
    def get_alerts(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None
    ) -> List[Alert]:
        """
        Queries alerts with optional filtering and pagination.
        """
        query = db.query(Alert)

        if severity:
            query = query.filter(Alert.severity == severity.upper())
        if status:
            query = query.filter(Alert.status == status.upper())
        if search:
            search_fmt = f"%{search}%"
            query = query.filter(
                (Alert.title.ilike(search_fmt)) |
                (Alert.description.ilike(search_fmt)) |
                (Alert.source_ip.ilike(search_fmt)) |
                (Alert.rule_id.ilike(search_fmt))
            )

        return query.order_by(desc(Alert.updated_at)).offset(skip).limit(limit).all()

    @staticmethod
    def get_alert_by_id(db: Session, alert_id: int) -> Optional[Alert]:
        return db.query(Alert).filter(Alert.id == alert_id).first()

    @staticmethod
    def update_status(db: Session, alert_id: int, new_status: str) -> Optional[Alert]:
        """
        Updates the triage status of an alert (e.g. from NEW to INVESTIGATING or RESOLVED).
        """
        status_norm = new_status.upper()
        if status_norm not in VALID_STATUSES:
            raise ValueError(f"Invalid alert status '{new_status}'. Allowed: {', '.join(VALID_STATUSES)}")

        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return None

        alert.status = status_norm
        alert.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(alert)

        logger.info(f"Alert {alert_id} status updated to {status_norm}")
        return alert


alert_service = AlertService()

