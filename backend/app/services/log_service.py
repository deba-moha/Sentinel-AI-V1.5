"""
Sentinel AI - Log Service
Handles log ingestion, persistence, and evaluation through the detection engine.
"""
import json
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc
from backend.app.models.security_log import SecurityLog
from backend.app.models.alert import Alert
from backend.app.schemas.log import LogCreate, LogBatchCreate
from backend.app.detection.engine import detection_engine
from backend.app.core.logging_config import logger


class LogService:
    @staticmethod
    def ingest_log(log_in: LogCreate, db: Session) -> Tuple[SecurityLog, List[Alert]]:
        """
        Persists an incoming security log and runs it through the detection engine.
        """
        raw_json = json.dumps(log_in.raw_data) if log_in.raw_data else None
        timestamp = log_in.timestamp or datetime.now(timezone.utc)

        protocol = (log_in.protocol or "TCP").upper()
        event_type = (log_in.event_type or "UNKNOWN").upper()
        severity = (log_in.severity or "INFO").upper()

        db_log = SecurityLog(
            timestamp=timestamp,
            source_ip=log_in.source_ip,
            destination_ip=log_in.destination_ip,
            source_port=log_in.source_port,
            destination_port=log_in.destination_port,
            protocol=protocol,
            event_type=event_type,
            severity=severity,
            user=log_in.user,
            message=log_in.message,
            raw_data=raw_json,
            created_at=datetime.now(timezone.utc)
        )

        db.add(db_log)
        db.commit()
        db.refresh(db_log)

        # Run through detection rules
        alerts = detection_engine.evaluate_log(db_log, db)
        return db_log, alerts

    @staticmethod
    def ingest_batch(batch_in: LogBatchCreate, db: Session) -> Tuple[List[SecurityLog], List[Alert]]:
        """
        Ingests a batch of security logs and evaluates each in order.
        """
        logs_created = []
        all_alerts = []

        for item in batch_in.logs:
            db_log, alerts = LogService.ingest_log(item, db)
            logs_created.append(db_log)
            all_alerts.extend(alerts)

        return logs_created, all_alerts

    @staticmethod
    def get_logs(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        search: Optional[str] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        source_ip: Optional[str] = None
    ) -> List[SecurityLog]:
        """
        Retrieves logs with optional filtering and pagination.
        """
        query = db.query(SecurityLog)

        if severity:
            query = query.filter(SecurityLog.severity == severity.upper())
        if event_type:
            query = query.filter(SecurityLog.event_type == event_type.upper())
        if source_ip:
            query = query.filter(SecurityLog.source_ip == source_ip)
        if search:
            search_fmt = f"%{search}%"
            query = query.filter(
                (SecurityLog.message.ilike(search_fmt)) |
                (SecurityLog.source_ip.ilike(search_fmt)) |
                (SecurityLog.user.ilike(search_fmt))
            )

        return query.order_by(desc(SecurityLog.timestamp)).offset(skip).limit(limit).all()

    @staticmethod
    def get_log_by_id(db: Session, log_id: int) -> Optional[SecurityLog]:
        return db.query(SecurityLog).filter(SecurityLog.id == log_id).first()


log_service = LogService()

