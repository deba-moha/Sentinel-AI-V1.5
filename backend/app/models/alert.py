"""
Sentinel AI - Alert Database Model
Stores security incidents and tracks incident lifecycle (triage, hits, and aggregation).
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime
from backend.app.database.session import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    rule_id = Column(String(50), nullable=False, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(20), nullable=False, default="NEW")       # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    source_ip = Column(String(100), nullable=False, index=True)
    destination_ip = Column(String(100), nullable=True, index=True)  # Facilitates incident grouping for aggregate DDoS
    target_user = Column(String(100), nullable=True)
    trigger_count = Column(Integer, default=1)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), index=True)

    def __repr__(self) -> str:
        return f"<Alert(id={self.id}, rule='{self.rule_id}', severity='{self.severity}', status='{self.status}', count={self.trigger_count})>"
