"""
Sentinel AI - Security Log Database Model
Stores raw telemetry and ingested security events.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime
from backend.app.database.session import Base


class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(10), default="TCP")
    event_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), default="INFO")
    user = Column(String(100), nullable=True)
    message = Column(Text, nullable=False)
    raw_data = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:
        return f"<SecurityLog(id={self.id}, ip='{self.source_ip}', event='{self.event_type}', sev='{self.severity}')>"
