"""
Sentinel AI - Detection Rule Database Model
Stores detection rule metadata, thresholds, and activation state.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, Boolean, Integer, DateTime
from backend.app.database.session import Base


class DetectionRuleModel(Base):
    __tablename__ = "detection_rules"

    id = Column(String(50), primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, default="HIGH")
    enabled = Column(Boolean, default=True)
    rule_type = Column(String(50), default="DETERMINISTIC")
    threshold = Column(Integer, default=5)
    window_seconds = Column(Integer, default=60)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:
        return f"<DetectionRuleModel(id='{self.id}', name='{self.name}', enabled={self.enabled})>"
