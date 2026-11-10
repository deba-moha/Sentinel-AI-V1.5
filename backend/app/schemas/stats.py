"""
Sentinel AI - Statistics Schemas
Pydantic contracts for dashboard metrics and telemetry aggregations.
"""
from typing import List
from pydantic import BaseModel


class SeverityCount(BaseModel):
    severity: str
    count: int


class TimelinePoint(BaseModel):
    time_label: str
    event_count: int
    alert_count: int
    rule_alert_count: int = 0
    ml_alert_count: int = 0


class TopAttacker(BaseModel):
    ip: str
    event_count: int
    alert_count: int


class DashboardStatsResponse(BaseModel):
    total_logs: int
    total_alerts: int
    critical_alerts: int
    active_alerts: int
    resolved_alerts: int
    ml_alerts: int = 0
    rule_alerts: int = 0
    active_ml_alerts: int = 0
    resolved_ml_alerts: int = 0
    severity_breakdown: List[SeverityCount]
    timeline: List[TimelinePoint]
    top_attackers: List[TopAttacker]
