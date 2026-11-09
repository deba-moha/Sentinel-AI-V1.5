"""
Sentinel AI - Simulator Schemas
Pydantic contracts for attack and traffic simulation requests.
"""
from typing import List, Optional
from pydantic import BaseModel, Field
from backend.app.schemas.alert import AlertResponse


class SimulationRequest(BaseModel):
    scenario: str = Field(
        ...,
        json_schema_extra={"example": "BRUTE_FORCE"},
        description="BRUTE_FORCE | PORT_SCAN | ROOT_LOGIN | DDOS_ATTACK | ANOMALOUS_SPIKE | NORMAL_TRAFFIC | MIXED"
    )
    count: int = Field(default=10, ge=1, le=100, description="Number of logs to generate")
    source_ip: Optional[str] = Field(None, json_schema_extra={"example": "198.51.100.42"})


class SimulationResponse(BaseModel):
    status: str
    scenario: str
    logs_generated: int
    alerts_triggered: int
    new_alerts: List[AlertResponse]
