"""
Sentinel AI - Alert Schemas
Pydantic contracts for security alerts, triage status updates, and incident details.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    title: str
    description: str
    severity: str
    status: str
    source_ip: str
    destination_ip: Optional[str] = None
    target_user: Optional[str] = None
    trigger_count: int
    created_at: datetime
    updated_at: datetime


class AlertUpdate(BaseModel):
    status: str = Field(
        ...,
        json_schema_extra={"example": "INVESTIGATING"},
        description="NEW | INVESTIGATING | RESOLVED | FALSE_POSITIVE"
    )
