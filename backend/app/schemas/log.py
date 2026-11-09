"""
Sentinel AI - Log Schemas
Pydantic contracts for log ingestion, batch processing, and query responses.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class LogCreate(BaseModel):
    timestamp: Optional[datetime] = None
    source_ip: str = Field(..., json_schema_extra={"example": "192.168.1.100"})
    destination_ip: Optional[str] = Field(None, json_schema_extra={"example": "10.0.0.1"})
    source_port: Optional[int] = Field(None, json_schema_extra={"example": 45210})
    destination_port: Optional[int] = Field(None, json_schema_extra={"example": 22})
    protocol: str = Field(default="TCP", json_schema_extra={"example": "TCP"})
    event_type: str = Field(..., json_schema_extra={"example": "AUTHENTICATION_FAILED"})
    severity: str = Field(default="INFO", json_schema_extra={"example": "MEDIUM"})
    user: Optional[str] = Field(None, json_schema_extra={"example": "root"})
    message: str = Field(..., json_schema_extra={"example": "Failed password attempt for root"})
    raw_data: Optional[Dict[str, Any]] = None


class LogBatchCreate(BaseModel):
    logs: List[LogCreate]


class LogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str
    event_type: str
    severity: str
    user: Optional[str] = None
    message: str
    raw_data: Optional[str] = None
    created_at: datetime
