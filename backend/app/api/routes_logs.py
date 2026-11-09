"""
Sentinel AI - Log Ingestion & Retrieval API Routes
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.schemas.log import LogCreate, LogResponse, LogBatchCreate
from backend.app.schemas.alert import AlertResponse
from backend.app.services.log_service import log_service
from pydantic import BaseModel

router = APIRouter(prefix="/logs", tags=["Logs"])


class LogIngestResult(BaseModel):
    log: LogResponse
    alerts_triggered: List[AlertResponse]


class LogBatchResult(BaseModel):
    count: int
    alerts_triggered: List[AlertResponse]


@router.post("", response_model=LogIngestResult, status_code=status.HTTP_201_CREATED)
def ingest_log(payload: LogCreate, db: Session = Depends(get_db)):
    """Ingest a single security event log and run detection rules."""
    log_record, alerts = log_service.ingest_log(payload, db)
    return {
        "log": LogResponse.model_validate(log_record),
        "alerts_triggered": [AlertResponse.model_validate(a) for a in alerts]
    }


@router.post("/batch", response_model=LogBatchResult, status_code=status.HTTP_201_CREATED)
def ingest_batch_logs(payload: LogBatchCreate, db: Session = Depends(get_db)):
    """Ingest a batch of security events."""
    logs, alerts = log_service.ingest_batch(payload, db)
    return {
        "count": len(logs),
        "alerts_triggered": [AlertResponse.model_validate(a) for a in alerts]
    }


@router.get("", response_model=List[LogResponse])
def get_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    search: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieve security logs with filtering and pagination."""
    logs = log_service.get_logs(
        db=db,
        skip=skip,
        limit=limit,
        search=search,
        severity=severity,
        event_type=event_type,
        source_ip=source_ip
    )
    return [LogResponse.model_validate(l) for l in logs]


@router.get("/{log_id}", response_model=LogResponse)
def get_log_by_id(log_id: int, db: Session = Depends(get_db)):
    """Get single security log by ID."""
    log_record = log_service.get_log_by_id(db, log_id)
    if not log_record:
        raise HTTPException(status_code=404, detail=f"Log with ID {log_id} not found")
    return LogResponse.model_validate(log_record)

