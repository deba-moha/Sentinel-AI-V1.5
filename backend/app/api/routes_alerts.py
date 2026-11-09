"""
Sentinel AI - Alert Investigation & Management API Routes
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.schemas.alert import AlertResponse, AlertUpdate
from backend.app.services.alert_service import alert_service

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=List[AlertResponse])
def get_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieve security alerts with optional severity/status filters."""
    alerts = alert_service.get_alerts(
        db=db,
        skip=skip,
        limit=limit,
        severity=severity,
        status=status,
        search=search
    )
    return [AlertResponse.model_validate(a) for a in alerts]


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert_by_id(alert_id: int, db: Session = Depends(get_db)):
    """Fetch single alert detail by ID."""
    alert = alert_service.get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found")
    return AlertResponse.model_validate(alert)


@router.patch("/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db)):
    """Update triage status: NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE."""
    try:
        updated = alert_service.update_status(db, alert_id, payload.status)
        if not updated:
            raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found")
        return AlertResponse.model_validate(updated)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

