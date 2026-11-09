"""
Sentinel AI - Statistics & Metrics API Routes
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.schemas.stats import DashboardStatsResponse
from backend.app.services.stats_service import stats_service

router = APIRouter(prefix="/stats", tags=["Stats"])


@router.get("", response_model=DashboardStatsResponse)
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Retrieve summarized telemetry metrics for dashboard visualization."""
    return stats_service.get_dashboard_stats(db)

