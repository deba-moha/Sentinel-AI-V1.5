"""
Sentinel AI - Main API Router Registration
"""
from fastapi import APIRouter
from backend.app.api.routes_logs import router as logs_router
from backend.app.api.routes_alerts import router as alerts_router
from backend.app.api.routes_stats import router as stats_router
from backend.app.api.routes_simulator import router as simulator_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(logs_router)
api_router.include_router(alerts_router)
api_router.include_router(stats_router)
api_router.include_router(simulator_router)

__all__ = ["api_router"]

