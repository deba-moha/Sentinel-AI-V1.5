"""
Sentinel AI - Attack & Traffic Simulator API Routes
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.schemas.simulator import SimulationRequest, SimulationResponse
from backend.app.services.simulator_service import simulator_service

router = APIRouter(prefix="/simulator", tags=["Simulator"])


@router.post("/run", response_model=SimulationResponse, status_code=status.HTTP_200_OK)
def run_simulation(req: SimulationRequest, db: Session = Depends(get_db)):
    """
    Triggers simulated attack traffic (e.g. BRUTE_FORCE, PORT_SCAN, ROOT_LOGIN, ANOMALOUS_SPIKE, NORMAL_TRAFFIC).
    """
    try:
        return simulator_service.run_simulation(req, db)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

