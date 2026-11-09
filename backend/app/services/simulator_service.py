"""
Sentinel AI - Simulator Service
Coordinates simulation runs and routes generated events into the ingestion pipeline.
"""
from typing import List
from sqlalchemy.orm import Session
from backend.app.schemas.simulator import SimulationRequest, SimulationResponse
from backend.app.schemas.alert import AlertResponse
from backend.app.schemas.log import LogCreate
from backend.app.simulator.generator import LogGenerator
from backend.app.services.log_service import log_service
from backend.app.models.alert import Alert


class SimulatorService:
    @staticmethod
    def run_simulation(req: SimulationRequest, db: Session) -> SimulationResponse:
        scenario = req.scenario.upper()
        logs_to_ingest: List[LogCreate] = []

        if scenario == "BRUTE_FORCE":
            logs_to_ingest = LogGenerator.generate_brute_force(count=req.count, attacker_ip=req.source_ip)
        elif scenario == "PORT_SCAN":
            logs_to_ingest = LogGenerator.generate_port_scan(count=req.count, attacker_ip=req.source_ip)
        elif scenario in ("ROOT_LOGIN", "SUCCESSFUL_ROOT_LOGIN"):
            logs_to_ingest = LogGenerator.generate_root_login(attacker_ip=req.source_ip, success=True)
        elif scenario == "FAILED_ROOT_LOGIN":
            logs_to_ingest = LogGenerator.generate_root_login(attacker_ip=req.source_ip, success=False)
        elif scenario in ("DDOS_ATTACK", "DDOS", "AGGREGATE_SPIKE"):
            logs_to_ingest = LogGenerator.generate_ddos_aggregate(count=max(20, req.count))
        elif scenario == "ANOMALOUS_SPIKE":
            logs_to_ingest = LogGenerator.generate_anomalous_spike(count=req.count, attacker_ip=req.source_ip)
        elif scenario == "NORMAL_TRAFFIC":
            logs_to_ingest = LogGenerator.generate_normal_traffic(count=req.count)
        elif scenario == "MIXED":
            normal = LogGenerator.generate_normal_traffic(count=max(3, req.count // 2))
            attack = LogGenerator.generate_brute_force(count=max(5, req.count // 2), attacker_ip=req.source_ip)
            logs_to_ingest = normal + attack
        else:
            raise ValueError(f"Unknown scenario '{req.scenario}'")

        triggered_alerts: List[Alert] = []
        for log_item in logs_to_ingest:
            _, alerts = log_service.ingest_log(log_item, db)
            triggered_alerts.extend(alerts)

        # De-duplicate alerts in response
        unique_alerts_dict = {a.id: a for a in triggered_alerts}
        alert_responses = [AlertResponse.model_validate(a) for a in unique_alerts_dict.values()]

        return SimulationResponse(
            status="SUCCESS",
            scenario=scenario,
            logs_generated=len(logs_to_ingest),
            alerts_triggered=len(alert_responses),
            new_alerts=alert_responses
        )


simulator_service = SimulatorService()
