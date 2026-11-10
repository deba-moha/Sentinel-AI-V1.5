"""
Sentinel AI - Comprehensive API Integration Test Suite
Validates all REST endpoints, query filters, error handling, status codes, and simulation scenarios.
"""
from fastapi import status


def test_root_and_health_endpoints(client):
    res_root = client.get("/")
    assert res_root.status_code == status.HTTP_200_OK
    data = res_root.json()
    assert data["service"] == "Sentinel AI"
    assert data["status"] == "OPERATIONAL"

    res_health = client.get("/health")
    assert res_health.status_code == status.HTTP_200_OK
    assert res_health.json()["status"] == "healthy"


def test_ingest_single_log(client):
    payload = {
        "source_ip": "10.0.0.99",
        "destination_ip": "10.0.0.1",
        "destination_port": 80,
        "protocol": "TCP",
        "event_type": "HTTP_REQUEST",
        "severity": "INFO",
        "message": "GET /healthcheck"
    }
    response = client.post("/api/v1/logs", json=payload)
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["log"]["source_ip"] == "10.0.0.99"
    assert data["log"]["id"] is not None
    assert isinstance(data["alerts_triggered"], list)


def test_ingest_batch_logs(client):
    batch_payload = {
        "logs": [
            {
                "source_ip": "10.0.0.10",
                "event_type": "HTTP_REQUEST",
                "message": "GET /api/v1/data"
            },
            {
                "source_ip": "10.0.0.11",
                "event_type": "DNS_QUERY",
                "message": "DNS query internal"
            }
        ]
    }
    response = client.post("/api/v1/logs/batch", json=batch_payload)
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["count"] == 2


def test_get_logs_filtering_and_pagination(client):
    client.post("/api/v1/logs", json={
        "source_ip": "1.1.1.1",
        "event_type": "DNS_QUERY",
        "severity": "LOW",
        "message": "Query sentinel.org"
    })
    client.post("/api/v1/logs", json={
        "source_ip": "2.2.2.2",
        "event_type": "AUTHENTICATION_FAILED",
        "severity": "HIGH",
        "message": "Login failed"
    })

    # Severity filter
    res_sev = client.get("/api/v1/logs?severity=HIGH")
    assert res_sev.status_code == status.HTTP_200_OK
    items = res_sev.json()
    assert len(items) >= 1
    assert all(item["severity"] == "HIGH" for item in items)

    # Search filter
    res_search = client.get("/api/v1/logs?search=sentinel.org")
    assert res_search.status_code == status.HTTP_200_OK
    assert len(res_search.json()) >= 1

    # Single log lookup
    first_id = items[0]["id"]
    res_single = client.get(f"/api/v1/logs/{first_id}")
    assert res_single.status_code == status.HTTP_200_OK
    assert res_single.json()["id"] == first_id

    # 404 on invalid ID
    res_404 = client.get("/api/v1/logs/999999")
    assert res_404.status_code == status.HTTP_404_NOT_FOUND


def test_simulation_scenarios_and_alert_triage(client):
    # 1. Trigger Brute Force simulation
    sim_payload = {
        "scenario": "BRUTE_FORCE",
        "count": 6,
        "source_ip": "198.51.100.77"
    }
    res_sim = client.post("/api/v1/simulator/run", json=sim_payload)
    assert res_sim.status_code == status.HTTP_200_OK
    sim_data = res_sim.json()
    assert sim_data["scenario"] == "BRUTE_FORCE"
    assert sim_data["logs_generated"] == 6
    assert sim_data["alerts_triggered"] >= 1

    # 2. Trigger DDoS Aggregate simulation
    res_ddos = client.post("/api/v1/simulator/run", json={"scenario": "DDOS_ATTACK", "count": 22})
    assert res_ddos.status_code == status.HTTP_200_OK
    ddos_data = res_ddos.json()
    assert ddos_data["alerts_triggered"] >= 1

    # 3. Fetch alerts list
    res_alerts = client.get("/api/v1/alerts")
    assert res_alerts.status_code == status.HTTP_200_OK
    alerts = res_alerts.json()
    assert len(alerts) >= 1

    alert_id = alerts[0]["id"]
    assert alerts[0]["status"] == "NEW"

    # 4. Triage: update to INVESTIGATING
    res_inv = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "INVESTIGATING"})
    assert res_inv.status_code == status.HTTP_200_OK
    assert res_inv.json()["status"] == "INVESTIGATING"

    # 5. Triage: update to RESOLVED
    res_res = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "RESOLVED"})
    assert res_res.status_code == status.HTTP_200_OK
    assert res_res.json()["status"] == "RESOLVED"

    # 6. Triage: invalid status rejection (400)
    res_bad = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "INVALID_STATUS"})
    assert res_bad.status_code == status.HTTP_400_BAD_REQUEST

    # 7. Alert 404
    res_alert_404 = client.get("/api/v1/alerts/999999")
    assert res_alert_404.status_code == status.HTTP_404_NOT_FOUND


def test_attack_simulation_scenarios(client):
    # 1. Port scan
    res = client.post("/api/v1/simulator/run", json={"scenario": "PORT_SCAN", "count": 6})
    assert res.status_code == status.HTTP_200_OK
    assert res.json()["scenario"] == "PORT_SCAN"

    # 2. Successful Root Login
    res = client.post("/api/v1/simulator/run", json={"scenario": "SUCCESSFUL_ROOT_LOGIN", "count": 1})
    assert res.status_code == status.HTTP_200_OK
    assert res.json()["alerts_triggered"] >= 1

    # 3. Failed Root Login (must NOT trigger critical root incident)
    res = client.post("/api/v1/simulator/run", json={"scenario": "FAILED_ROOT_LOGIN", "count": 1})
    assert res.status_code == status.HTTP_200_OK
    alerts = res.json()["new_alerts"]
    assert not any(a["rule_id"] == "RULE-AUTH-ROOT-LOGIN" for a in alerts)

    # 4. Anomalous Spike
    res = client.post("/api/v1/simulator/run", json={"scenario": "ANOMALOUS_SPIKE", "count": 22})
    assert res.status_code == status.HTTP_200_OK

    # 5. Mixed Traffic
    res = client.post("/api/v1/simulator/run", json={"scenario": "MIXED", "count": 10})
    assert res.status_code == status.HTTP_200_OK

    # 6. Unknown scenario -> 400 Bad Request
    res = client.post("/api/v1/simulator/run", json={"scenario": "NON_EXISTENT_SCENARIO", "count": 5})
    assert res.status_code == status.HTTP_400_BAD_REQUEST


def test_normal_traffic_simulation(client, monkeypatch):
    # Standalone normal traffic test verifying zero alerts from the deterministic detection rules.
    # Disables ML detection so that statistical anomaly scoring on rapid synthetic bursts is excluded.
    from backend.app.core.config import settings
    from backend.app.detection.engine import detection_engine
    monkeypatch.setattr(settings, "ENABLE_ML_DETECTION", False)
    deterministic_rules = [r for r in detection_engine.rules if r.id != "RULE-ML-ANOMALY-IFOREST"]
    monkeypatch.setattr(detection_engine, "rules", deterministic_rules)

    res = client.post("/api/v1/simulator/run", json={"scenario": "NORMAL_TRAFFIC", "count": 5})
    assert res.status_code == status.HTTP_200_OK
    assert res.json()["scenario"] == "NORMAL_TRAFFIC"
    assert res.json()["alerts_triggered"] == 0


def test_dashboard_stats(client):
    res = client.get("/api/v1/stats")
    assert res.status_code == status.HTTP_200_OK
    stats = res.json()
    # Original V1.0 keys
    assert "total_logs" in stats
    assert "total_alerts" in stats
    assert "critical_alerts" in stats
    assert "active_alerts" in stats
    assert "resolved_alerts" in stats
    assert "severity_breakdown" in stats
    assert "timeline" in stats
    assert "top_attackers" in stats

    # New V1.5 Step 4A statistics keys
    assert "ml_alerts" in stats
    assert "rule_alerts" in stats
    assert "active_ml_alerts" in stats
    assert "resolved_ml_alerts" in stats
    assert len(stats["timeline"]) == 6
    for point in stats["timeline"]:
        assert "rule_alert_count" in point
        assert "ml_alert_count" in point


def test_dashboard_ml_and_rule_statistics_aggregation(client, db_session):
    """
    Validates V1.5 dashboard statistics aggregation across deterministic rules and ML anomalies:
    1. Zero metrics on empty database.
    2. ML anomaly alert count (RULE-ML-ANOMALY-IFOREST).
    3. Deterministic alert count (exact 5 known rule IDs).
    4. Active ML count (NEW + INVESTIGATING).
    5. Resolved ML count (RESOLVED only; FALSE_POSITIVE excluded).
    6. Non-classification of unknown rule IDs as deterministic.
    7. Timeline separation of rule vs ML alert counts.
    """
    from datetime import datetime, timezone, timedelta
    from backend.app.models.alert import Alert

    # 1. Empty database verification
    res_empty = client.get("/api/v1/stats")
    assert res_empty.status_code == status.HTTP_200_OK
    empty_stats = res_empty.json()
    assert empty_stats["total_alerts"] == 0
    assert empty_stats["ml_alerts"] == 0
    assert empty_stats["rule_alerts"] == 0
    assert empty_stats["active_ml_alerts"] == 0
    assert empty_stats["resolved_ml_alerts"] == 0
    for pt in empty_stats["timeline"]:
        assert pt["alert_count"] == 0
        assert pt["rule_alert_count"] == 0
        assert pt["ml_alert_count"] == 0

    # 2. Seed database with controlled alerts
    now = datetime.now(timezone.utc)

    # 5 Deterministic alerts across the 5 known IDs
    det_alerts = [
        Alert(rule_id="RULE-AUTH-BRUTEFORCE", title="Brute Force", description="d1", severity="HIGH", status="NEW", source_ip="10.0.0.1", created_at=now - timedelta(minutes=2)),
        Alert(rule_id="RULE-NET-PORTSCAN", title="Port Scan", description="d2", severity="MEDIUM", status="INVESTIGATING", source_ip="10.0.0.2", created_at=now - timedelta(minutes=3)),
        Alert(rule_id="RULE-AUTH-ROOT-LOGIN", title="Root Login", description="d3", severity="CRITICAL", status="RESOLVED", source_ip="10.0.0.3", created_at=now - timedelta(minutes=15)),
        Alert(rule_id="RULE-NET-DDOS-AGGREGATE", title="DDoS", description="d4", severity="CRITICAL", status="NEW", source_ip="10.0.0.4", created_at=now - timedelta(minutes=4)),
        Alert(rule_id="RULE-ANOMALOUS-SPIKE", title="Spike", description="d5", severity="HIGH", status="RESOLVED", source_ip="10.0.0.5", created_at=now - timedelta(minutes=25)),
    ]
    for a in det_alerts:
        db_session.add(a)

    # 6 ML Anomaly alerts (with varying statuses)
    ml_alerts_data = [
        # Active ML (NEW)
        Alert(rule_id="RULE-ML-ANOMALY-IFOREST", title="ML 1", description="m1", severity="MEDIUM", status="NEW", source_ip="10.1.0.1", created_at=now - timedelta(minutes=1)),
        Alert(rule_id="RULE-ML-ANOMALY-IFOREST", title="ML 2", description="m2", severity="MEDIUM", status="NEW", source_ip="10.1.0.2", created_at=now - timedelta(minutes=2)),
        # Active ML (INVESTIGATING)
        Alert(rule_id="RULE-ML-ANOMALY-IFOREST", title="ML 3", description="m3", severity="MEDIUM", status="INVESTIGATING", source_ip="10.1.0.3", created_at=now - timedelta(minutes=3)),
        # Resolved ML (RESOLVED)
        Alert(rule_id="RULE-ML-ANOMALY-IFOREST", title="ML 4", description="m4", severity="MEDIUM", status="RESOLVED", source_ip="10.1.0.4", created_at=now - timedelta(minutes=14)),
        Alert(rule_id="RULE-ML-ANOMALY-IFOREST", title="ML 5", description="m5", severity="MEDIUM", status="RESOLVED", source_ip="10.1.0.5", created_at=now - timedelta(minutes=24)),
        # False Positive ML (Must NOT be counted in resolved_ml_alerts)
        Alert(rule_id="RULE-ML-ANOMALY-IFOREST", title="ML 6", description="m6", severity="MEDIUM", status="FALSE_POSITIVE", source_ip="10.1.0.6", created_at=now - timedelta(minutes=4)),
    ]
    for a in ml_alerts_data:
        db_session.add(a)

    # 1 Unknown custom rule ID (must NOT be counted in rule_alerts or ml_alerts)
    unknown_alert = Alert(
        rule_id="RULE-CUSTOM-UNKNOWN",
        title="Unknown Rule Alert",
        description="u1",
        severity="LOW",
        status="NEW",
        source_ip="10.99.0.1",
        created_at=now - timedelta(minutes=2)
    )
    db_session.add(unknown_alert)
    db_session.commit()

    # 3. Retrieve and assert metrics
    res = client.get("/api/v1/stats")
    assert res.status_code == status.HTTP_200_OK
    stats = res.json()

    # Total database alerts = 5 det + 6 ML + 1 unknown = 12
    assert stats["total_alerts"] == 12

    # Deterministic alerts = 5 (exact 5 known IDs only; unknown rule is excluded)
    assert stats["rule_alerts"] == 5

    # ML alerts = 6
    assert stats["ml_alerts"] == 6

    # Active ML alerts = 3 (2 NEW + 1 INVESTIGATING)
    assert stats["active_ml_alerts"] == 3

    # Resolved ML alerts = 2 (RESOLVED only; FALSE_POSITIVE excluded)
    assert stats["resolved_ml_alerts"] == 2

    # 4. Timeline validation
    timeline = stats["timeline"]
    assert len(timeline) == 6

    total_timeline_alerts = sum(pt["alert_count"] for pt in timeline)
    total_timeline_rule_alerts = sum(pt["rule_alert_count"] for pt in timeline)
    total_timeline_ml_alerts = sum(pt["ml_alert_count"] for pt in timeline)

    # In our seed, all 12 alerts were created within the last 30 minutes (within the 60-min window)
    assert total_timeline_alerts == 12
    assert total_timeline_rule_alerts == 5
    assert total_timeline_ml_alerts == 6

    # Total timeline alerts equals rule + ml + 1 (unknown alert)
    assert total_timeline_alerts == total_timeline_rule_alerts + total_timeline_ml_alerts + 1


def test_alert_engine_filtering_and_pagination(client, db_session):
    from datetime import datetime, timezone, timedelta
    from backend.app.models.alert import Alert

    # 1. Invalid engine parameter -> 422 Unprocessable Entity
    assert client.get("/api/v1/alerts?engine=INVALID").status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert client.get("/api/v1/alerts?engine=UNKNOWN").status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert client.get("/api/v1/alerts?engine=").status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # 2. Seed database with deterministic and ML alerts
    now = datetime.now(timezone.utc)

    # 5 deterministic alerts
    for i in range(5):
        db_session.add(Alert(
            rule_id="RULE-AUTH-BRUTEFORCE",
            title="Brute Force Detected",
            description=f"Deterministic attack attempt {i}",
            severity="HIGH",
            source_ip=f"192.168.1.{10+i}",
            destination_ip="10.0.0.1",
            status="NEW" if i < 3 else "INVESTIGATING",
            trigger_count=i + 1,
            created_at=now - timedelta(minutes=i * 2),
            updated_at=now - timedelta(minutes=i * 2)
        ))

    # 5 ML anomaly alerts
    for i in range(5):
        db_session.add(Alert(
            rule_id="RULE-ML-ANOMALY-IFOREST",
            title="ML Anomaly Detected",
            description=f"[ML Anomaly Detection] Statistical anomaly {i}. Metrics: Normalized Anomaly Score = 0.7500 | Raw Score = -0.0250 (Decision Cutoff: -0.0200). Window Telemetry (60s): 10 total events",
            severity="MEDIUM",
            source_ip=f"10.200.0.{10+i}",
            destination_ip=None,
            status="NEW" if i < 4 else "RESOLVED",
            trigger_count=10,
            created_at=now - timedelta(minutes=i * 2 + 1),
            updated_at=now - timedelta(minutes=i * 2 + 1)
        ))
    db_session.commit()

    # 3. All Engines backward compatibility (omitted engine returns all 10)
    res_all = client.get("/api/v1/alerts?limit=50")
    assert res_all.status_code == status.HTTP_200_OK
    assert len(res_all.json()) == 10

    # 4. Engine filtering: ML only
    res_ml = client.get("/api/v1/alerts?engine=ML&limit=50")
    assert res_ml.status_code == status.HTTP_200_OK
    ml_alerts = res_ml.json()
    assert len(ml_alerts) == 5
    assert all(a["rule_id"] == "RULE-ML-ANOMALY-IFOREST" for a in ml_alerts)

    # 5. Engine filtering: RULE only
    res_rule = client.get("/api/v1/alerts?engine=RULE&limit=50")
    assert res_rule.status_code == status.HTTP_200_OK
    rule_alerts = res_rule.json()
    assert len(rule_alerts) == 5
    assert all(a["rule_id"] != "RULE-ML-ANOMALY-IFOREST" for a in rule_alerts)

    # 6. Engine filtering combined with custom search (SQL AND logic)
    res_search_ml = client.get("/api/v1/alerts?engine=ML&search=10.200.0.10")
    assert res_search_ml.status_code == status.HTTP_200_OK
    assert len(res_search_ml.json()) == 1
    assert res_search_ml.json()[0]["source_ip"] == "10.200.0.10"

    res_search_mismatch = client.get("/api/v1/alerts?engine=RULE&search=10.200.0.10")
    assert res_search_mismatch.status_code == status.HTTP_200_OK
    assert len(res_search_mismatch.json()) == 0

    # 7. Engine filtering combined with severity and status
    res_comb_ml = client.get("/api/v1/alerts?engine=ML&severity=MEDIUM&status=NEW")
    assert res_comb_ml.status_code == status.HTTP_200_OK
    assert len(res_comb_ml.json()) == 4

    res_comb_rule = client.get("/api/v1/alerts?engine=RULE&severity=HIGH&status=INVESTIGATING")
    assert res_comb_rule.status_code == status.HTTP_200_OK
    assert len(res_comb_rule.json()) == 2

    # 8. Pagination after engine filtering
    res_p1 = client.get("/api/v1/alerts?engine=RULE&skip=0&limit=3")
    assert res_p1.status_code == status.HTTP_200_OK
    assert len(res_p1.json()) == 3

    res_p2 = client.get("/api/v1/alerts?engine=RULE&skip=3&limit=3")
    assert res_p2.status_code == status.HTTP_200_OK
    assert len(res_p2.json()) == 2
