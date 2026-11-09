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


def test_normal_traffic_simulation(client):
    # Standalone normal traffic test with isolated session
    res = client.post("/api/v1/simulator/run", json={"scenario": "NORMAL_TRAFFIC", "count": 5})
    assert res.status_code == status.HTTP_200_OK
    assert res.json()["scenario"] == "NORMAL_TRAFFIC"
    assert res.json()["alerts_triggered"] == 0


def test_dashboard_stats(client):
    res = client.get("/api/v1/stats")
    assert res.status_code == status.HTTP_200_OK
    stats = res.json()
    assert "total_logs" in stats
    assert "total_alerts" in stats
    assert "critical_alerts" in stats
    assert "active_alerts" in stats
    assert "resolved_alerts" in stats
    assert "severity_breakdown" in stats
    assert "timeline" in stats
    assert "top_attackers" in stats
