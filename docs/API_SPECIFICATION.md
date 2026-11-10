# Sentinel AI V1.5 — REST API Specification

**Base URL**: `http://127.0.0.1:8000/api/v1`

---

## 1. General & Health Endpoints

### `GET /`
Returns service status, version, and documentation link.

*Response (200 OK)*:
```json
{
  "service": "Sentinel AI",
  "version": "1.5.0",
  "status": "OPERATIONAL",
  "docs_url": "/docs"
}
```

### `GET /health`
Returns backend service health and SQLite connectivity.

*Response (200 OK)*:
```json
{
  "status": "healthy",
  "version": "1.5.0",
  "database": "connected"
}
```

---

## 2. Telemetry Log Ingestion & Retrieval

### `POST /api/v1/logs`
Ingests a single security log, stores it in SQLite, and evaluates it through the active hybrid detection engine (deterministic rules and unsupervised Isolation Forest).

*Request Body*:
```json
{
  "timestamp": "2026-11-10T08:00:00Z",
  "source_ip": "198.51.100.42",
  "destination_ip": "10.0.0.5",
  "source_port": 54210,
  "destination_port": 22,
  "protocol": "TCP",
  "event_type": "AUTHENTICATION_FAILED",
  "severity": "MEDIUM",
  "user": "root",
  "message": "Failed SSH password authentication for root from 198.51.100.42",
  "raw_data": { "attempt": 1 }
}
```

*Response (201 Created)*:
```json
{
  "log": {
    "id": 1,
    "timestamp": "2026-11-10T08:00:00Z",
    "source_ip": "198.51.100.42",
    "destination_ip": "10.0.0.5",
    "source_port": 54210,
    "destination_port": 22,
    "protocol": "TCP",
    "event_type": "AUTHENTICATION_FAILED",
    "severity": "MEDIUM",
    "user": "root",
    "message": "Failed SSH password authentication for root from 198.51.100.42",
    "raw_data": "{\"attempt\": 1}",
    "created_at": "2026-11-10T08:00:00.123456Z"
  },
  "alerts_triggered": []
}
```

### `POST /api/v1/logs/batch`
Ingests an array of security logs and evaluates each sequentially.

*Request Body*:
```json
{
  "logs": [
    { "source_ip": "10.0.0.1", "event_type": "HTTP_REQUEST", "message": "GET /api/v1/data" }
  ]
}
```

### `GET /api/v1/logs`
Retrieves stored security logs with filtering and pagination.

*Query Parameters*:
- `skip` (integer, default: 0): Offset for pagination.
- `limit` (integer, default: 50, max: 200): Maximum records to retrieve.
- `severity` (string, optional): Filter by `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- `event_type` (string, optional): Filter by event type (`AUTHENTICATION_FAILED`, `PORT_SCAN_PROBE`, etc.).
- `source_ip` (string, optional): Filter by specific source IP.
- `search` (string, optional): Substring search across message, source_ip, and user.

*Response (200 OK)*: Array of `LogResponse` objects.

### `GET /api/v1/logs/{log_id}`
Retrieves a single log by its integer ID. Returns `404 Not Found` if missing.

---

## 3. Threat Alert Management & Triage

### `GET /api/v1/alerts`
Retrieves threat incidents raised by the hybrid detection engine (deterministic rules and Isolation Forest anomaly detector).

*Query Parameters*:
- `skip` (integer, default: 0): Offset for pagination.
- `limit` (integer, default: 50, max: 200): Records to return.
- `severity` (string, optional): `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- `status` (string, optional): `NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`.
- `search` (string, optional): Substring search across title, description, rule ID, or source IP.
- `engine` (string, optional): Filter by detection engine:
  - `"ML"`: Retrieves strictly Machine Learning anomaly incidents (`rule_id == "RULE-ML-ANOMALY-IFOREST"`).
  - `"RULE"`: Retrieves deterministic threat signature incidents (`rule_id != "RULE-ML-ANOMALY-IFOREST"`).
  - Omitted: Retrieves incidents across all engines.
  - *Note*: Any invalid non-empty string returns `422 Unprocessable Entity`.

*Response (200 OK)*:
```json
[
  {
    "id": 1,
    "rule_id": "RULE-AUTH-BRUTEFORCE",
    "title": "Authentication Brute Force Detected",
    "description": "Observed 5+ failed login attempts from a single IP within 60s.",
    "severity": "HIGH",
    "status": "NEW",
    "source_ip": "198.51.100.42",
    "destination_ip": "10.0.0.5",
    "target_user": "root",
    "trigger_count": 5,
    "created_at": "2026-11-10T08:00:05Z",
    "updated_at": "2026-11-10T08:00:05Z"
  },
  {
    "id": 2,
    "rule_id": "RULE-ML-ANOMALY-IFOREST",
    "title": "Machine Learning Anomaly Detected",
    "description": "[ML Anomaly Detection] Observed statistical deviation in security telemetry over 60s observation window. Model Version: Isolation Forest v1.5.0. Raw Score = -0.0412 (Decision Cutoff: -0.0200). Normalized Anomaly Score = 0.8240. Extracted Features: 12 total events, 6 failed auths, 1 unique source IPs, 1 unique dest IPs, 1 unique dest ports, 0.20 req/s, 5.00s avg time interval, 4480.0 bytes volume.",
    "severity": "MEDIUM",
    "status": "NEW",
    "source_ip": "198.51.100.42",
    "destination_ip": "10.0.0.5",
    "target_user": null,
    "trigger_count": 12,
    "created_at": "2026-11-10T08:00:05Z",
    "updated_at": "2026-11-10T08:00:05Z"
  }
]
```

### `GET /api/v1/alerts/{alert_id}`
Retrieves details of a specific alert by ID. Returns `404 Not Found` if missing.

### `PATCH /api/v1/alerts/{alert_id}/status`
Updates the investigation/triage status of an alert.

*Request Body*:
```json
{
  "status": "INVESTIGATING"
}
```
*Allowed Statuses*: `NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`.  
*Response Codes*: `200 OK` (updated), `400 Bad Request` (invalid status), `404 Not Found`.

---

## 4. Dashboard Statistics

### `GET /api/v1/stats`
Returns aggregated security telemetry metrics for real-time visualization, including engine-specific breakdowns.

*Response (200 OK)*:
```json
{
  "total_logs": 142,
  "total_alerts": 8,
  "critical_alerts": 2,
  "active_alerts": 5,
  "resolved_alerts": 3,
  "ml_alerts": 3,
  "rule_alerts": 5,
  "active_ml_alerts": 2,
  "resolved_ml_alerts": 1,
  "severity_breakdown": [
    { "severity": "CRITICAL", "count": 2 },
    { "severity": "HIGH", "count": 3 },
    { "severity": "MEDIUM", "count": 3 },
    { "severity": "LOW", "count": 0 }
  ],
  "timeline": [
    {
      "time_label": "07:40",
      "event_count": 12,
      "alert_count": 1,
      "rule_alert_count": 1,
      "ml_alert_count": 0
    },
    {
      "time_label": "07:50",
      "event_count": 45,
      "alert_count": 4,
      "rule_alert_count": 2,
      "ml_alert_count": 2
    }
  ],
  "top_attackers": [
    { "ip": "198.51.100.42", "event_count": 28, "alert_count": 2 }
  ]
}
```

*Response Field Descriptions*:
- `total_logs`: Total security log records stored in the database.
- `total_alerts`: Total alert incident records.
- `critical_alerts`: Alerts with `CRITICAL` severity.
- `active_alerts`: Alerts with status `NEW` or `INVESTIGATING`.
- `resolved_alerts`: Alerts with status `RESOLVED`.
- `ml_alerts`: Total alerts generated by `RULE-ML-ANOMALY-IFOREST`.
- `rule_alerts`: Total alerts generated by the 5 deterministic rules.
- `active_ml_alerts`: ML anomaly alerts with status `NEW` or `INVESTIGATING`.
- `resolved_ml_alerts`: ML anomaly alerts with status `RESOLVED` (excluding `FALSE_POSITIVE`).
- `timeline`: Array of 6 10-minute intervals containing `event_count`, `alert_count`, `rule_alert_count`, and `ml_alert_count`.

---

## 5. Synthetic Attack Simulator

### `POST /api/v1/simulator/run`
Triggers simulated cyber-attack patterns or normal operational traffic directly in SQLite for demonstration without live network packets.

*Request Body*:
```json
{
  "scenario": "BRUTE_FORCE",
  "count": 6,
  "source_ip": "198.51.100.99"
}
```

*Supported Scenarios*:
- `BRUTE_FORCE`: Sequential failed SSH logins ($\ge 5 \to$ High Alert). High volume can trigger a concurrent ML anomaly alert.
- `PORT_SCAN`: Multi-port reconnaissance probes ($\ge 5 \to$ Medium Alert). Multi-port probe spread can trigger ML.
- `SUCCESSFUL_ROOT_LOGIN`: Direct remote root login ($\to$ Critical Alert).
- `FAILED_ROOT_LOGIN`: Isolated failed root password attempt ($\to$ Telemetry only, no critical alert).
- `DDOS_ATTACK`: Aggregate multi-source HTTP flood ($\ge 20$ events across $\ge 3$ IPs $\to$ Critical Alert + ML anomaly).
- `ANOMALOUS_SPIKE`: Volumetric single-source traffic burst ($\ge 20 \to$ Medium Alert + ML anomaly).
- `NORMAL_TRAFFIC`: Benign background operations (HTTP 200, DNS lookups, authorized logins $\to$ 0 alerts).
- `MIXED`: Blended background traffic + brute force attack.

*Response (200 OK)*:
```json
{
  "status": "SUCCESS",
  "scenario": "BRUTE_FORCE",
  "logs_generated": 6,
  "alerts_triggered": 2,
  "new_alerts": [
    {
      "id": 1,
      "rule_id": "RULE-AUTH-BRUTEFORCE",
      "title": "Authentication Brute Force Detected",
      "severity": "HIGH",
      "source_ip": "198.51.100.99"
    },
    {
      "id": 2,
      "rule_id": "RULE-ML-ANOMALY-IFOREST",
      "title": "Machine Learning Anomaly Detected",
      "severity": "MEDIUM",
      "source_ip": "198.51.100.99"
    }
  ]
}
```
