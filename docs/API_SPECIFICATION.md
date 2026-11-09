# Sentinel AI V1.0 — REST API Specification

**Base URL**: `http://127.0.0.1:8000/api/v1`

---

## 1. General & Health Endpoints

### `GET /`
Returns service status, version, and documentation link.

*Response (200 OK)*:
```json
{
  "service": "Sentinel AI",
  "version": "1.0.0",
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
  "version": "1.0.0",
  "database": "connected"
}
```

---

## 2. Telemetry Log Ingestion & Retrieval

### `POST /api/v1/logs`
Ingests a single security log, stores it in SQLite, and evaluates it through the active detection engine rules.

*Request Body*:
```json
{
  "timestamp": "2026-11-09T17:00:00Z",
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
    "timestamp": "2026-11-09T17:00:00Z",
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
    "created_at": "2026-11-09T17:00:00.123456Z"
  },
  "alerts_triggered": []
}
```

### `POST /api/v1/logs/batch`
Ingests an array of security logs and evaluates each in order.

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
Retrieves threat incidents raised by detection rules.

*Query Parameters*:
- `skip` (integer, default: 0)
- `limit` (integer, default: 50, max: 200)
- `severity` (string, optional): `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- `status` (string, optional): `NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`
- `search` (string, optional): Substring search across title, description, rule ID, or source IP.

*Response (200 OK)*:
```json
[
  {
    "id": 1,
    "rule_id": "RULE-AUTH-BRUTEFORCE",
    "title": "Authentication Brute Force Detected",
    "description": "Potential brute force attack: 5 failed login attempts from IP 198.51.100.42.",
    "severity": "HIGH",
    "status": "NEW",
    "source_ip": "198.51.100.42",
    "destination_ip": "10.0.0.5",
    "target_user": "root",
    "trigger_count": 5,
    "created_at": "2026-11-09T17:00:05Z",
    "updated_at": "2026-11-09T17:00:05Z"
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
Returns aggregated security telemetry metrics for real-time visualization.

*Response (200 OK)*:
```json
{
  "total_logs": 142,
  "total_alerts": 8,
  "critical_alerts": 2,
  "active_alerts": 5,
  "resolved_alerts": 3,
  "severity_breakdown": [
    { "severity": "CRITICAL", "count": 2 },
    { "severity": "HIGH", "count": 3 },
    { "severity": "MEDIUM", "count": 2 },
    { "severity": "LOW", "count": 1 }
  ],
  "timeline": [
    { "time_label": "16:40", "event_count": 12, "alert_count": 0 },
    { "time_label": "16:50", "event_count": 45, "alert_count": 3 }
  ],
  "top_attackers": [
    { "ip": "198.51.100.42", "event_count": 28, "alert_count": 2 }
  ]
}
```

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
- `BRUTE_FORCE`: Sequential failed SSH logins ($\ge 5 \to$ High Alert).
- `PORT_SCAN`: Multi-port reconnaissance probes ($\ge 5 \to$ Medium Alert).
- `SUCCESSFUL_ROOT_LOGIN`: Direct remote root login ($\to$ Critical Alert).
- `FAILED_ROOT_LOGIN`: Isolated failed root password attempt ($\to$ Telemetry only, no critical alert).
- `DDOS_ATTACK`: Aggregate multi-source HTTP flood ($\ge 20$ events across $\ge 3$ IPs $\to$ Critical Alert).
- `ANOMALOUS_SPIKE`: Volumetric single-source traffic burst ($\ge 20 \to$ Medium Alert).
- `NORMAL_TRAFFIC`: Benign background operations (HTTP 200, DNS lookups, authorized logins $\to$ 0 alerts).
- `MIXED`: Blended background traffic + brute force attack.

*Response (200 OK)*:
```json
{
  "status": "SUCCESS",
  "scenario": "BRUTE_FORCE",
  "logs_generated": 6,
  "alerts_triggered": 1,
  "new_alerts": [ ... ]
}
```

