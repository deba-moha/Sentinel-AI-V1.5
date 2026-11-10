/**
 * Sentinel AI - Centralized Frontend API Service
 * Communicates with FastAPI backend using configurable base URL and uniform error handling.
 */

const BASE_URL = import.meta.env.VITE_API_BASE_URL || '';
const API_BASE = `${BASE_URL}/api/v1`;

async function handleResponse(response) {
  if (!response.ok) {
    let errorMsg = `HTTP Error ${response.status}`;
    try {
      const errorJson = await response.json();
      errorMsg = errorJson.detail || errorMsg;
    } catch {
      // ignore JSON parse error on non-JSON body
    }
    throw new Error(errorMsg);
  }
  return response.json();
}

export const apiService = {
  async getHealth() {
    const res = await fetch(`${BASE_URL}/health`);
    return handleResponse(res);
  },

  async getDashboardStats() {
    const res = await fetch(`${API_BASE}/stats`);
    return handleResponse(res);
  },

  async getAlerts({ skip = 0, limit = 50, severity = '', status = '', search = '', engine = '' } = {}) {
    const params = new URLSearchParams();
    params.set('skip', skip.toString());
    params.set('limit', limit.toString());
    if (severity) params.set('severity', severity);
    if (status) params.set('status', status);
    if (search) params.set('search', search);
    if (engine) params.set('engine', engine);

    const res = await fetch(`${API_BASE}/alerts?${params.toString()}`);
    return handleResponse(res);
  },

  async updateAlertStatus(alertId, newStatus) {
    const res = await fetch(`${API_BASE}/alerts/${alertId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });
    return handleResponse(res);
  },

  async getLogs({ skip = 0, limit = 50, severity = '', event_type = '', search = '', source_ip = '' } = {}) {
    const params = new URLSearchParams();
    params.set('skip', skip.toString());
    params.set('limit', limit.toString());
    if (severity) params.set('severity', severity);
    if (event_type) params.set('event_type', event_type);
    if (source_ip) params.set('source_ip', source_ip);
    if (search) params.set('search', search);

    const res = await fetch(`${API_BASE}/logs?${params.toString()}`);
    return handleResponse(res);
  },

  async runSimulation({ scenario, count = 10, source_ip = null }) {
    const payload = { scenario, count };
    if (source_ip) payload.source_ip = source_ip;

    const res = await fetch(`${API_BASE}/simulator/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return handleResponse(res);
  }
};
