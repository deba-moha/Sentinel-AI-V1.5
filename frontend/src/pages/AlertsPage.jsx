import React, { useState, useEffect } from 'react';
import {
  AlertOctagon,
  Search,
  Filter,
  CheckCircle,
  AlertCircle,
  Clock,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  ShieldAlert
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import { apiService } from '../services/api';

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedSeverity, setSelectedSeverity] = useState('');
  const [selectedStatus, setSelectedStatus] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const [updatingId, setUpdatingId] = useState(null);
  const [feedback, setFeedback] = useState(null);

  // Pagination state
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const loadAlerts = async () => {
    try {
      setLoading(true);
      const data = await apiService.getAlerts({
        skip: (page - 1) * pageSize,
        limit: pageSize,
        severity: selectedSeverity,
        status: selectedStatus,
        search: searchTerm
      });
      setAlerts(data);
    } catch (err) {
      setFeedback({ type: 'error', message: err.message || 'Failed to fetch threat alerts.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [page, pageSize, selectedSeverity, selectedStatus]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    loadAlerts();
  };

  const handleUpdateStatus = async (alertId, newStatus) => {
    try {
      setUpdatingId(alertId);
      const updated = await apiService.updateAlertStatus(alertId, newStatus);
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? updated : a))
      );
      setFeedback({
        type: 'success',
        message: `Alert #${alertId} status successfully transitioned to ${newStatus}.`
      });
      setTimeout(() => setFeedback(null), 4000);
    } catch (err) {
      setFeedback({
        type: 'error',
        message: `Error updating Alert #${alertId}: ${err.message}`
      });
    } finally {
      setUpdatingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Title & Refresh */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <AlertOctagon className="w-6 h-6 text-red-500" />
            Threat Alert Investigation & Triage Centre
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Review security incidents detected by deterministic rules, inspect incident payloads, and manage triage lifecycles.
          </p>
        </div>
        <button
          onClick={loadAlerts}
          disabled={loading}
          className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 hover:text-white text-xs font-medium"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Refresh Feed</span>
        </button>
      </div>

      {/* Success / Error Feedback Banner */}
      {feedback && (
        <div
          className={`p-3.5 rounded-lg border text-xs flex items-center justify-between transition-all ${
            feedback.type === 'success'
              ? 'bg-emerald-950/60 border-emerald-700 text-emerald-300'
              : 'bg-red-950/60 border-red-800 text-red-300'
          }`}
        >
          <div className="flex items-center gap-2">
            {feedback.type === 'success' ? (
              <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            )}
            <span>{feedback.message}</span>
          </div>
          <button onClick={() => setFeedback(null)} className="underline hover:text-white ml-2">Dismiss</button>
        </div>
      )}

      {/* Filter & Search Bar */}
      <div className="p-4 rounded-xl border border-slate-800 bg-[#0c101a] flex flex-wrap items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="flex-1 min-w-[240px] relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search alerts by IP, title, rule ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </form>

        <div className="flex flex-wrap items-center gap-3">
          {/* Severity Filter */}
          <div className="flex items-center space-x-1.5">
            <span className="text-xs text-slate-400">Severity:</span>
            <select
              value={selectedSeverity}
              onChange={(e) => {
                setSelectedSeverity(e.target.value);
                setPage(1);
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Status Filter */}
          <div className="flex items-center space-x-1.5">
            <span className="text-xs text-slate-400">Status:</span>
            <select
              value={selectedStatus}
              onChange={(e) => {
                setSelectedStatus(e.target.value);
                setPage(1);
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Statuses</option>
              <option value="NEW">New</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="RESOLVED">Resolved</option>
              <option value="FALSE_POSITIVE">False Positive</option>
            </select>
          </div>

          {/* Page Size */}
          <div className="flex items-center space-x-1.5">
            <span className="text-xs text-slate-400">Rows:</span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setPage(1);
              }}
              className="px-2 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="25">25</option>
              <option value="50">50</option>
              <option value="100">100</option>
            </select>
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0c101a] overflow-hidden">
        {loading && alerts.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-400">
            <RefreshCw className="w-5 h-5 mx-auto mb-2 animate-spin text-cyan-400" />
            Loading threat alerts...
          </div>
        ) : alerts.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-500">
            No threat alerts matched the current criteria. Run the Simulation Centre to inject test attack traffic.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase tracking-wider font-semibold">
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Incident / Rule</th>
                  <th className="py-3 px-4">Source Origin</th>
                  <th className="py-3 px-4">Target Destination</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-center">Hits</th>
                  <th className="py-3 px-4">Last Updated</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {alerts.map((alert) => {
                  const isExpanded = expandedId === alert.id;
                  const isBusy = updatingId === alert.id;
                  const updatedFormatted = new Date(alert.updated_at).toLocaleString();

                  return (
                    <React.Fragment key={alert.id}>
                      <tr className="hover:bg-slate-900/40 transition">
                        <td className="py-3 px-4">
                          <SeverityBadge severity={alert.severity} />
                        </td>
                        <td className="py-3 px-4">
                          <div className="font-medium text-slate-200">{alert.title}</div>
                          <div className="text-[11px] font-mono text-slate-500 mt-0.5">{alert.rule_id}</div>
                        </td>
                        <td className="py-3 px-4 font-mono text-cyan-300 font-semibold">{alert.source_ip}</td>
                        <td className="py-3 px-4 font-mono text-slate-400">{alert.destination_ip || 'Internal / Any'}</td>
                        <td className="py-3 px-4">
                          <StatusBadge status={alert.status} />
                        </td>
                        <td className="py-3 px-4 text-center font-mono font-bold text-slate-200">
                          {alert.trigger_count}x
                        </td>
                        <td className="py-3 px-4 text-slate-400 text-[11px] whitespace-nowrap">
                          {updatedFormatted}
                        </td>
                        <td className="py-3 px-4 text-right space-x-1.5">
                          <button
                            onClick={() => setExpandedId(isExpanded ? null : alert.id)}
                            className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                            title="Inspect Details"
                          >
                            {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                          </button>
                        </td>
                      </tr>

                      {/* Expanded Details Row */}
                      {isExpanded && (
                        <tr className="bg-slate-900/30">
                          <td colSpan="8" className="p-4 border-t border-slate-800/80">
                            <div className="space-y-3">
                              <div className="text-xs text-slate-300 bg-slate-950 p-3 rounded-lg border border-slate-800">
                                <span className="text-slate-400 font-semibold uppercase tracking-wider block mb-1">
                                  Incident Description:
                                </span>
                                {alert.description}
                              </div>

                              <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
                                <div className="text-slate-400 space-x-4">
                                  <span>Target User: <strong className="text-slate-200 font-mono">{alert.target_user || 'None'}</strong></span>
                                  <span>Created: <strong className="text-slate-200">{new Date(alert.created_at).toLocaleString()}</strong></span>
                                  <span>Total Aggregated Hits: <strong className="text-cyan-300 font-mono">{alert.trigger_count}</strong></span>
                                </div>

                                <div className="flex items-center space-x-2">
                                  <span className="text-slate-400 font-medium">Triage Action:</span>
                                  {alert.status !== 'INVESTIGATING' && (
                                    <button
                                      disabled={isBusy}
                                      onClick={() => handleUpdateStatus(alert.id, 'INVESTIGATING')}
                                      className="px-2.5 py-1 rounded bg-amber-950 hover:bg-amber-900 text-amber-300 border border-amber-800 font-medium text-[11px] transition"
                                    >
                                      Mark Investigating
                                    </button>
                                  )}
                                  {alert.status !== 'RESOLVED' && (
                                    <button
                                      disabled={isBusy}
                                      onClick={() => handleUpdateStatus(alert.id, 'RESOLVED')}
                                      className="px-2.5 py-1 rounded bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800 font-medium text-[11px] transition"
                                    >
                                      Mark Resolved
                                    </button>
                                  )}
                                  {alert.status !== 'FALSE_POSITIVE' && (
                                    <button
                                      disabled={isBusy}
                                      onClick={() => handleUpdateStatus(alert.id, 'FALSE_POSITIVE')}
                                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 font-medium text-[11px] transition"
                                    >
                                      Mark False Positive
                                    </button>
                                  )}
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        <div className="p-3 bg-slate-900/40 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing <strong className="text-slate-200">{alerts.length}</strong> alerts on page <strong className="text-slate-200">{page}</strong>
          </div>
          <div className="flex items-center space-x-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage(page - 1)}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 flex items-center space-x-1"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
              <span>Previous</span>
            </button>
            <span className="px-2 font-mono text-cyan-400">Page {page}</span>
            <button
              disabled={alerts.length < pageSize}
              onClick={() => setPage(page + 1)}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 flex items-center space-x-1"
            >
              <span>Next</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
