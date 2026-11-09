import React, { useState, useEffect } from 'react';
import {
  Terminal,
  Search,
  Filter,
  RefreshCw,
  Pause,
  Play,
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  AlertCircle
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import { apiService } from '../services/api';

export default function LogsPage() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState('');
  const [expandedLogId, setExpandedLogId] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);

  // Pagination state
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const loadLogs = async () => {
    try {
      setLoading(true);
      setErrorMessage(null);
      const data = await apiService.getLogs({
        skip: (page - 1) * pageSize,
        limit: pageSize,
        search: searchTerm,
        severity: severityFilter,
        event_type: eventTypeFilter
      });
      setLogs(data);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to load telemetry logs from backend.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, [page, pageSize, severityFilter, eventTypeFilter]);

  // Periodic polling for live stream if autoRefresh is active
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      loadLogs();
    }, 5000);
    return () => clearInterval(interval);
  }, [autoRefresh, page, pageSize, searchTerm, severityFilter, eventTypeFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    loadLogs();
  };

  const handleFilterChange = (setter, value) => {
    setter(value);
    setPage(1);
  };

  return (
    <div className="space-y-6">
      {/* Title & Stream Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Terminal className="w-6 h-6 text-cyan-400" />
            Security Telemetry & Live Event Log
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time feed of network traffic, authentication attempts, and endpoint security telemetry.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition ${
              autoRefresh
                ? 'bg-emerald-950/40 text-emerald-300 border-emerald-800'
                : 'bg-slate-900 text-slate-400 border-slate-700 hover:text-white'
            }`}
          >
            {autoRefresh ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{autoRefresh ? 'Live Polling (5s)' : 'Polling Paused'}</span>
          </button>

          <button
            onClick={loadLogs}
            disabled={loading}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 hover:text-white hover:border-slate-500"
            title="Refresh Now"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>

      {errorMessage && (
        <div className="p-3.5 rounded-lg bg-red-950/60 border border-red-800 text-red-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{errorMessage}</span>
          <button onClick={loadLogs} className="ml-auto underline hover:text-white">Retry</button>
        </div>
      )}

      {/* Filter & Search Bar */}
      <div className="p-4 rounded-xl border border-slate-800 bg-[#0c101a] flex flex-wrap items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="flex-1 min-w-[240px] relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search logs by message, IP, user..."
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
              value={severityFilter}
              onChange={(e) => handleFilterChange(setSeverityFilter, e.target.value)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </select>
          </div>

          {/* Event Type Filter */}
          <div className="flex items-center space-x-1.5">
            <span className="text-xs text-slate-400">Event Type:</span>
            <select
              value={eventTypeFilter}
              onChange={(e) => handleFilterChange(setEventTypeFilter, e.target.value)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Events</option>
              <option value="AUTHENTICATION_FAILED">Auth Failed</option>
              <option value="AUTHENTICATION_SUCCESS">Auth Success</option>
              <option value="PORT_SCAN_PROBE">Port Probe</option>
              <option value="HTTP_REQUEST">HTTP Request</option>
              <option value="HTTP_FLOOD_PROBE">HTTP Flood</option>
              <option value="DNS_QUERY">DNS Query</option>
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

      {/* Logs Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0c101a] overflow-hidden">
        {loading && logs.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-400">
            <RefreshCw className="w-5 h-5 mx-auto mb-2 animate-spin text-cyan-400" />
            Connecting to security telemetry feed...
          </div>
        ) : logs.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-500">
            No telemetry records found. Run the Simulation Centre to inject test traffic.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase tracking-wider font-semibold">
                  <th className="py-3 px-4">Time (UTC)</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Event Type</th>
                  <th className="py-3 px-4">Protocol</th>
                  <th className="py-3 px-4">Source IP</th>
                  <th className="py-3 px-4">Destination</th>
                  <th className="py-3 px-4">User</th>
                  <th className="py-3 px-4">Message</th>
                  <th className="py-3 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {logs.map((log) => {
                  const isExpanded = expandedLogId === log.id;
                  const formattedTime = new Date(log.timestamp).toISOString().replace('T', ' ').substring(0, 19);

                  return (
                    <React.Fragment key={log.id}>
                      <tr className="hover:bg-slate-900/40 transition font-mono text-[11px]">
                        <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">{formattedTime}</td>
                        <td className="py-2.5 px-4">
                          <SeverityBadge severity={log.severity} />
                        </td>
                        <td className="py-2.5 px-4 text-cyan-300 font-semibold">{log.event_type}</td>
                        <td className="py-2.5 px-4 text-slate-400">{log.protocol}</td>
                        <td className="py-2.5 px-4 text-slate-300 font-semibold">{log.source_ip}</td>
                        <td className="py-2.5 px-4 text-slate-400">
                          {log.destination_ip ? `${log.destination_ip}:${log.destination_port || '-'}` : '—'}
                        </td>
                        <td className="py-2.5 px-4 text-slate-400">{log.user || '—'}</td>
                        <td className="py-2.5 px-4 text-slate-300 font-sans max-w-[260px] truncate" title={log.message}>
                          {log.message}
                        </td>
                        <td className="py-2.5 px-4 text-right">
                          <button
                            onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                            className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                            title="Inspect Raw Event"
                          >
                            {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                          </button>
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr className="bg-slate-950/90 font-mono text-[11px]">
                          <td colSpan="9" className="p-4 border-t border-slate-800 space-y-2">
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-slate-400 bg-slate-900/60 p-2.5 rounded border border-slate-800">
                              <div><span className="text-slate-500">Record ID:</span> #{log.id}</div>
                              <div><span className="text-slate-500">Source Port:</span> {log.source_port || '—'}</div>
                              <div><span className="text-slate-500">Dest Port:</span> {log.destination_port || '—'}</div>
                              <div><span className="text-slate-500">Protocol:</span> {log.protocol}</div>
                            </div>

                            <div className="text-slate-300">
                              <span className="text-slate-500 block mb-0.5 font-semibold">Full Message:</span>
                              <div className="p-2 rounded bg-slate-900/40 border border-slate-800 font-sans text-xs">
                                {log.message}
                              </div>
                            </div>

                            {log.raw_data && (
                              <div>
                                <span className="text-slate-500 block mb-0.5 font-semibold">JSON Raw Payload:</span>
                                <div className="bg-black/60 p-2.5 rounded border border-slate-800 overflow-x-auto text-emerald-400 text-xs">
                                  <pre>{JSON.stringify(JSON.parse(log.raw_data), null, 2)}</pre>
                                </div>
                              </div>
                            )}
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
            Showing <strong className="text-slate-200">{logs.length}</strong> events on page <strong className="text-slate-200">{page}</strong>
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
              disabled={logs.length < pageSize}
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
