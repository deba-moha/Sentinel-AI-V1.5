import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Activity,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  TrendingUp,
  Cpu,
  Radio,
  Layers
} from 'lucide-react';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Cell,
  Legend
} from 'recharts';
import StatCard from '../components/StatCard';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import DetectionBadge from '../components/DetectionBadge';
import { apiService } from '../services/api';

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#3b82f6',
};

export default function Dashboard({ setActiveTab }) {
  const [stats, setStats] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  const loadData = async (isManual = false) => {
    if (isManual) setRefreshing(true);
    try {
      setError(null);
      const [statsData, alertsData] = await Promise.all([
        apiService.getDashboardStats(),
        apiService.getAlerts({ limit: 5 })
      ]);
      setStats(statsData);
      setRecentAlerts(alertsData);
    } catch (err) {
      setError(err.message || 'Failed to fetch dashboard metrics.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(() => loadData(), 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="flex flex-col items-center space-y-3">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
          <span className="text-slate-400 text-sm">Initializing Sentinel AI telemetry stream...</span>
        </div>
      </div>
    );
  }

  // Calculate safe detection engine split percentages
  const totalEngineAlerts = (stats?.rule_alerts || 0) + (stats?.ml_alerts || 0);
  const rulePct = totalEngineAlerts > 0 ? Math.round(((stats?.rule_alerts || 0) / totalEngineAlerts) * 100) : 0;
  const mlPct = totalEngineAlerts > 0 ? Math.round(((stats?.ml_alerts || 0) / totalEngineAlerts) * 100) : 0;

  return (
    <div className="space-y-6">
      {/* Scope Disclaimer Banner */}
      <div className="p-3.5 rounded-lg bg-cyan-950/30 border border-cyan-800/50 flex items-start space-x-3 text-xs text-cyan-200">
        <Radio className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0 animate-pulse" />
        <div>
          <span className="font-semibold text-cyan-300">V1.5 Hybrid Operation:</span> Continuous security telemetry evaluated simultaneously by 5 deterministic threshold rules and unsupervised Isolation Forest statistical anomaly heuristics.
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-red-950/50 border border-red-800 text-red-300 text-sm flex items-center justify-between">
          <span>Error connecting to backend: {error}</span>
          <button onClick={() => loadData(true)} className="underline hover:text-white">Retry</button>
        </div>
      )}

      {/* Top Header & Refresh */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            Cyber Threat Operations Center
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time hybrid threat detection, telemetry monitoring, and incident triage feed.
          </p>
        </div>
        <button
          onClick={() => loadData(true)}
          disabled={refreshing}
          className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 hover:text-white hover:border-slate-500 text-xs font-medium transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Metric Cards Grid (5-column responsive layout) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
        <StatCard
          title="Total Ingested Logs"
          value={stats?.total_logs ?? 0}
          icon={Activity}
          alertColor="cyan"
          subtitle="Processed through pipeline"
        />
        <StatCard
          title="Active Threats"
          value={stats?.active_alerts ?? 0}
          icon={AlertTriangle}
          alertColor="amber"
          subtitle="New & investigating alerts"
        />
        <StatCard
          title="Critical Incidents"
          value={stats?.critical_alerts ?? 0}
          icon={ShieldAlert}
          alertColor="red"
          subtitle="Immediate action required"
        />
        <StatCard
          title="Resolved Threats"
          value={stats?.resolved_alerts ?? 0}
          icon={CheckCircle2}
          alertColor="emerald"
          subtitle="Triaged and mitigated"
        />
        <StatCard
          title="ML Anomalies"
          value={stats?.ml_alerts ?? 0}
          icon={Cpu}
          alertColor="purple"
          subtitle={`Active: ${stats?.active_ml_alerts ?? 0} | Resolved: ${stats?.resolved_ml_alerts ?? 0}`}
        />
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Area Chart */}
        <div className="lg:col-span-2 p-5 rounded-xl border border-slate-800 bg-[#0c101a] flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <div>
              <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-cyan-400" />
                Telemetry & Threat Surge Timeline
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Telemetry logs vs. rule alerts vs. ML anomaly alerts over the past 60 minutes
              </p>
            </div>
          </div>
          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats?.timeline || []} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
                <defs>
                  <linearGradient id="eventGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="ruleAlertGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.5} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="mlAlertGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#a855f7" stopOpacity={0.5} />
                    <stop offset="95%" stopColor="#a855f7" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="time_label" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#111726',
                    borderColor: '#1e293b',
                    borderRadius: '8px',
                    fontSize: '12px'
                  }}
                />
                <Legend
                  verticalAlign="top"
                  align="right"
                  iconType="circle"
                  wrapperStyle={{ paddingBottom: '12px', fontSize: '11px' }}
                />
                <Area
                  type="monotone"
                  dataKey="event_count"
                  name="Telemetry Logs"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#eventGrad)"
                />
                <Area
                  type="monotone"
                  dataKey="rule_alert_count"
                  name="Rule-Based Alerts"
                  stroke="#ef4444"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#ruleAlertGrad)"
                />
                <Area
                  type="monotone"
                  dataKey="ml_alert_count"
                  name="ML Anomalies"
                  stroke="#a855f7"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#mlAlertGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity & Engine Breakdown Panel */}
        <div className="p-5 rounded-xl border border-slate-800 bg-[#0c101a] flex flex-col justify-between space-y-4">
          {/* Detection Engine Split */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                Detection Engine Split
              </h2>
              <span className="text-[11px] font-mono text-slate-400 font-semibold">
                {totalEngineAlerts} Total
              </span>
            </div>
            <p className="text-xs text-slate-400 mb-3">
              Deterministic threat rules vs. Isolation Forest anomaly heuristics
            </p>

            {/* Dual Metric Display */}
            <div className="grid grid-cols-2 gap-2 mb-2.5">
              <div className="p-2.5 rounded-lg bg-slate-900/60 border border-cyan-800/40">
                <div className="flex items-center justify-between text-[11px] text-cyan-300 mb-1">
                  <span className="font-semibold">Rule-Based</span>
                  <span className="font-mono font-bold">{rulePct}%</span>
                </div>
                <div className="text-lg font-bold text-white font-mono">{stats?.rule_alerts ?? 0}</div>
                <div className="text-[10px] text-slate-400 mt-0.5">Known signatures</div>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-900/60 border border-purple-800/40">
                <div className="flex items-center justify-between text-[11px] text-purple-300 mb-1">
                  <span className="font-semibold">ML Heuristic</span>
                  <span className="font-mono font-bold">{mlPct}%</span>
                </div>
                <div className="text-lg font-bold text-white font-mono">{stats?.ml_alerts ?? 0}</div>
                <div className="text-[10px] text-slate-400 mt-0.5">Statistical anomalies*</div>
              </div>
            </div>

            {/* Proportional Split Bar */}
            <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden flex mb-2">
              <div
                style={{ width: `${rulePct}%` }}
                className="bg-cyan-500 transition-all duration-500"
                title={`Rule-Based: ${stats?.rule_alerts ?? 0} (${rulePct}%)`}
              />
              <div
                style={{ width: `${mlPct}%` }}
                className="bg-purple-500 transition-all duration-500"
                title={`ML Anomaly: ${stats?.ml_alerts ?? 0} (${mlPct}%)`}
              />
            </div>

            <p className="text-[10px] text-slate-500 italic leading-relaxed">
              *Note: ML alerts denote unsupervised statistical anomalies, not confirmed attacks.
            </p>
          </div>

          {/* Alerts by Severity Section */}
          <div className="border-t border-slate-800/80 pt-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                Alerts by Severity
              </span>
              <span className="text-[10px] text-slate-400">All Active & Resolved</span>
            </div>
            <div className="h-28 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats?.severity_breakdown || []} layout="vertical" margin={{ top: 0, right: 10, left: -10, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis type="number" stroke="#64748b" fontSize={10} allowDecimals={false} />
                  <YAxis dataKey="severity" type="category" stroke="#94a3b8" fontSize={10} width={65} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#111726',
                      borderColor: '#1e293b',
                      borderRadius: '8px',
                      fontSize: '11px'
                    }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {(stats?.severity_breakdown || []).map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.severity] || '#64748b'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Grid: Top Attacker IPs & Recent Alerts Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top Attacking Entities */}
        <div className="p-5 rounded-xl border border-slate-800 bg-[#0c101a]">
          <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider mb-1">
            Top Offending Sources
          </h2>
          <p className="text-xs text-slate-400 mb-4">IPs generating the highest volume of events</p>
          {stats?.top_attackers && stats.top_attackers.length > 0 ? (
            <div className="space-y-3">
              {stats.top_attackers.map((item, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 text-xs"
                >
                  <div className="font-mono text-cyan-300 font-semibold">{item.ip}</div>
                  <div className="flex items-center space-x-3 text-slate-400">
                    <span>{item.event_count} logs</span>
                    {item.alert_count > 0 && (
                      <span className="px-1.5 py-0.5 rounded bg-red-950/80 text-red-400 border border-red-800 font-bold">
                        {item.alert_count} alerts
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-slate-500 py-8 text-center">
              No traffic recorded yet. Use the Attack Simulator to generate telemetry.
            </div>
          )}
        </div>

        {/* Recent Alerts Feed */}
        <div className="lg:col-span-2 p-5 rounded-xl border border-slate-800 bg-[#0c101a]">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider">
                Active Incident Feed
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">Latest high-fidelity threat alerts</p>
            </div>
            <button
              onClick={() => setActiveTab('alerts')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
            >
              View All Alerts &rarr;
            </button>
          </div>

          {recentAlerts.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold">
                    <th className="pb-2.5">Severity</th>
                    <th className="pb-2.5">Threat Title</th>
                    <th className="pb-2.5">Source IP</th>
                    <th className="pb-2.5">Status</th>
                    <th className="pb-2.5 text-right">Count</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {recentAlerts.map((alert) => (
                    <tr key={alert.id} className="hover:bg-slate-900/40 transition">
                      <td className="py-2.5">
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td className="py-2.5">
                        <div className="flex items-center gap-2 flex-wrap max-w-[280px]">
                          <span className="font-medium text-slate-200 truncate">{alert.title}</span>
                          <DetectionBadge ruleId={alert.rule_id} />
                        </div>
                      </td>
                      <td className="py-2.5 font-mono text-cyan-300">{alert.source_ip}</td>
                      <td className="py-2.5">
                        <StatusBadge status={alert.status} />
                      </td>
                      <td className="py-2.5 text-right font-mono text-slate-300">
                        {alert.trigger_count}x
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-xs text-slate-500 py-10 text-center">
              No active security incidents detected. System is running cleanly.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
