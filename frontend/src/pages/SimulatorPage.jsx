import React, { useState } from 'react';
import {
  PlayCircle,
  ShieldAlert,
  Radio,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Globe,
  Lock,
  Zap,
  Info,
  Server,
  Cpu
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import DetectionBadge from '../components/DetectionBadge';
import { apiService } from '../services/api';

export default function SimulatorPage({ setActiveTab }) {
  const [runningScenario, setRunningScenario] = useState(null);
  const [result, setResult] = useState(null);
  const [customIp, setCustomIp] = useState('');
  const [customCount, setCustomCount] = useState(10);
  const [errorMessage, setErrorMessage] = useState(null);

  const scenarios = [
    {
      id: 'BRUTE_FORCE',
      title: 'SSH Brute Force Attack',
      icon: Lock,
      color: 'orange',
      badge: 'RULE-AUTH-BRUTEFORCE',
      severity: 'HIGH',
      description: 'Simulates 6 rapid failed password attempts against port 22 from an external attacker IP.',
      expectedResult: 'Triggers High severity deterministic brute force alert (threshold 5). High-frequency bursts can additionally trigger an unsupervised ML anomaly alert.',
      defaultCount: 6
    },
    {
      id: 'PORT_SCAN',
      title: 'Port Scan Reconnaissance',
      icon: Globe,
      color: 'amber',
      badge: 'RULE-NET-PORTSCAN',
      severity: 'MEDIUM',
      description: 'Simulates TCP SYN connection probes targeting 8 distinct destination ports (21, 22, 23, 80, 443, etc.).',
      expectedResult: 'Triggers Medium severity deterministic port scan alert (threshold 5 ports). Rapid multi-port scans may also trigger an ML statistical anomaly alert.',
      defaultCount: 8
    },
    {
      id: 'SUCCESSFUL_ROOT_LOGIN',
      title: 'Unauthorized Root Breach',
      icon: ShieldAlert,
      color: 'red',
      badge: 'RULE-AUTH-ROOT-LOGIN',
      severity: 'CRITICAL',
      description: 'Simulates an authenticated remote root shell session opened from an untrusted public IP.',
      expectedResult: 'Immediately triggers Critical severity deterministic root breach alert. Single-event logins may not trigger statistical ML anomaly detection.',
      defaultCount: 1
    },
    {
      id: 'FAILED_ROOT_LOGIN',
      title: 'Isolated Failed Root Login',
      icon: Info,
      color: 'slate',
      badge: 'BENIGN / TELEMETRY',
      severity: 'LOW',
      description: 'Simulates an isolated mistyped password attempt for user "root".',
      expectedResult: 'Captured as baseline telemetry; zero deterministic alerts triggered. Isolated low-volume events fall within baseline ML expectations.',
      defaultCount: 1
    },
    {
      id: 'DDOS_ATTACK',
      title: 'Distributed DDoS Surge',
      icon: Flame,
      color: 'red',
      badge: 'RULE-NET-DDOS-AGGREGATE',
      severity: 'CRITICAL',
      description: 'Simulates 24 HTTP flood probe requests targeting one destination across 6 distinct botnet IPs.',
      expectedResult: 'Triggers Critical severity aggregate DDoS alert (threshold 20). High-volume surge telemetry typically triggers a concurrent ML anomaly alert.',
      defaultCount: 24
    },
    {
      id: 'ANOMALOUS_SPIKE',
      title: 'Single-Source Traffic Spike',
      icon: Zap,
      color: 'amber',
      badge: 'RULE-ANOMALOUS-SPIKE',
      severity: 'MEDIUM',
      description: 'Simulates 25 rapid requests hitting web endpoints from a single host within 60s.',
      expectedResult: 'Triggers Medium severity deterministic traffic spike alert (threshold 20) and frequently registers as an unsupervised ML outlier.',
      defaultCount: 25
    },
    {
      id: 'NORMAL_TRAFFIC',
      title: 'Normal Operational Telemetry',
      icon: CheckCircle2,
      color: 'emerald',
      badge: 'BENIGN BASELINE',
      severity: 'INFO',
      description: 'Simulates routine internal HTTP 200 responses, DNS resolutions, and legitimate user logins.',
      expectedResult: 'Zero deterministic alerts triggered. Normal operations align with the ML baseline, confirming low false-positive rates.',
      defaultCount: 5
    },
    {
      id: 'MIXED',
      title: 'Blended Real-World Feed',
      icon: Server,
      color: 'cyan',
      badge: 'MIXED TELEMETRY',
      severity: 'HIGH',
      description: 'Generates background legitimate traffic combined with an injected SSH brute-force attack.',
      expectedResult: 'Raises deterministic brute force alert while logging normal events. Rapid attack injection can also produce a concurrent ML anomaly alert.',
      defaultCount: 12
    }
  ];

  const handleRun = async (scenarioId, defaultCount) => {
    setRunningScenario(scenarioId);
    setErrorMessage(null);
    try {
      const response = await apiService.runSimulation({
        scenario: scenarioId,
        count: customCount || defaultCount,
        source_ip: customIp.trim() || null
      });
      setResult(response);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to execute simulation.');
    } finally {
      setRunningScenario(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <PlayCircle className="w-6 h-6 text-cyan-400" />
          Synthetic Attack & Telemetry Simulator
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Safely inject synthetic security telemetry to evaluate Sentinel AI V1.5 dual detection: 5 deterministic signature rules and an unsupervised Isolation Forest ML anomaly detector.
        </p>
      </div>

      {/* Safe Simulation & Hybrid Architecture Notice */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
        <div className="p-3.5 rounded-lg bg-cyan-950/30 border border-cyan-800/50 flex items-start space-x-3 text-cyan-200">
          <Radio className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0 animate-pulse" />
          <div>
            <span className="font-semibold text-cyan-300">Safe Local Simulation:</span> All simulation scenarios generate structured security events directly into the local SQLite database. No live network packets or external flooding traffic are generated.
          </div>
        </div>
        <div className="p-3.5 rounded-lg bg-purple-950/30 border border-purple-800/50 flex items-start space-x-3 text-purple-200">
          <Cpu className="w-4 h-4 text-purple-400 mt-0.5 shrink-0" />
          <div>
            <span className="font-semibold text-purple-300">Hybrid Detection Architecture:</span> Generated events are concurrently evaluated by deterministic rules and the unsupervised Isolation Forest ML model. High-volume attacks may trigger dual alerts (deterministic signature + ML anomaly). ML anomaly scores represent statistical distances from baseline traffic, not attack probabilities or confirmed malicious intent.
          </div>
        </div>
      </div>

      {/* Optional Custom Configuration Bar */}
      <div className="p-4 rounded-xl border border-slate-800 bg-[#0c101a] flex flex-wrap items-center gap-4 text-xs">
        <span className="text-slate-300 font-semibold uppercase tracking-wider">Parameters:</span>
        <div className="flex items-center space-x-2">
          <label className="text-slate-400">Custom Source IP (Optional):</label>
          <input
            type="text"
            placeholder="e.g. 198.51.100.42"
            value={customIp}
            onChange={(e) => setCustomIp(e.target.value)}
            className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 w-36 font-mono"
          />
        </div>
        <div className="flex items-center space-x-2">
          <label className="text-slate-400">Event Multiplier:</label>
          <input
            type="number"
            min="1"
            max="100"
            value={customCount}
            onChange={(e) => setCustomCount(Math.max(1, parseInt(e.target.value) || 1))}
            className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500 w-20 font-mono"
          />
        </div>
      </div>

      {errorMessage && (
        <div className="p-3.5 rounded-lg bg-red-950/60 border border-red-800 text-red-300 text-xs">
          Simulation Error: {errorMessage}
        </div>
      )}

      {/* Simulation Result Output Banner */}
      {result && (
        <div className="p-4 rounded-xl border border-emerald-800/60 bg-emerald-950/20 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <span className="text-sm font-semibold text-emerald-300">
                Scenario Executed: {result.scenario}
              </span>
            </div>
            <div className="flex items-center space-x-4 text-xs font-mono">
              <span className="text-slate-300">Logs Generated: <strong className="text-white">{result.logs_generated}</strong></span>
              <span className="text-slate-300">Alerts Triggered: <strong className="text-cyan-300">{result.alerts_triggered}</strong></span>
            </div>
          </div>

          {result.new_alerts && result.new_alerts.length > 0 && (
            <div className="pt-2 border-t border-emerald-900/40 space-y-2">
              <span className="text-xs font-semibold text-slate-300 block">Incident Alerts Generated:</span>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {result.new_alerts.map((al) => (
                  <div key={al.id} className="p-2.5 rounded-lg bg-black/40 border border-slate-800 text-xs flex items-center justify-between gap-3">
                    <div className="space-y-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <SeverityBadge severity={al.severity} />
                        <DetectionBadge ruleId={al.rule_id} />
                        <span className="font-semibold text-slate-200 truncate">{al.title}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono">Source: {al.source_ip}</div>
                    </div>
                    <button
                      onClick={() => setActiveTab('alerts')}
                      className="text-xs text-cyan-400 hover:text-cyan-300 font-medium ml-2 shrink-0 underline"
                    >
                      Investigate &rarr;
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Scenario Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {scenarios.map((sc) => {
          const Icon = sc.icon;
          const isBusy = runningScenario === sc.id;

          return (
            <div
              key={sc.id}
              className="p-5 rounded-xl border border-slate-800 bg-[#0c101a] flex flex-col justify-between hover:border-slate-700 transition"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-cyan-400">
                    <Icon className="w-5 h-5" />
                  </div>
                  <SeverityBadge severity={sc.severity} />
                </div>

                <div>
                  <h3 className="text-sm font-bold text-white">{sc.title}</h3>
                  <span className="text-[10px] font-mono text-cyan-400/80">{sc.badge}</span>
                </div>

                <p className="text-xs text-slate-400">{sc.description}</p>

                <div className="text-[11px] text-slate-400 bg-slate-900/60 p-2 rounded border border-slate-800">
                  <span className="text-slate-400 font-semibold block mb-0.5">Expected Outcome:</span>
                  {sc.expectedResult}
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80">
                <button
                  disabled={isBusy}
                  onClick={() => handleRun(sc.id, sc.defaultCount)}
                  className={`w-full py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition ${
                    isBusy
                      ? 'bg-cyan-950 text-cyan-400 cursor-not-allowed border border-cyan-800'
                      : 'bg-cyan-600 hover:bg-cyan-500 text-black font-bold'
                  }`}
                >
                  <PlayCircle className={`w-4 h-4 ${isBusy ? 'animate-spin' : ''}`} />
                  <span>{isBusy ? 'Injecting Telemetry...' : 'Inject Simulation'}</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
