import React from 'react';
import { ShieldCheck, Cpu } from 'lucide-react';

/**
 * DetectionBadge - Sentinel AI V1.5 Visual Distinction Component
 *
 * Differentiates detection mechanisms based strictly on rule ID:
 * - "RULE-ML-ANOMALY-IFOREST" -> "ML HEURISTIC" (Unsupervised Isolation Forest)
 * - All other rule IDs        -> "RULE-BASED" (Deterministic Threat Signature)
 *
 * Consistent with SeverityBadge and StatusBadge styling in cyber dark theme.
 */
export default function DetectionBadge({ ruleId, rule_id, showIcon = true, className = '' }) {
  const activeRule = (ruleId || rule_id || '').trim();
  const isML = activeRule === 'RULE-ML-ANOMALY-IFOREST';

  if (isML) {
    return (
      <span
        title="Unsupervised Machine Learning: Statistical outlier detected by Isolation Forest"
        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-semibold border bg-purple-950/80 text-purple-300 border-purple-700/60 shadow-[0_0_8px_rgba(168,85,247,0.25)] ${className}`}
      >
        {showIcon && <Cpu className="w-3.5 h-3.5 text-purple-400 shrink-0" />}
        <span>ML HEURISTIC</span>
      </span>
    );
  }

  return (
    <span
      title="Deterministic Rule Engine: High-fidelity attack signature match"
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-semibold border bg-cyan-950/80 text-cyan-300 border-cyan-700/60 ${className}`}
    >
      {showIcon && <ShieldCheck className="w-3.5 h-3.5 text-cyan-400 shrink-0" />}
      <span>RULE-BASED</span>
    </span>
  );
}
