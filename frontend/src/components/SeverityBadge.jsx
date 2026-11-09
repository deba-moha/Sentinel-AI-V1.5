import React from 'react';

export default function SeverityBadge({ severity }) {
  const sev = (severity || 'INFO').toUpperCase();

  const styles = {
    CRITICAL: 'bg-red-950/80 text-red-400 border-red-700/60 shadow-[0_0_8px_rgba(239,68,68,0.25)]',
    HIGH: 'bg-orange-950/80 text-orange-400 border-orange-700/60',
    MEDIUM: 'bg-amber-950/80 text-amber-400 border-amber-700/60',
    LOW: 'bg-blue-950/80 text-blue-400 border-blue-700/60',
    INFO: 'bg-slate-800 text-slate-300 border-slate-700'
  };

  const currentStyle = styles[sev] || styles.INFO;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border ${currentStyle}`}>
      {sev}
    </span>
  );
}

