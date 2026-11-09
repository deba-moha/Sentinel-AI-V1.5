import React from 'react';

export default function StatusBadge({ status }) {
  const st = (status || 'NEW').toUpperCase();

  const styles = {
    NEW: 'bg-rose-900/40 text-rose-300 border-rose-700/50',
    INVESTIGATING: 'bg-amber-900/40 text-amber-300 border-amber-700/50',
    RESOLVED: 'bg-emerald-900/40 text-emerald-300 border-emerald-700/50',
    FALSE_POSITIVE: 'bg-slate-800 text-slate-400 border-slate-700'
  };

  const currentStyle = styles[st] || styles.NEW;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${currentStyle}`}>
      <span className="w-1.5 h-1.5 rounded-full mr-1.5 bg-current opacity-75"></span>
      {st.replace('_', ' ')}
    </span>
  );
}

