import React from 'react';

export default function StatCard({ title, value, icon: Icon, alertColor, subtitle }) {
  const colorMap = {
    cyan: 'border-cyan-500/30 text-cyan-400 bg-cyan-950/20 shadow-[0_0_15px_rgba(6,182,212,0.1)]',
    red: 'border-red-500/30 text-red-400 bg-red-950/20 shadow-[0_0_15px_rgba(239,68,68,0.1)]',
    amber: 'border-amber-500/30 text-amber-400 bg-amber-950/20 shadow-[0_0_15px_rgba(245,158,11,0.1)]',
    emerald: 'border-emerald-500/30 text-emerald-400 bg-emerald-950/20 shadow-[0_0_15px_rgba(16,185,129,0.1)]',
    slate: 'border-slate-800 text-slate-400 bg-slate-900/40'
  };

  const style = colorMap[alertColor] || colorMap.slate;

  return (
    <div className={`p-4 rounded-xl border ${style} transition-all duration-200 hover:border-slate-600`}>
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider text-slate-400 font-semibold">{title}</span>
        {Icon && <Icon className="w-5 h-5 opacity-80" />}
      </div>
      <div className="mt-2 flex items-baseline gap-2">
        <span className="text-2xl font-bold text-white tracking-tight">{value}</span>
      </div>
      {subtitle && <p className="mt-1 text-xs text-slate-400">{subtitle}</p>}
    </div>
  );
}

