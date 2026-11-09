import React from 'react';
import { Shield, Activity, AlertOctagon, Terminal, PlayCircle } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, systemHealthy }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'alerts', label: 'Alerts & Triage', icon: AlertOctagon },
    { id: 'logs', label: 'Log Stream', icon: Terminal },
    { id: 'simulator', label: 'Attack Simulator', icon: PlayCircle },
  ];

  return (
    <header className="border-b border-slate-800 bg-[#0c101a]/90 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Branding */}
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-lg tracking-wider text-white">SENTINEL</span>
                <span className="text-xs px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 font-mono border border-cyan-800">
                  AI v1.0
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-medium">Foundation Security Monitoring</p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="flex space-x-1 sm:space-x-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`flex items-center space-x-2 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-[0_0_10px_rgba(6,182,212,0.15)]'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Backend Status Pill */}
          <div className="hidden sm:flex items-center space-x-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs">
            <span
              className={`w-2 h-2 rounded-full ${
                systemHealthy ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'
              }`}
            />
            <span className="text-slate-300 font-mono">
              {systemHealthy ? 'API ONLINE' : 'API DISCONNECTED'}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}

