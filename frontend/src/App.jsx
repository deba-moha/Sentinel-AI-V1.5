import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import AlertsPage from './pages/AlertsPage';
import LogsPage from './pages/LogsPage';
import SimulatorPage from './pages/SimulatorPage';
import { apiService } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [systemHealthy, setSystemHealthy] = useState(true);

  // Periodic health check
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const res = await apiService.getHealth();
        setSystemHealthy(res.status === 'healthy');
      } catch {
        setSystemHealthy(false);
      }
    };

    checkStatus();
    const interval = setInterval(checkStatus, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-[#0a0d14] text-slate-100 flex flex-col font-sans">
      {/* Navigation Header */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        systemHealthy={systemHealthy}
      />

      {/* Main Content Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'dashboard' && <Dashboard setActiveTab={setActiveTab} />}
        {activeTab === 'alerts' && <AlertsPage />}
        {activeTab === 'logs' && <LogsPage />}
        {activeTab === 'simulator' && <SimulatorPage setActiveTab={setActiveTab} />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-[#0c101a] py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            <span className="font-semibold text-slate-400">Sentinel AI</span> — Version 1.0 (Foundation)
          </div>
          <div>
            Built with FastAPI, SQLite, Pydantic, React & Tailwind CSS
          </div>
        </div>
      </footer>
    </div>
  );
}

