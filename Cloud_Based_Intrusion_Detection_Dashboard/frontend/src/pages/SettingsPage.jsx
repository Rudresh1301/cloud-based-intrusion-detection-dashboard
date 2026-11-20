import React, { useState, useEffect } from 'react';
import {
  Settings,
  Sliders,
  Cloud,
  Database,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Save,
  Server
} from 'lucide-react';
import { getSettings, updateSettings, clearAllLogs, getCloudHealth } from '../services/api';

export const SettingsPage = () => {
  const [config, setConfig] = useState({
    brute_force_threshold: 5,
    brute_force_critical: 10,
    high_volume_threshold: 50,
    ml_contamination: 0.1,
    time_window_minutes: 10,
    auto_refresh_seconds: 15
  });

  const [healthData, setHealthData] = useState(null);
  const [isSaving, setIsSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState('');
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    try {
      const [settingsRes, healthRes] = await Promise.all([
        getSettings(),
        getCloudHealth()
      ]);
      setConfig(settingsRes.data);
      setHealthData(healthRes.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSave = async (e) => {
    e.preventDefault();
    setIsSaving(true);
    setSaveMessage('');
    try {
      await updateSettings(config);
      setSaveMessage('Detection settings saved successfully.');
      setTimeout(() => setSaveMessage(''), 4000);
    } catch (err) {
      console.error(err);
    } finally {
      setIsSaving(false);
    }
  };

  const handleClear = async () => {
    if (window.confirm('Are you sure you want to clear all processed records, alerts, and analysis history?')) {
      try {
        await clearAllLogs();
        setSaveMessage('All operational logs and security alerts have been cleared.');
        setTimeout(() => setSaveMessage(''), 4000);
      } catch (err) {
        console.error(err);
      }
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <RefreshCw className="w-8 h-8 text-[#00C8FF] animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fadeIn max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1E2D4A]">
        <div>
          <h2 className="text-xl font-bold text-[#F1F5F9]">System Configuration & Cloud Diagnostics</h2>
          <p className="text-xs text-[#94A3B8] mt-1">
            Tune detection thresholds, view actual cloud BaaS health status, and manage persistent storage.
          </p>
        </div>
      </div>

      {saveMessage && (
        <div className="p-4 rounded-xl bg-[#00D68F]/20 border border-[#00D68F]/40 text-[#00D68F] text-xs font-semibold flex items-center gap-2">
          <CheckCircle2 size={16} /> {saveMessage}
        </div>
      )}

      {/* Cloud Service Health Checks (Section 5E) */}
      <div className="rounded-2xl bg-[#121E32] border border-[#1E2D4A] p-5 shadow-soc-card">
        <div className="flex items-center justify-between pb-3 border-b border-[#1E2D4A] mb-4">
          <h3 className="text-sm font-bold text-[#F1F5F9] flex items-center gap-2">
            <Cloud size={16} className="text-[#00C8FF]" /> Cloud Service Status & Genuine Health Checks
          </h3>
          <button
            onClick={loadData}
            className="text-xs text-[#94A3B8] hover:text-[#F1F5F9] flex items-center gap-1.5 transition-colors"
          >
            <RefreshCw size={13} /> Re-probe
          </button>
        </div>

        <div className="space-y-3">
          {healthData?.services?.map((svc) => {
            const isConn = svc.status === 'connected';
            const isFallback = svc.status === 'fallback';
            const statusBadge = isConn
              ? 'bg-[#00D68F]/20 text-[#00D68F] border border-[#00D68F]/40'
              : isFallback
              ? 'bg-[#FFB020]/20 text-[#FFB020] border border-[#FFB020]/40'
              : 'bg-[#FF4560]/20 text-[#FF4560] border border-[#FF4560]/40';

            return (
              <div
                key={svc.name}
                className="p-3 rounded-xl bg-[#080D19]/60 border border-[#1E2D4A] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-[#F1F5F9]">{svc.name}</span>
                    <span className="text-[10px] text-[#94A3B8] bg-[#121E32] px-2 py-0.5 rounded">
                      {svc.provider}
                    </span>
                  </div>
                  <p className="text-[#94A3B8] mt-0.5 text-[11px]">{svc.details}</p>
                </div>

                <div className="flex items-center gap-3 flex-shrink-0">
                  {svc.latency_ms && (
                    <span className="font-mono text-[#00C8FF] text-[11px] font-semibold">
                      {svc.latency_ms} ms
                    </span>
                  )}
                  <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase ${statusBadge}`}>
                    {svc.status}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Thresholds Form */}
      <form onSubmit={handleSave} className="rounded-2xl bg-[#121E32] border border-[#1E2D4A] p-5 shadow-soc-card space-y-4">
        <h3 className="text-sm font-bold text-[#F1F5F9] flex items-center gap-2 pb-3 border-b border-[#1E2D4A]">
          <Sliders size={16} className="text-[#087FE5]" /> Threat Detection Heuristics & Machine Learning Parameters
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div>
            <label className="block text-[#94A3B8] font-semibold mb-1">
              Brute Force Alert Threshold (High Severity)
            </label>
            <input
              type="number"
              min="2"
              max="20"
              value={config.brute_force_threshold}
              onChange={(e) => setConfig({ ...config, brute_force_threshold: Number(e.target.value) })}
              className="w-full p-2.5 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-[#F1F5F9] font-mono focus:outline-none focus:border-[#00C8FF]"
            />
            <span className="text-[10px] text-[#94A3B8] mt-1 block">Failed logins before triggering High severity alert.</span>
          </div>

          <div>
            <label className="block text-[#94A3B8] font-semibold mb-1">
              Brute Force Escalation (Critical Severity)
            </label>
            <input
              type="number"
              min="5"
              max="50"
              value={config.brute_force_critical}
              onChange={(e) => setConfig({ ...config, brute_force_critical: Number(e.target.value) })}
              className="w-full p-2.5 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-[#F1F5F9] font-mono focus:outline-none focus:border-[#00C8FF]"
            />
            <span className="text-[10px] text-[#94A3B8] mt-1 block">Failed logins before escalating to Critical incident.</span>
          </div>

          <div>
            <label className="block text-[#94A3B8] font-semibold mb-1">
              High-Volume Flood Threshold
            </label>
            <input
              type="number"
              min="10"
              max="500"
              value={config.high_volume_threshold}
              onChange={(e) => setConfig({ ...config, high_volume_threshold: Number(e.target.value) })}
              className="w-full p-2.5 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-[#F1F5F9] font-mono focus:outline-none focus:border-[#00C8FF]"
            />
            <span className="text-[10px] text-[#94A3B8] mt-1 block">Requests per single IP to trigger flooding heuristic.</span>
          </div>

          <div>
            <label className="block text-[#94A3B8] font-semibold mb-1">
              Isolation Forest ML Contamination Factor
            </label>
            <input
              type="number"
              step="0.01"
              min="0.01"
              max="0.4"
              value={config.ml_contamination}
              onChange={(e) => setConfig({ ...config, ml_contamination: Number(e.target.value) })}
              className="w-full p-2.5 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-[#F1F5F9] font-mono focus:outline-none focus:border-[#00C8FF]"
            />
            <span className="text-[10px] text-[#94A3B8] mt-1 block">Expected outlier proportion in behavioral clustering.</span>
          </div>
        </div>

        <div className="flex justify-end pt-3 border-t border-[#1E2D4A]">
          <button
            type="submit"
            disabled={isSaving}
            className="py-2.5 px-6 rounded-xl bg-gradient-to-r from-[#087FE5] to-[#00A8FF] text-white font-bold text-xs shadow-neon-blue hover:brightness-110 transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
          >
            {isSaving ? <RefreshCw size={14} className="animate-spin" /> : <Save size={14} />}
            Save Detection Thresholds
          </button>
        </div>
      </form>

      {/* Danger Zone */}
      <div className="rounded-2xl bg-[#121E32] border border-[#FF4560]/30 p-5 shadow-soc-card">
        <h3 className="text-sm font-bold text-[#FF4560] flex items-center gap-2 mb-2">
          <Trash2 size={16} /> Operational Data Reset
        </h3>
        <p className="text-xs text-[#94A3B8] mb-4">
          Permanently clear ingested security logs, alerts, and historical runs from the database.
        </p>
        <button
          onClick={handleClear}
          className="py-2 px-4 rounded-xl bg-[#FF4560]/20 border border-[#FF4560]/40 text-[#FF4560] hover:bg-[#FF4560]/30 font-semibold text-xs transition-colors cursor-pointer"
        >
          Clear All Database Records
        </button>
      </div>
    </div>
  );
};
