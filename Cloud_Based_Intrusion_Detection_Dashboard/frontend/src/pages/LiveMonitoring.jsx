import React, { useState, useEffect } from 'react';
import {
  Activity,
  Play,
  Square,
  Zap,
  ShieldAlert,
  Radio,
  Clock,
  RefreshCw,
  AlertTriangle
} from 'lucide-react';
import { getLiveStream, tickLiveTelemetry } from '../services/api';

export const LiveMonitoring = () => {
  const [isRunning, setIsRunning] = useState(true);
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [lastTick, setLastTick] = useState(new Date().toLocaleTimeString());
  const [tickerCount, setTickerCount] = useState(0);

  const fetchStream = async () => {
    try {
      const res = await getLiveStream({ count: 12 });
      setEvents(res.data.recent_events || []);
      setAlerts(res.data.recent_alerts || []);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchStream();
  }, []);

  // Periodic heartbeat timer when isRunning
  useEffect(() => {
    let interval = null;
    if (isRunning) {
      interval = setInterval(async () => {
        try {
          await tickLiveTelemetry();
          fetchStream();
          setLastTick(new Date().toLocaleTimeString());
          setTickerCount((prev) => prev + 1);
        } catch (err) {
          console.error(err);
        }
      }, 4000);
    }
    return () => clearInterval(interval);
  }, [isRunning]);

  const handleManualTick = async () => {
    try {
      await tickLiveTelemetry();
      fetchStream();
      setLastTick(new Date().toLocaleTimeString());
      setTickerCount((prev) => prev + 1);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1E2D4A]">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-black uppercase bg-[#087FE5]/20 text-[#00C8FF] border border-[#087FE5]/40 tracking-wider">
              SIMULATED LIVE MONITORING
            </span>
            <span className="text-xs text-[#94A3B8]">Demonstration Telemetry Stream</span>
          </div>
          <h2 className="text-xl font-bold text-[#F1F5F9] mt-1">Real-Time Threat Ingestion Pipeline</h2>
        </div>

        {/* Stream Controls */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsRunning(!isRunning)}
            className={`py-2 px-4 rounded-xl font-bold text-xs flex items-center gap-2 transition-all cursor-pointer ${
              isRunning
                ? 'bg-[#FF4560]/20 text-[#FF4560] border border-[#FF4560]/40 hover:bg-[#FF4560]/30 shadow-neon-red'
                : 'bg-[#00D68F]/20 text-[#00D68F] border border-[#00D68F]/40 hover:bg-[#00D68F]/30 shadow-neon-green'
            }`}
          >
            {isRunning ? (
              <>
                <Square size={14} /> Pause Heartbeat
              </>
            ) : (
              <>
                <Play size={14} /> Resume Telemetry
              </>
            )}
          </button>

          <button
            onClick={handleManualTick}
            className="py-2 px-4 rounded-xl bg-gradient-to-r from-[#087FE5] to-[#00A8FF] text-white font-bold text-xs shadow-neon-blue hover:brightness-110 transition-all flex items-center gap-2 cursor-pointer"
          >
            <Zap size={14} /> Pulse Single Event
          </button>
        </div>
      </div>

      {/* Mandatory Academic Disclaimer Banner */}
      <div className="p-4 rounded-xl bg-[#121E32] border border-[#1E2D4A] text-xs text-[#94A3B8] flex items-center gap-3">
        <Radio size={18} className="text-[#00C8FF] flex-shrink-0 animate-pulse" />
        <div>
          <span className="font-semibold text-[#F1F5F9]">Simulation Notice: </span>
          This telemetry stream generates synthetic cloud access events to safely demonstrate real-time packet inspection, rule evaluation, and alert dispatching without intercepting live physical interfaces.
        </div>
      </div>

      {/* Live Status Indicators */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-[#121E32] border border-[#1E2D4A] flex items-center justify-between">
          <div>
            <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Pipeline State</span>
            <div className="flex items-center gap-2 mt-1">
              <span className={`w-2.5 h-2.5 rounded-full ${isRunning ? 'bg-[#00D68F] animate-ping' : 'bg-[#94A3B8]'}`} />
              <p className="font-bold text-[#F1F5F9] text-sm">{isRunning ? 'Active Ingestion' : 'Telemetry Paused'}</p>
            </div>
          </div>
          <Activity size={24} className="text-[#00C8FF]" />
        </div>

        <div className="p-4 rounded-xl bg-[#121E32] border border-[#1E2D4A] flex items-center justify-between">
          <div>
            <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Latest Heartbeat Pulse</span>
            <p className="font-mono font-bold text-[#00C8FF] text-sm mt-1">{lastTick}</p>
          </div>
          <Clock size={24} className="text-[#087FE5]" />
        </div>

        <div className="p-4 rounded-xl bg-[#121E32] border border-[#1E2D4A] flex items-center justify-between">
          <div>
            <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Total Pulses Dispatched</span>
            <p className="font-mono font-bold text-[#F1F5F9] text-sm mt-1">{tickerCount} events</p>
          </div>
          <Zap size={24} className="text-[#FFB020]" />
        </div>
      </div>

      {/* Event Stream and Detected Alerts (Two columns) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Ingested Telemetry Log Stream (7 cols) */}
        <div className="lg:col-span-7 rounded-2xl bg-[#121E32] border border-[#1E2D4A] p-5 shadow-soc-card">
          <div className="flex items-center justify-between pb-3 border-b border-[#1E2D4A] mb-3">
            <h3 className="text-sm font-bold text-[#F1F5F9] flex items-center gap-2">
              <Activity size={16} className="text-[#00C8FF]" /> Ingested Telemetry Feed
            </h3>
            <span className="text-xs text-[#94A3B8] font-mono">Real-Time Ingestion</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="text-[#94A3B8] border-b border-[#1E2D4A] text-[11px]">
                  <th className="pb-2">Time</th>
                  <th className="pb-2">Source IP</th>
                  <th className="pb-2">Action</th>
                  <th className="pb-2">Endpoint</th>
                  <th className="pb-2 text-right">Classification</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1E2D4A]/50">
                {events.map((ev) => {
                  const isAttack = ev.classification && ev.classification !== 'Normal';
                  return (
                    <tr key={ev.id} className="hover:bg-[#16253e] transition-colors">
                      <td className="py-2.5 font-mono text-[#94A3B8] text-[11px] whitespace-nowrap">
                        {ev.timestamp?.split(' ')[1] || ev.timestamp}
                      </td>
                      <td className="py-2.5 font-mono text-[#00C8FF] whitespace-nowrap">
                        {ev.source_ip}
                      </td>
                      <td className="py-2.5 text-[#F1F5F9] whitespace-nowrap">
                        {ev.event_type}
                      </td>
                      <td className="py-2.5 text-[#94A3B8] max-w-xs truncate" title={ev.endpoint}>
                        {ev.endpoint}
                      </td>
                      <td className="py-2.5 text-right whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                            isAttack
                              ? 'bg-[#FF4560]/20 text-[#FF4560] border border-[#FF4560]/40'
                              : 'bg-[#00D68F]/20 text-[#00D68F] border border-[#00D68F]/40'
                          }`}
                        >
                          {ev.classification || 'Normal'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Detected Threats Stream (5 cols) */}
        <div className="lg:col-span-5 rounded-2xl bg-[#121E32] border border-[#1E2D4A] p-5 shadow-soc-card">
          <div className="flex items-center justify-between pb-3 border-b border-[#1E2D4A] mb-3">
            <h3 className="text-sm font-bold text-[#F1F5F9] flex items-center gap-2">
              <ShieldAlert size={16} className="text-[#FF4560]" /> Dispatched Threat Alerts
            </h3>
            <span className="text-xs text-[#FF4560] font-semibold">{alerts.length} Incidents</span>
          </div>

          <div className="space-y-3">
            {alerts.slice(0, 6).map((alert) => {
              const isCrit = alert.severity === 'Critical';
              return (
                <div
                  key={alert.id}
                  className="p-3 rounded-xl bg-[#080D19]/70 border border-[#1E2D4A] hover:border-[#FF4560]/40 transition-colors"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold text-[#F1F5F9] text-xs">{alert.alert_type}</span>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[9px] font-extrabold uppercase ${
                        isCrit ? 'bg-[#FF4560] text-white shadow-neon-red' : 'bg-[#FFB020]/20 text-[#FFB020] border border-[#FFB020]/40'
                      }`}
                    >
                      {alert.severity}
                    </span>
                  </div>
                  <p className="text-[11px] text-[#94A3B8]">{alert.description || alert.evidence}</p>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-[#1E2D4A]/60 text-[10px] text-[#94A3B8]">
                    <span className="font-mono text-[#00C8FF]">{alert.source_ip}</span>
                    <span className="font-mono">{alert.timestamp?.split(' ')[1] || alert.timestamp}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
