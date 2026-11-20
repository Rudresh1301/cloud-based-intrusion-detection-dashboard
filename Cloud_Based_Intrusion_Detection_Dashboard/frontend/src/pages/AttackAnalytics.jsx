import React, { useState, useEffect } from 'react';
import {
  TrendingUp,
  BarChart2,
  PieChart,
  Calendar,
  Clock,
  History,
  RefreshCw
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell
} from 'recharts';
import { getAttackAnalytics } from '../services/api';

export const AttackAnalytics = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAttackAnalytics()
      .then((res) => setData(res.data))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <RefreshCw className="w-8 h-8 text-[#00C8FF] animate-spin" />
      </div>
    );
  }

  const hourlyData = data?.hourly_distribution || [];
  const dailyData = data?.daily_distribution || [];
  const categoryData = data?.category_distribution || [];
  const historyRuns = data?.historical_runs || [];

  return (
    <div className="space-y-6 animate-fadeIn max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1E2D4A]">
        <div>
          <h2 className="text-xl font-bold text-[#F1F5F9]">Attack Analytics & Temporal Intelligence</h2>
          <p className="text-xs text-[#94A3B8] mt-1">
            Aggregated attack frequency trends, diurnal hourly spikes, and multi-run historical audit benchmarks.
          </p>
        </div>
      </div>

      {/* Top Charts: Hourly & Daily Temporal Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 24-Hour Diurnal Attack Distribution */}
        <div className="p-5 rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-[#F1F5F9] flex items-center gap-2">
              <Clock size={16} className="text-[#00C8FF]" /> Hourly Attack Frequency (24h Diurnal)
            </h3>
            <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Incident Count</span>
          </div>

          <div className="w-full h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={hourlyData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E2D4A" vertical={false} />
                <XAxis dataKey="hour" stroke="#94A3B8" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                <YAxis stroke="#94A3B8" tick={{ fill: '#94A3B8', fontSize: 10 }} />
                <Tooltip
                  content={({ active, payload, label }) => {
                    if (active && payload && payload.length) {
                      return (
                        <div className="bg-[#121E32] border border-[#1E2D4A] p-2 rounded-xl text-xs">
                          <p className="font-semibold text-[#F1F5F9]">{label}</p>
                          <p className="text-[#00C8FF]">{payload[0].value} detected incidents</p>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Bar dataKey="incidents" fill="#087FE5" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Weekly Attack Cadence (Mon-Sun) */}
        <div className="p-5 rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-[#F1F5F9] flex items-center gap-2">
              <Calendar size={16} className="text-[#FFB020]" /> Day-of-Week Attack Distribution
            </h3>
            <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Weekly Load</span>
          </div>

          <div className="w-full h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={dailyData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E2D4A" vertical={false} />
                <XAxis dataKey="day" stroke="#94A3B8" tick={{ fill: '#94A3B8', fontSize: 11 }} />
                <YAxis stroke="#94A3B8" tick={{ fill: '#94A3B8', fontSize: 11 }} />
                <Tooltip
                  content={({ active, payload, label }) => {
                    if (active && payload && payload.length) {
                      return (
                        <div className="bg-[#121E32] border border-[#1E2D4A] p-2 rounded-xl text-xs">
                          <p className="font-semibold text-[#F1F5F9]">{label}</p>
                          <p className="text-[#FFB020]">{payload[0].value} incidents</p>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Bar dataKey="attacks" fill="#FFB020" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Category Breakdown & Historical Analysis Runs */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Attack Category Volume Table (5 cols) */}
        <div className="lg:col-span-5 rounded-2xl bg-[#121E32] border border-[#1E2D4A] p-5 shadow-soc-card">
          <h3 className="text-sm font-bold text-[#F1F5F9] mb-3 flex items-center gap-2">
            <BarChart2 size={16} className="text-[#8B5CF6]" /> Attack Category Distribution
          </h3>
          <div className="space-y-3">
            {categoryData.map((cat) => (
              <div key={cat.category} className="text-xs">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-semibold text-[#F1F5F9]">{cat.category}</span>
                  <span className="font-mono text-[#94A3B8]">{cat.count} events</span>
                </div>
                <div className="w-full h-2 rounded-full bg-[#080D19] overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${Math.min(100, (cat.count / Math.max(1, data?.total_threats)) * 100)}%`,
                      backgroundColor: cat.color || '#00C8FF'
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Historical Analysis History (7 cols) */}
        <div className="lg:col-span-7 rounded-2xl bg-[#121E32] border border-[#1E2D4A] p-5 shadow-soc-card">
          <h3 className="text-sm font-bold text-[#F1F5F9] mb-3 flex items-center gap-2">
            <History size={16} className="text-[#00D68F]" /> Ingestion & Detection History
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="text-[#94A3B8] border-b border-[#1E2D4A] text-[11px]">
                  <th className="pb-2">Timestamp</th>
                  <th className="pb-2">Dataset Source</th>
                  <th className="pb-2">Processed Records</th>
                  <th className="pb-2">Threats Flagged</th>
                  <th className="pb-2 text-right">Risk Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1E2D4A]/50">
                {historyRuns.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="p-4 text-center text-[#94A3B8]">
                      No historical batch runs recorded yet.
                    </td>
                  </tr>
                ) : (
                  historyRuns.map((run) => (
                    <tr key={run.id} className="hover:bg-[#16253e]">
                      <td className="py-2.5 font-mono text-[#94A3B8] text-[11px] whitespace-nowrap">{run.timestamp}</td>
                      <td className="py-2.5 font-semibold text-[#F1F5F9] whitespace-nowrap">{run.filename}</td>
                      <td className="py-2.5 font-mono text-[#00C8FF] whitespace-nowrap">{run.total_records}</td>
                      <td className="py-2.5 font-mono text-[#FF4560] font-bold whitespace-nowrap">{run.threats_found}</td>
                      <td className="py-2.5 text-right whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-[#FF4560]/20 text-[#FF4560] border border-[#FF4560]/40">
                          {run.risk_level}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
