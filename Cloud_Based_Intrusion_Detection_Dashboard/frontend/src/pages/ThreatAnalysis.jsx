import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  RefreshCw,
  Terminal,
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  Cpu
} from 'lucide-react';
import { getThreats, getThreatSummary, updateAlertStatus } from '../services/api';
import { ThreatDetailModal } from '../components/ThreatDetailModal';

export const ThreatAnalysis = () => {
  const [threats, setThreats] = useState([]);
  const [summary, setSummary] = useState(null);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchThreats = async () => {
    setLoading(true);
    try {
      const [listRes, sumRes] = await Promise.all([
        getThreats({
          page,
          page_size: 20,
          severity: severityFilter === 'All' ? '' : severityFilter,
          search
        }),
        getThreatSummary()
      ]);
      setThreats(listRes.data.items);
      setTotal(listRes.data.total);
      setSummary(sumRes.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, [page, severityFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    fetchThreats();
  };

  const handleStatusChange = async (alertId, newStatus) => {
    try {
      await updateAlertStatus(alertId, newStatus);
      if (selectedThreat) {
        setSelectedThreat({ ...selectedThreat, status: newStatus });
      }
      fetchThreats();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1E2D4A]">
        <div>
          <h2 className="text-xl font-bold text-[#F1F5F9]">Threat Analysis & Incident Forensics</h2>
          <p className="text-xs text-[#94A3B8] mt-1">
            Deterministic rule heuristics and machine learning anomaly incident investigation.
          </p>
        </div>
      </div>

      {/* Summary Stat Cards */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="p-3.5 rounded-xl bg-[#121E32] border border-[#1E2D4A]">
            <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Total Threats</span>
            <p className="text-xl font-black text-[#F1F5F9] mt-0.5">{summary.total_threats}</p>
          </div>
          <div className="p-3.5 rounded-xl bg-[#121E32] border border-[#FF4560]/30">
            <span className="text-[10px] text-[#FF4560] uppercase font-semibold">Critical Incidents</span>
            <p className="text-xl font-black text-[#FF4560] mt-0.5">{summary.critical_threats}</p>
          </div>
          <div className="p-3.5 rounded-xl bg-[#121E32] border border-[#FFB020]/30">
            <span className="text-[10px] text-[#FFB020] uppercase font-semibold">High Severity</span>
            <p className="text-xl font-black text-[#FFB020] mt-0.5">{summary.high_threats}</p>
          </div>
          <div className="p-3.5 rounded-xl bg-[#121E32] border border-[#00C8FF]/30">
            <span className="text-[10px] text-[#00C8FF] uppercase font-semibold">Medium Severity</span>
            <p className="text-xl font-black text-[#00C8FF] mt-0.5">{summary.medium_threats}</p>
          </div>
          <div className="p-3.5 rounded-xl bg-[#121E32] border border-[#087FE5]/30">
            <span className="text-[10px] text-[#087FE5] uppercase font-semibold">Rule Heuristics</span>
            <p className="text-xl font-black text-[#087FE5] mt-0.5">{summary.rule_based_detections}</p>
          </div>
          <div className="p-3.5 rounded-xl bg-[#121E32] border border-[#8B5CF6]/30">
            <span className="text-[10px] text-[#8B5CF6] uppercase font-semibold">ML Anomalies</span>
            <p className="text-xl font-black text-[#8B5CF6] mt-0.5">{summary.ml_anomaly_detections}</p>
          </div>
        </div>
      )}

      {/* Search and Filters Bar */}
      <div className="p-4 rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card flex flex-col sm:flex-row items-center justify-between gap-4">
        {/* Search */}
        <form onSubmit={handleSearchSubmit} className="relative w-full sm:w-80">
          <Search size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8]" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by IP, threat type, or payload..."
            className="w-full pl-9 pr-3 py-2 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-xs text-[#F1F5F9] focus:outline-none focus:border-[#00C8FF]"
          />
        </form>

        {/* Severity Tabs */}
        <div className="flex items-center gap-1.5 p-1 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-xs font-semibold overflow-x-auto w-full sm:w-auto">
          {['All', 'Critical', 'High', 'Medium', 'Low'].map((sev) => (
            <button
              key={sev}
              onClick={() => { setSeverityFilter(sev); setPage(1); }}
              className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
                severityFilter === sev
                  ? 'bg-[#087FE5] text-white shadow-neon-blue'
                  : 'text-[#94A3B8] hover:text-[#F1F5F9]'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Threats Table */}
      <div className="rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-[#0D1526] text-[#94A3B8] border-b border-[#1E2D4A] text-[11px]">
                <th className="p-3.5 font-semibold">Timestamp</th>
                <th className="p-3.5 font-semibold">Source Host</th>
                <th className="p-3.5 font-semibold">Attack Category</th>
                <th className="p-3.5 font-semibold">Detection Engine</th>
                <th className="p-3.5 font-semibold">Severity</th>
                <th className="p-3.5 font-semibold">Evidence Snippet</th>
                <th className="p-3.5 font-semibold text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D4A]/60">
              {loading ? (
                <tr>
                  <td colSpan="7" className="p-8 text-center text-[#94A3B8]">
                    <RefreshCw className="w-6 h-6 text-[#00C8FF] animate-spin mx-auto mb-2" />
                    Loading threat intelligence records...
                  </td>
                </tr>
              ) : threats.length === 0 ? (
                <tr>
                  <td colSpan="7" className="p-8 text-center text-[#94A3B8]">
                    No threat alerts matching query criteria.
                  </td>
                </tr>
              ) : (
                threats.map((threat) => {
                  const isCrit = threat.severity === 'Critical';
                  const isHigh = threat.severity === 'High';
                  const isMed = threat.severity === 'Medium';
                  const sevBadge = isCrit
                    ? 'bg-[#FF4560] text-white shadow-neon-red'
                    : isHigh
                    ? 'bg-[#FFB020] text-black font-bold'
                    : isMed
                    ? 'bg-[#FFB020]/20 text-[#FFB020] border border-[#FFB020]/40'
                    : 'bg-[#00D68F]/20 text-[#00D68F] border border-[#00D68F]/40';

                  const isML = threat.detection_method?.includes('ml') || threat.detection_method?.includes('isolation');

                  return (
                    <tr
                      key={threat.id}
                      onClick={() => setSelectedThreat(threat)}
                      className="hover:bg-[#16253e] cursor-pointer transition-colors"
                    >
                      <td className="p-3.5 font-mono text-[#94A3B8] whitespace-nowrap">
                        {threat.timestamp}
                      </td>
                      <td className="p-3.5 font-mono text-[#00C8FF] font-semibold whitespace-nowrap">
                        {threat.source_ip}
                      </td>
                      <td className="p-3.5 font-semibold text-[#F1F5F9] whitespace-nowrap">
                        {threat.alert_type}
                      </td>
                      <td className="p-3.5 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold flex items-center gap-1 w-fit ${
                          isML ? 'bg-[#8B5CF6]/20 text-[#8B5CF6] border border-[#8B5CF6]/40' : 'bg-[#087FE5]/20 text-[#00A8FF] border border-[#087FE5]/40'
                        }`}>
                          {isML ? <Cpu size={11} /> : <Terminal size={11} />}
                          {isML ? 'Isolation Forest ML' : 'Rule Heuristic'}
                        </span>
                      </td>
                      <td className="p-3.5 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-extrabold uppercase ${sevBadge}`}>
                          {threat.severity}
                        </span>
                      </td>
                      <td className="p-3.5 font-mono text-[#94A3B8] max-w-xs truncate" title={threat.evidence}>
                        {threat.evidence}
                      </td>
                      <td className="p-3.5 text-right whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-[#121E32] text-[#F1F5F9] border border-[#1E2D4A]">
                          {threat.status || 'New'}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div className="flex items-center justify-between p-4 border-t border-[#1E2D4A] text-xs text-[#94A3B8]">
          <span>Showing page {page} of {Math.ceil(total / 20) || 1} ({total} total incidents)</span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="p-1.5 rounded-lg bg-[#080D19] border border-[#1E2D4A] disabled:opacity-40 hover:text-white"
            >
              <ChevronLeft size={16} />
            </button>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={page * 20 >= total}
              className="p-1.5 rounded-lg bg-[#080D19] border border-[#1E2D4A] disabled:opacity-40 hover:text-white"
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </div>

      {/* Forensic Modal */}
      {selectedThreat && (
        <ThreatDetailModal
          threat={selectedThreat}
          onClose={() => setSelectedThreat(null)}
          onStatusChange={handleStatusChange}
        />
      )}
    </div>
  );
};
