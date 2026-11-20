import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Search,
  CheckCircle2,
  Clock,
  ShieldAlert,
  RefreshCw,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import { getAlerts, updateAlertStatus } from '../services/api';
import { ThreatDetailModal } from '../components/ThreatDetailModal';

export const AlertsCenter = () => {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const res = await getAlerts({
        page,
        page_size: 20,
        severity: severityFilter === 'All' ? '' : severityFilter,
        status: statusFilter === 'All' ? '' : statusFilter,
        search
      });
      setAlerts(res.data.items);
      setTotal(res.data.total);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [page, severityFilter, statusFilter]);

  const handleStatusChange = async (alertId, newStatus) => {
    try {
      await updateAlertStatus(alertId, newStatus);
      if (selectedThreat) {
        setSelectedThreat({ ...selectedThreat, status: newStatus });
      }
      fetchAlerts();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1E2D4A]">
        <div>
          <h2 className="text-xl font-bold text-[#F1F5F9]">Security Alerts Center</h2>
          <p className="text-xs text-[#94A3B8] mt-1">
            Triage, acknowledge, and resolve high-priority intrusion alerts across cloud infrastructure.
          </p>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="relative w-full md:w-80">
          <Search size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8]" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by IP, alert type..."
            className="w-full pl-9 pr-3 py-2 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-xs text-[#F1F5F9] focus:outline-none focus:border-[#00C8FF]"
          />
        </div>

        {/* Status Filters */}
        <div className="flex items-center gap-1.5 p-1 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-xs font-semibold overflow-x-auto w-full md:w-auto">
          {['All', 'New', 'Investigating', 'Resolved'].map((st) => (
            <button
              key={st}
              onClick={() => { setStatusFilter(st); setPage(1); }}
              className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
                statusFilter === st
                  ? 'bg-[#087FE5] text-white shadow-neon-blue'
                  : 'text-[#94A3B8] hover:text-[#F1F5F9]'
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        {/* Severity Filter */}
        <div className="flex items-center gap-2 text-xs text-[#94A3B8] w-full md:w-auto">
          <span>Severity:</span>
          <select
            value={severityFilter}
            onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
            className="px-3 py-1.5 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-[#F1F5F9] text-xs focus:outline-none cursor-pointer"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>
      </div>

      {/* Alerts Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {loading ? (
          <div className="col-span-2 p-12 text-center text-[#94A3B8]">
            <RefreshCw className="w-8 h-8 text-[#00C8FF] animate-spin mx-auto mb-2" />
            Loading security incident queue...
          </div>
        ) : alerts.length === 0 ? (
          <div className="col-span-2 p-12 text-center text-[#94A3B8] bg-[#121E32] rounded-2xl border border-[#1E2D4A]">
            No alerts found matching filter criteria.
          </div>
        ) : (
          alerts.map((alert) => {
            const isCrit = alert.severity === 'Critical';
            const isHigh = alert.severity === 'High';
            const badgeClass = isCrit
              ? 'bg-[#FF4560] text-white shadow-neon-red'
              : isHigh
              ? 'bg-[#FFB020] text-black font-bold'
              : 'bg-[#00C8FF]/20 text-[#00C8FF] border border-[#00C8FF]/40';

            return (
              <div
                key={alert.id}
                className="p-5 rounded-2xl bg-[#121E32] border border-[#1E2D4A] hover:border-[#087FE5]/60 shadow-soc-card transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <div className="flex items-center gap-2.5">
                      <div className={`p-2 rounded-xl ${isCrit ? 'bg-[#FF4560]/20 text-[#FF4560]' : 'bg-[#FFB020]/20 text-[#FFB020]'}`}>
                        <ShieldAlert size={18} />
                      </div>
                      <div>
                        <h4 className="text-sm font-bold text-[#F1F5F9]">{alert.alert_type}</h4>
                        <span className="font-mono text-[11px] text-[#00C8FF]">{alert.source_ip}</span>
                      </div>
                    </div>

                    <span className={`px-2.5 py-0.5 rounded-full text-[9px] font-extrabold uppercase ${badgeClass}`}>
                      {alert.severity}
                    </span>
                  </div>

                  <p className="text-xs text-[#94A3B8] my-2 leading-relaxed">
                    {alert.description || alert.evidence}
                  </p>

                  <div className="p-2.5 rounded-xl bg-[#080D19] border border-[#1E2D4A] font-mono text-[11px] text-[#00C8FF] truncate my-2">
                    {alert.evidence}
                  </div>
                </div>

                <div className="flex items-center justify-between pt-3 border-t border-[#1E2D4A]/60 mt-2 text-xs">
                  <span className="text-[11px] text-[#94A3B8] font-mono">
                    {alert.timestamp}
                  </span>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleStatusChange(alert.id, 'Investigating')}
                      className="px-2.5 py-1 text-[11px] font-semibold rounded-lg bg-[#FFB020]/20 text-[#FFB020] border border-[#FFB020]/40 hover:bg-[#FFB020]/30 transition-colors"
                    >
                      Investigate
                    </button>
                    <button
                      onClick={() => handleStatusChange(alert.id, 'Resolved')}
                      className="px-2.5 py-1 text-[11px] font-semibold rounded-lg bg-[#00D68F]/20 text-[#00D68F] border border-[#00D68F]/40 hover:bg-[#00D68F]/30 transition-colors"
                    >
                      Resolve
                    </button>
                    <button
                      onClick={() => setSelectedThreat(alert)}
                      className="px-2.5 py-1 text-[11px] font-semibold rounded-lg bg-[#087FE5]/20 text-[#00A8FF] border border-[#087FE5]/40 hover:bg-[#087FE5]/30 transition-colors"
                    >
                      Drilldown
                    </button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between p-4 bg-[#121E32] rounded-2xl border border-[#1E2D4A] text-xs text-[#94A3B8]">
        <span>Showing page {page} of {Math.ceil(total / 20) || 1} ({total} alerts)</span>
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
