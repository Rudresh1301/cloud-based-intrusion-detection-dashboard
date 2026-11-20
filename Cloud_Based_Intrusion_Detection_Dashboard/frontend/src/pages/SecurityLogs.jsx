import React, { useState, useEffect } from 'react';
import {
  FileText,
  Search,
  Filter,
  Download,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  Database
} from 'lucide-react';
import { getSecurityLogs, exportLogsCsv } from '../services/api';

export const SecurityLogs = () => {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [classificationFilter, setClassificationFilter] = useState('All');
  const [loading, setLoading] = useState(true);
  const [isExporting, setIsExporting] = useState(false);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await getSecurityLogs({
        page,
        page_size: 25,
        search,
        classification: classificationFilter === 'All' ? '' : classificationFilter
      });
      setLogs(res.data.items);
      setTotal(res.data.total);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [page, classificationFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    fetchLogs();
  };

  const handleExportCsv = async () => {
    setIsExporting(true);
    try {
      const res = await exportLogsCsv({
        search,
        classification: classificationFilter === 'All' ? '' : classificationFilter
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', 'soc_security_logs_export.csv');
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      console.error(err);
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1E2D4A]">
        <div>
          <h2 className="text-xl font-bold text-[#F1F5F9]">Security Telemetry Logs Explorer</h2>
          <p className="text-xs text-[#94A3B8] mt-1">
            Browse and query ingested security log transactions stored in Firestore cloud database.
          </p>
        </div>

        <button
          onClick={handleExportCsv}
          disabled={isExporting}
          className="py-2 px-4 rounded-xl bg-[#121E32] border border-[#1E2D4A] hover:border-[#00C8FF]/40 text-[#00C8FF] font-semibold text-xs flex items-center gap-2 transition-colors cursor-pointer disabled:opacity-50"
        >
          {isExporting ? <RefreshCw size={14} className="animate-spin" /> : <Download size={14} />}
          Export CSV
        </button>
      </div>

      {/* Search and Filters */}
      <div className="p-4 rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card flex flex-col md:flex-row items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="relative w-full md:w-80">
          <Search size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8]" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by IP, username, endpoint..."
            className="w-full pl-9 pr-3 py-2 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-xs text-[#F1F5F9] focus:outline-none focus:border-[#00C8FF]"
          />
        </form>

        <div className="flex items-center gap-1.5 p-1 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-xs font-semibold overflow-x-auto w-full md:w-auto">
          {['All', 'Normal', 'Brute Force', 'SQL Injection', 'Cross-Site Scripting'].map((cat) => (
            <button
              key={cat}
              onClick={() => { setClassificationFilter(cat); setPage(1); }}
              className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer whitespace-nowrap ${
                classificationFilter === cat
                  ? 'bg-[#087FE5] text-white shadow-neon-blue'
                  : 'text-[#94A3B8] hover:text-[#F1F5F9]'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Logs Table */}
      <div className="rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-[#0D1526] text-[#94A3B8] border-b border-[#1E2D4A] text-[11px]">
                <th className="p-3.5 font-semibold">Timestamp</th>
                <th className="p-3.5 font-semibold">Source Host</th>
                <th className="p-3.5 font-semibold">Identity</th>
                <th className="p-3.5 font-semibold">Event Action</th>
                <th className="p-3.5 font-semibold">Status</th>
                <th className="p-3.5 font-semibold">Target Resource</th>
                <th className="p-3.5 font-semibold text-right">SOC Classification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D4A]/60">
              {loading ? (
                <tr>
                  <td colSpan="7" className="p-8 text-center text-[#94A3B8]">
                    <RefreshCw className="w-6 h-6 text-[#00C8FF] animate-spin mx-auto mb-2" />
                    Querying cloud logs collection...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan="7" className="p-8 text-center text-[#94A3B8]">
                    No security log entries match current filter parameters.
                  </td>
                </tr>
              ) : (
                logs.map((row) => {
                  const isAttack = row.classification && row.classification !== 'Normal';
                  return (
                    <tr key={row.id} className="hover:bg-[#16253e] transition-colors">
                      <td className="p-3.5 font-mono text-[#94A3B8] whitespace-nowrap">
                        {row.timestamp}
                      </td>
                      <td className="p-3.5 font-mono text-[#00C8FF] font-semibold whitespace-nowrap">
                        {row.source_ip}
                      </td>
                      <td className="p-3.5 text-[#F1F5F9] whitespace-nowrap">
                        {row.username || 'anonymous'}
                      </td>
                      <td className="p-3.5 font-semibold text-[#F1F5F9] whitespace-nowrap">
                        {row.event_type}
                      </td>
                      <td className="p-3.5 font-mono text-xs whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          row.status === 'success' || row.status === '200'
                            ? 'bg-[#00D68F]/20 text-[#00D68F]'
                            : 'bg-[#FF4560]/20 text-[#FF4560]'
                        }`}>
                          {row.status}
                        </span>
                      </td>
                      <td className="p-3.5 font-mono text-[#94A3B8] max-w-xs truncate" title={row.endpoint}>
                        {row.endpoint}
                      </td>
                      <td className="p-3.5 text-right whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                          isAttack
                            ? 'bg-[#FF4560]/20 text-[#FF4560] border border-[#FF4560]/40'
                            : 'bg-[#00D68F]/20 text-[#00D68F] border border-[#00D68F]/40'
                        }`}>
                          {row.classification || 'Normal'}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="flex items-center justify-between p-4 border-t border-[#1E2D4A] text-xs text-[#94A3B8]">
          <span>Showing page {page} of {Math.ceil(total / 25) || 1} ({total} total records)</span>
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
              disabled={page * 25 >= total}
              className="p-1.5 rounded-lg bg-[#080D19] border border-[#1E2D4A] disabled:opacity-40 hover:text-white"
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
