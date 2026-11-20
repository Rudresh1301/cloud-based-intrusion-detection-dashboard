import React, { useState, useEffect } from 'react';
import {
  FileCheck,
  FileDown,
  RefreshCw,
  Calendar,
  Cloud,
  CheckCircle2,
  Download,
  AlertCircle
} from 'lucide-react';
import { generateReport, getReportsList } from '../services/api';

export const Reports = () => {
  const [reports, setReports] = useState([]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [lastGenerated, setLastGenerated] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchReports = async () => {
    try {
      const res = await getReportsList();
      setReports(res.data.items || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const handleGenerate = async () => {
    setIsGenerating(true);
    try {
      const res = await generateReport();
      const report = res.data.report;
      setLastGenerated(report);
      fetchReports();

      // Trigger automatic download
      if (report.download_url) {
        window.open(report.download_url, '_blank');
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1E2D4A]">
        <div>
          <h2 className="text-xl font-bold text-[#F1F5F9]">Security Audit & Executive Reports</h2>
          <p className="text-xs text-[#94A3B8] mt-1">
            Generate formal SOC audit documentation, risk scorecards, and mitigation blueprints in PDF format.
          </p>
        </div>

        <button
          onClick={handleGenerate}
          disabled={isGenerating}
          className="py-2.5 px-6 rounded-xl bg-gradient-to-r from-[#087FE5] to-[#00A8FF] text-white font-bold text-xs shadow-neon-blue hover:brightness-110 transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
        >
          {isGenerating ? (
            <>
              <RefreshCw size={14} className="animate-spin" /> Compiling Report...
            </>
          ) : (
            <>
              <FileDown size={14} /> Generate New Security Audit PDF
            </>
          )}
        </button>
      </div>

      {/* Success Notification */}
      {lastGenerated && (
        <div className="p-4 rounded-xl bg-[#00D68F]/20 border border-[#00D68F]/40 text-[#00D68F] text-xs font-semibold flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 size={16} />
            <span>Audit report successfully compiled and stored: {lastGenerated.filename}</span>
          </div>
          <a
            href={lastGenerated.download_url}
            target="_blank"
            rel="noreferrer"
            className="underline hover:text-white"
          >
            Download Now
          </a>
        </div>
      )}

      {/* Reports Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="p-5 rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card">
          <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Total Reports Compiled</span>
          <p className="text-2xl font-black text-[#F1F5F9] mt-1">{reports.length}</p>
          <span className="text-xs text-[#00C8FF] mt-2 block">SOC Operations Compliance</span>
        </div>

        <div className="p-5 rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card">
          <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Standard Format</span>
          <p className="text-2xl font-black text-[#087FE5] mt-1">PDF / ReportLab</p>
          <span className="text-xs text-[#94A3B8] mt-2 block">Standardized Vector Typography</span>
        </div>

        <div className="p-5 rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card">
          <span className="text-[10px] text-[#94A3B8] uppercase font-semibold">Report Storage</span>
          <p className="text-2xl font-black text-[#00D68F] mt-1">Cloud Storage</p>
          <span className="text-xs text-[#94A3B8] mt-2 block">Persistent Object Bucket</span>
        </div>
      </div>

      {/* Reports Archive Table */}
      <div className="rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card overflow-hidden">
        <div className="p-4 border-b border-[#1E2D4A] flex items-center justify-between">
          <h3 className="text-sm font-bold text-[#F1F5F9] flex items-center gap-2">
            <FileCheck size={16} className="text-[#00C8FF]" /> Audit Reports Archive
          </h3>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-[#0D1526] text-[#94A3B8] border-b border-[#1E2D4A] text-[11px]">
                <th className="p-3.5 font-semibold">Report File Name</th>
                <th className="p-3.5 font-semibold">Generation Date</th>
                <th className="p-3.5 font-semibold">Audited Events</th>
                <th className="p-3.5 font-semibold">Threats Flagged</th>
                <th className="p-3.5 font-semibold">Storage Provider</th>
                <th className="p-3.5 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D4A]/60">
              {loading ? (
                <tr>
                  <td colSpan="6" className="p-8 text-center text-[#94A3B8]">
                    <RefreshCw className="w-6 h-6 text-[#00C8FF] animate-spin mx-auto mb-2" />
                    Loading report archive...
                  </td>
                </tr>
              ) : reports.length === 0 ? (
                <tr>
                  <td colSpan="6" className="p-8 text-center text-[#94A3B8]">
                    No reports generated yet. Click "Generate New Security Audit PDF" above.
                  </td>
                </tr>
              ) : (
                reports.map((rep) => (
                  <tr key={rep.id} className="hover:bg-[#16253e] transition-colors">
                    <td className="p-3.5 font-mono text-[#F1F5F9] font-semibold whitespace-nowrap">
                      {rep.filename}
                    </td>
                    <td className="p-3.5 font-mono text-[#94A3B8] whitespace-nowrap">
                      {rep.generated_at?.slice(0, 19).replace('T', ' ')}
                    </td>
                    <td className="p-3.5 font-mono text-[#00C8FF] whitespace-nowrap">
                      {rep.total_events}
                    </td>
                    <td className="p-3.5 font-mono text-[#FF4560] font-bold whitespace-nowrap">
                      {rep.threats_found}
                    </td>
                    <td className="p-3.5 text-[#94A3B8] whitespace-nowrap">
                      <span className="flex items-center gap-1.5">
                        <Cloud size={13} className="text-[#087FE5]" />
                        {rep.storage_type}
                      </span>
                    </td>
                    <td className="p-3.5 text-right whitespace-nowrap">
                      <a
                        href={`/api/reports/download/${rep.filename}`}
                        target="_blank"
                        rel="noreferrer"
                        className="py-1 px-3 rounded-lg bg-[#087FE5]/20 text-[#00A8FF] border border-[#087FE5]/40 hover:bg-[#087FE5]/30 text-xs font-semibold inline-flex items-center gap-1 transition-colors"
                      >
                        <Download size={12} /> Download
                      </a>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
