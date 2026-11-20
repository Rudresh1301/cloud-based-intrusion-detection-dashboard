import React from 'react';
import { X, Globe, Shield, MapPin, Server, Activity } from 'lucide-react';

export const IPDetailModal = ({ ipProfile, onClose }) => {
  if (!ipProfile) return null;

  const riskScore = ipProfile.risk_score || 0;
  const isHighRisk = riskScore >= 50;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-xl rounded-2xl bg-[#0D1526] border border-[#1E2D4A] shadow-2xl p-6 overflow-hidden">
        {/* Header */}
        <div className="flex items-start justify-between pb-4 border-b border-[#1E2D4A]">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl border ${isHighRisk ? 'bg-[#FF4560]/20 border-[#FF4560]/40 text-[#FF4560]' : 'bg-[#00D68F]/20 border-[#00D68F]/40 text-[#00D68F]'}`}>
              <Globe size={22} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-base font-bold text-[#F1F5F9]">
                  {ipProfile.ip_address}
                </span>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${isHighRisk ? 'bg-[#FF4560]/20 text-[#FF4560] border border-[#FF4560]/40' : 'bg-[#00D68F]/20 text-[#00D68F] border border-[#00D68F]/40'}`}>
                  {ipProfile.threat_status || 'Clean'}
                </span>
              </div>
              <p className="text-xs text-[#94A3B8] mt-0.5">
                {ipProfile.city}, {ipProfile.country}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#94A3B8] hover:text-[#F1F5F9] hover:bg-[#121E32] transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="py-4 space-y-4 text-xs">
          {/* Risk Metric Box */}
          <div className="flex items-center justify-between p-4 rounded-xl bg-[#121E32] border border-[#1E2D4A]">
            <div>
              <span className="text-[#94A3B8] text-[10px] uppercase font-semibold">Reputation Threat Score</span>
              <h4 className="text-2xl font-black text-[#F1F5F9] mt-0.5 font-mono">
                {riskScore} <span className="text-xs font-normal text-[#94A3B8]">/ 100</span>
              </h4>
            </div>
            <div className="text-right">
              <span className="text-[#94A3B8] text-[10px] uppercase font-semibold">Total Telemetry Events</span>
              <p className="text-lg font-bold text-[#00C8FF] mt-0.5">{ipProfile.total_events || 0}</p>
            </div>
          </div>

          {/* Network Location Intelligence */}
          <div className="p-3.5 rounded-xl bg-[#121E32]/60 border border-[#1E2D4A] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[#94A3B8] flex items-center gap-1.5"><MapPin size={14} className="text-[#00A8FF]" /> Geolocation</span>
              <span className="font-semibold text-[#F1F5F9]">{ipProfile.city}, {ipProfile.country} ({ipProfile.country_code || 'LOC'})</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[#94A3B8] flex items-center gap-1.5"><Server size={14} className="text-[#8B5CF6]" /> Network ISP / AS</span>
              <span className="font-semibold text-[#F1F5F9]">{ipProfile.isp || 'Enterprise Gateway'}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[#94A3B8] flex items-center gap-1.5"><Activity size={14} className="text-[#FF4560]" /> Flagged Suspicious Events</span>
              <span className="font-bold text-[#FF4560]">{ipProfile.suspicious_events || 0} incidents</span>
            </div>
          </div>

          {/* Attack Categories */}
          <div>
            <h5 className="font-bold text-[#F1F5F9] text-xs uppercase tracking-wider mb-1.5">
              Associated Attack Signatures
            </h5>
            <div className="flex flex-wrap gap-1.5">
              {ipProfile.attack_categories && ipProfile.attack_categories.length > 0 ? (
                ipProfile.attack_categories.map((cat, i) => (
                  <span
                    key={i}
                    className="px-2.5 py-1 rounded-lg bg-[#FF4560]/15 text-[#FF4560] border border-[#FF4560]/30 font-medium text-[11px]"
                  >
                    {cat}
                  </span>
                ))
              ) : (
                <span className="text-[#94A3B8] italic">No malicious attack categories triggered by this host.</span>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex justify-end pt-4 border-t border-[#1E2D4A]">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold rounded-xl bg-[#121E32] border border-[#1E2D4A] hover:bg-[#16253e] text-[#F1F5F9] transition-colors"
          >
            Close Intelligence View
          </button>
        </div>
      </div>
    </div>
  );
};
