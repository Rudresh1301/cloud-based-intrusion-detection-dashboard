import React from 'react';
import { X, ShieldAlert, AlertCircle, CheckCircle2, Terminal, ArrowRight } from 'lucide-react';

export const ThreatDetailModal = ({ threat, onClose, onStatusChange }) => {
  if (!threat) return null;

  const isCritical = threat.severity === 'Critical';
  const isHigh = threat.severity === 'High';
  const badgeColor = isCritical
    ? 'bg-[#FF4560]/20 text-[#FF4560] border-[#FF4560]/40'
    : isHigh
    ? 'bg-[#FFB020]/20 text-[#FFB020] border-[#FFB020]/40'
    : 'bg-[#00C8FF]/20 text-[#00C8FF] border-[#00C8FF]/40';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-2xl rounded-2xl bg-[#0D1526] border border-[#1E2D4A] shadow-2xl p-6 overflow-hidden max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-start justify-between pb-4 border-b border-[#1E2D4A]">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-[#FF4560]/20 border border-[#FF4560]/40 text-[#FF4560]">
              <ShieldAlert size={22} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase border ${badgeColor}`}>
                  {threat.severity}
                </span>
                <span className="text-xs text-[#94A3B8]">
                  ID: {threat.id}
                </span>
              </div>
              <h3 className="text-lg font-bold text-[#F1F5F9] mt-1">
                {threat.alert_type}
              </h3>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#94A3B8] hover:text-[#F1F5F9] hover:bg-[#121E32] transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {/* Content Body */}
        <div className="py-4 space-y-4 text-xs">
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 rounded-xl bg-[#121E32] border border-[#1E2D4A]">
            <div>
              <span className="text-[#94A3B8] text-[10px] uppercase font-semibold">Source Host</span>
              <p className="font-mono text-[#00C8FF] font-semibold mt-0.5">{threat.source_ip}</p>
            </div>
            <div>
              <span className="text-[#94A3B8] text-[10px] uppercase font-semibold">Timestamp</span>
              <p className="font-mono text-[#F1F5F9] mt-0.5">{threat.timestamp}</p>
            </div>
            <div>
              <span className="text-[#94A3B8] text-[10px] uppercase font-semibold">Detection Engine</span>
              <p className="text-[#00D68F] font-semibold mt-0.5 capitalize">{threat.detection_method || 'Rule-Based Heuristic'}</p>
            </div>
            <div>
              <span className="text-[#94A3B8] text-[10px] uppercase font-semibold">Status</span>
              <p className="text-[#FFB020] font-semibold mt-0.5">{threat.status || 'New'}</p>
            </div>
          </div>

          {/* Description */}
          <div>
            <h5 className="font-bold text-[#F1F5F9] text-xs uppercase tracking-wider mb-1">
              Incident Summary
            </h5>
            <p className="text-[#94A3B8] leading-relaxed bg-[#121E32]/50 p-3 rounded-xl border border-[#1E2D4A]">
              {threat.description || 'Threat pattern detected across ingested log sequence.'}
            </p>
          </div>

          {/* Technical Evidence */}
          <div>
            <h5 className="font-bold text-[#F1F5F9] text-xs uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <Terminal size={14} className="text-[#00C8FF]" /> Forensic Evidence Payload
            </h5>
            <div className="p-3 rounded-xl bg-[#080D19] border border-[#1E2D4A] font-mono text-[#00C8FF] text-[11px] break-all select-all">
              {threat.evidence || 'Pattern match found in request parameters.'}
            </div>
          </div>

          {/* Mitigation Strategy */}
          <div>
            <h5 className="font-bold text-[#F1F5F9] text-xs uppercase tracking-wider mb-1 flex items-center gap-1.5 text-[#00D68F]">
              <CheckCircle2 size={14} /> Recommended Security Countermeasure
            </h5>
            <p className="text-[#F1F5F9] bg-[#00D68F]/10 p-3 rounded-xl border border-[#00D68F]/30 leading-relaxed">
              {threat.recommended_action || 'Enforce strict WAF rule and apply adaptive IP throttling.'}
            </p>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-4 border-t border-[#1E2D4A]">
          <div className="flex items-center gap-2">
            <span className="text-xs text-[#94A3B8]">Change Status:</span>
            <button
              onClick={() => onStatusChange(threat.id, 'Investigating')}
              className="px-3 py-1 text-xs rounded-lg bg-[#FFB020]/20 text-[#FFB020] border border-[#FFB020]/40 hover:bg-[#FFB020]/30 transition-colors"
            >
              Investigating
            </button>
            <button
              onClick={() => onStatusChange(threat.id, 'Resolved')}
              className="px-3 py-1 text-xs rounded-lg bg-[#00D68F]/20 text-[#00D68F] border border-[#00D68F]/40 hover:bg-[#00D68F]/30 transition-colors"
            >
              Mark Resolved
            </button>
          </div>

          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold rounded-xl bg-[#121E32] border border-[#1E2D4A] hover:bg-[#16253e] text-[#F1F5F9] transition-colors"
          >
            Close Drilldown
          </button>
        </div>
      </div>
    </div>
  );
};
