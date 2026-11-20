import React from 'react';
import { ShieldAlert } from 'lucide-react';

export const RiskGauge = ({ riskInfo }) => {
  const level = riskInfo?.level || 'HIGH RISK';
  const percentage = riskInfo?.percentage || 85;
  const description = riskInfo?.description || 'Immediate attention required!';

  // SVG circular gauge math
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  const isCrit = level.includes('CRITICAL');
  const isHigh = level.includes('HIGH');
  const ringColor = isCrit || isHigh ? '#FF4560' : (level.includes('MEDIUM') ? '#FFB020' : '#00D68F');

  return (
    <div className="flex items-center justify-between p-5 rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card bg-gradient-to-r from-[#FF4560]/10 to-transparent">
      {/* Left Info */}
      <div className="flex items-start gap-4">
        <div className="p-3 rounded-xl bg-[#FF4560]/20 border border-[#FF4560]/40 text-[#FF4560] flex-shrink-0">
          <ShieldAlert size={26} />
        </div>
        <div>
          <span className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
            Risk Level
          </span>
          <h4
            className="text-xl font-black tracking-tight mt-0.5"
            style={{ color: ringColor }}
          >
            {level}
          </h4>
          <p className="text-xs text-[#94A3B8] mt-0.5 max-w-[200px]">
            {description}
          </p>
        </div>
      </div>

      {/* Right Circular Gauge */}
      <div className="relative w-24 h-24 flex items-center justify-center flex-shrink-0">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
          {/* Background circle */}
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="transparent"
            stroke="#1E2D4A"
            strokeWidth="9"
          />
          {/* Progress circle */}
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="transparent"
            stroke={ringColor}
            strokeWidth="9"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.8s ease-in-out' }}
          />
        </svg>

        {/* Center Percentage */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <span className="text-lg font-black text-[#F1F5F9] font-mono">
            {percentage}%
          </span>
        </div>
      </div>
    </div>
  );
};
