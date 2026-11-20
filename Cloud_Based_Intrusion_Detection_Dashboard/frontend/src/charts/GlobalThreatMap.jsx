import React, { useState } from 'react';
import { Maximize2, Minimize2 } from 'lucide-react';

export const GlobalThreatMap = ({ points }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [activeTooltip, setActiveTooltip] = useState(null);

  // Default demonstration attack locations matching SOC visualization
  const mapHotspots = points && points.length > 0 ? points : [
    { ip: '103.21.45.67', x: 67, y: 48, city: 'Mumbai', country: 'India', severity: 'Critical', attacks: 120 },
    { ip: '45.77.89.12', x: 26, y: 35, city: 'New York', country: 'United States', severity: 'High', attacks: 54 },
    { ip: '91.203.12.78', x: 52, y: 32, city: 'Frankfurt', country: 'Germany', severity: 'Low', attacks: 42 },
    { ip: '185.220.101.5', x: 49, y: 28, city: 'Amsterdam', country: 'Netherlands', severity: 'Critical', attacks: 89 },
    { ip: '203.114.108.45', x: 88, y: 78, city: 'Sydney', country: 'Australia', severity: 'Medium', attacks: 35 },
  ];

  return (
    <div className={`relative w-full ${isExpanded ? 'h-96' : 'h-64'} transition-all duration-300 flex items-center justify-center overflow-hidden rounded-xl bg-[#080D19]/60 border border-[#1E2D4A]`}>
      {/* Expand / Minimize Button */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="absolute top-2.5 right-2.5 z-20 p-1.5 rounded-lg bg-[#121E32]/80 border border-[#1E2D4A] text-[#94A3B8] hover:text-[#00C8FF] hover:border-[#00C8FF]/40 transition-colors"
        title={isExpanded ? 'Shrink Map' : 'Expand Map'}
      >
        {isExpanded ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
      </button>

      {/* World Map Background Vector SVG */}
      <svg
        className="w-full h-full object-contain opacity-35"
        viewBox="0 0 1000 500"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          d="M150 120 Q 200 90 280 130 T 360 210 T 260 380 T 170 280 Z"
          fill="#087FE5"
          opacity="0.25"
        />
        <path
          d="M450 110 Q 550 70 650 110 T 600 230 T 470 200 Z"
          fill="#087FE5"
          opacity="0.25"
        />
        <path
          d="M480 230 Q 560 230 580 320 T 520 440 T 460 310 Z"
          fill="#087FE5"
          opacity="0.2"
        />
        <path
          d="M650 120 Q 820 90 920 180 T 850 320 T 700 240 Z"
          fill="#087FE5"
          opacity="0.3"
        />
        <path
          d="M800 370 Q 890 350 920 420 T 820 450 Z"
          fill="#087FE5"
          opacity="0.25"
        />
        {/* Subtle coordinate grid lines */}
        <line x1="0" y1="250" x2="1000" y2="250" stroke="#1E2D4A" strokeWidth="0.8" strokeDasharray="5 5" />
        <line x1="500" y1="0" x2="500" y2="500" stroke="#1E2D4A" strokeWidth="0.8" strokeDasharray="5 5" />
      </svg>

      {/* Pulsing Threat Hotspots */}
      <div className="absolute inset-0">
        {mapHotspots.map((spot, i) => {
          // Normalize lat/lon to percentage coordinates if present
          let posX = spot.x;
          let posY = spot.y;
          if (spot.lon !== undefined && spot.lat !== undefined) {
            posX = ((spot.lon + 180) / 360) * 100;
            posY = ((90 - spot.lat) / 180) * 100;
          }

          const isCrit = spot.severity === 'Critical';
          const dotColor = isCrit ? '#FF4560' : (spot.severity === 'High' ? '#FFB020' : '#00C8FF');

          return (
            <div
              key={i}
              className="absolute -translate-x-1/2 -translate-y-1/2 cursor-pointer group"
              style={{ left: `${posX}%`, top: `${posY}%` }}
              onMouseEnter={() => setActiveTooltip(spot)}
              onMouseLeave={() => setActiveTooltip(null)}
            >
              {/* Outer pulsing ping */}
              <span
                className="animate-ping absolute inline-flex h-6 w-6 rounded-full opacity-75"
                style={{ backgroundColor: dotColor }}
              />
              {/* Core dot */}
              <span
                className="relative inline-flex rounded-full h-3 w-3 border border-white shadow-neon-red"
                style={{ backgroundColor: dotColor }}
              />

              {/* Tooltip on hover */}
              {activeTooltip === spot && (
                <div className="absolute bottom-5 left-1/2 -translate-x-1/2 z-30 min-w-[130px] p-2 bg-[#121E32] border border-[#1E2D4A] rounded-xl shadow-soc-card text-[10px] pointer-events-none whitespace-nowrap">
                  <p className="font-bold text-[#F1F5F9]">{spot.city}, {spot.country}</p>
                  <p className="font-mono text-[#00C8FF] text-[9px]">{spot.ip}</p>
                  <p className="text-[#FF4560] font-semibold mt-0.5">{spot.attacks} hostile attempts</p>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
