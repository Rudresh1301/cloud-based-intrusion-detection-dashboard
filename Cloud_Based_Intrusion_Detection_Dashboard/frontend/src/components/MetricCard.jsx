import React from 'react';
import { ResponsiveContainer, LineChart, Line } from 'recharts';

export const MetricCard = ({ title, value, trend, icon: Icon, colorTheme = 'blue', sparklineData }) => {
  // Color configuration matching SOC aesthetics
  const themes = {
    blue: {
      bg: 'from-[#087FE5]/10 to-transparent',
      border: 'hover:border-[#087FE5]/50',
      iconBg: 'bg-[#087FE5]/20 border-[#087FE5]/40 text-[#00C8FF]',
      trendColor: 'text-[#00D68F]',
      stroke: '#087FE5',
    },
    red: {
      bg: 'from-[#FF4560]/10 to-transparent',
      border: 'hover:border-[#FF4560]/50',
      iconBg: 'bg-[#FF4560]/20 border-[#FF4560]/40 text-[#FF4560]',
      trendColor: 'text-[#FF4560]',
      stroke: '#FF4560',
    },
    green: {
      bg: 'from-[#00D68F]/10 to-transparent',
      border: 'hover:border-[#00D68F]/50',
      iconBg: 'bg-[#00D68F]/20 border-[#00D68F]/40 text-[#00D68F]',
      trendColor: 'text-[#00D68F]',
      stroke: '#00D68F',
    },
    purple: {
      bg: 'from-[#8B5CF6]/10 to-transparent',
      border: 'hover:border-[#8B5CF6]/50',
      iconBg: 'bg-[#8B5CF6]/20 border-[#8B5CF6]/40 text-[#8B5CF6]',
      trendColor: 'text-[#00C8FF]',
      stroke: '#8B5CF6',
    },
  };

  const currentTheme = themes[colorTheme] || themes.blue;

  // Default sparkline trend if not provided
  const dummySpark = sparklineData || [
    { val: 12 }, { val: 19 }, { val: 15 }, { val: 24 }, { val: 20 }, { val: 28 }, { val: 32 }
  ];

  return (
    <div
      className={`relative overflow-hidden rounded-2xl bg-[#121E32] border border-[#1E2D4A] p-5 shadow-soc-card transition-all duration-300 ${currentTheme.border} bg-gradient-to-b ${currentTheme.bg}`}
    >
      <div className="flex items-start justify-between">
        {/* Left: Icon & Title & Value */}
        <div className="flex items-center gap-3.5">
          <div className={`p-3 rounded-xl border flex-shrink-0 ${currentTheme.iconBg}`}>
            <Icon size={22} />
          </div>
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
              {title}
            </span>
            <h3 className="text-2xl font-extrabold text-[#F1F5F9] tracking-tight mt-0.5">
              {typeof value === 'number' ? value.toLocaleString() : value}
            </h3>
            {trend && (
              <span className={`text-xs font-semibold flex items-center gap-1 mt-1 ${currentTheme.trendColor}`}>
                {trend}
              </span>
            )}
          </div>
        </div>

        {/* Right: Sparkline Mini Chart */}
        <div className="w-24 h-12 flex-shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={dummySpark}>
              <Line
                type="monotone"
                dataKey="val"
                stroke={currentTheme.stroke}
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};
