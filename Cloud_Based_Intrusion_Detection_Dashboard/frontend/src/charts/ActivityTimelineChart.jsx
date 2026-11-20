import React from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-[#121E32] border border-[#1E2D4A] p-3 rounded-xl shadow-soc-card text-xs">
        <p className="font-semibold text-[#F1F5F9] mb-1.5">{label}</p>
        <div className="flex items-center gap-2 text-[#00C8FF]">
          <span className="w-2 h-2 rounded-full bg-[#00C8FF]" />
          <span>Normal Traffic: <b>{payload[0].value.toLocaleString()}</b></span>
        </div>
        {payload[1] && (
          <div className="flex items-center gap-2 text-[#FF4560] mt-1">
            <span className="w-2 h-2 rounded-full bg-[#FF4560]" />
            <span>Threats: <b>{payload[1].value.toLocaleString()}</b></span>
          </div>
        )}
      </div>
    );
  }
  return null;
};

export const ActivityTimelineChart = ({ data }) => {
  const chartData = data && data.length > 0 ? data : [
    { time: '12AM', normal_traffic: 320, threats: 45 },
    { time: '4AM', normal_traffic: 540, threats: 80 },
    { time: '8AM', normal_traffic: 680, threats: 190 },
    { time: '12PM', normal_traffic: 610, threats: 140 },
    { time: '4PM', normal_traffic: 980, threats: 240 },
    { time: '8PM', normal_traffic: 790, threats: 160 },
  ];

  return (
    <div className="w-full h-64">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="normalGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#00A8FF" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#087FE5" stopOpacity={0.0} />
            </linearGradient>
            <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#FF4560" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#FF4560" stopOpacity={0.0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1E2D4A" opacity={0.6} vertical={false} />
          <XAxis
            dataKey="time"
            stroke="#94A3B8"
            tick={{ fill: '#94A3B8', fontSize: 11 }}
            axisLine={{ stroke: '#1E2D4A' }}
            tickLine={false}
          />
          <YAxis
            stroke="#94A3B8"
            tick={{ fill: '#94A3B8', fontSize: 11 }}
            axisLine={{ stroke: '#1E2D4A' }}
            tickLine={false}
          />
          <Tooltip content={<CustomTooltip />} />
          <Area
            type="monotone"
            dataKey="normal_traffic"
            stroke="#00C8FF"
            strokeWidth={2.5}
            fillOpacity={1}
            fill="url(#normalGrad)"
            name="Normal Traffic"
          />
          <Area
            type="monotone"
            dataKey="threats"
            stroke="#FF4560"
            strokeWidth={2.5}
            fillOpacity={1}
            fill="url(#threatGrad)"
            name="Threats"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};
