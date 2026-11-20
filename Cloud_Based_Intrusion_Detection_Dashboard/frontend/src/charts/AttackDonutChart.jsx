import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

export const AttackDonutChart = ({ distribution, totalThreats }) => {
  const data = distribution && distribution.length > 0 ? distribution : [
    { name: 'Brute Force', count: 206, percentage: 42.7, color: '#FF4560' },
    { name: 'Suspicious Login', count: 150, percentage: 31.1, color: '#FFB020' },
    { name: 'SQL Injection', count: 75, percentage: 15.6, color: '#00C8FF' },
    { name: 'Other Attacks', count: 51, percentage: 10.6, color: '#087FE5' },
  ];

  const total = totalThreats || data.reduce((acc, curr) => acc + curr.count, 0);

  return (
    <div className="flex flex-col sm:flex-row items-center justify-between gap-4 h-64">
      {/* Donut Chart with Center Label */}
      <div className="relative w-48 h-48 flex-shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const d = payload[0].payload;
                  return (
                    <div className="bg-[#121E32] border border-[#1E2D4A] p-2.5 rounded-xl shadow-soc-card text-xs">
                      <span className="font-semibold text-[#F1F5F9]">{d.name}</span>
                      <p className="text-[#94A3B8]">{d.count} events ({d.percentage}%)</p>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Pie
              data={data}
              innerRadius={52}
              outerRadius={75}
              paddingAngle={4}
              dataKey="count"
              stroke="none"
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>

        {/* Center Text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-xl font-bold text-[#F1F5F9] tracking-tight">
            {total}
          </span>
          <span className="text-[10px] uppercase font-semibold text-[#94A3B8] tracking-wider">
            Threats
          </span>
        </div>
      </div>

      {/* Legend List */}
      <div className="flex-1 w-full space-y-2.5 pl-2">
        {data.map((item) => (
          <div key={item.name} className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <span
                className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                style={{ backgroundColor: item.color }}
              />
              <span className="text-[#F1F5F9] font-medium truncate max-w-[120px]">
                {item.name}
              </span>
            </div>
            <span className="font-mono text-[#94A3B8] font-semibold">
              {item.percentage}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};
