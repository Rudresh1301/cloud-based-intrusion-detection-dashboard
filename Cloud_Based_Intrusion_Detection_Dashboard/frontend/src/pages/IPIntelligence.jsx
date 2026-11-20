import React, { useState, useEffect } from 'react';
import {
  Globe,
  Search,
  Filter,
  ShieldAlert,
  Server,
  MapPin,
  RefreshCw,
  ArrowRight
} from 'lucide-react';
import { getIPIntelligence } from '../services/api';
import { IPDetailModal } from '../components/IPDetailModal';

export const IPIntelligence = () => {
  const [ips, setIps] = useState([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');
  const [threatStatusFilter, setThreatStatusFilter] = useState('All');
  const [minRisk, setMinRisk] = useState(0);
  const [selectedIP, setSelectedIP] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchIPs = async () => {
    setLoading(true);
    try {
      const res = await getIPIntelligence({
        search,
        threat_status: threatStatusFilter === 'All' ? '' : threatStatusFilter,
        min_risk: minRisk
      });
      setIps(res.data.items);
      setTotal(res.data.total);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIPs();
  }, [threatStatusFilter, minRisk]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchIPs();
  };

  return (
    <div className="space-y-6 animate-fadeIn max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1E2D4A]">
        <div>
          <h2 className="text-xl font-bold text-[#F1F5F9]">IP Threat Intelligence & Geolocation</h2>
          <p className="text-xs text-[#94A3B8] mt-1">
            Correlate host reputations, telemetry event volumes, attack signatures, and autonomous network ASN routing.
          </p>
        </div>
        <div className="text-xs font-semibold text-[#00C8FF] bg-[#121E32] px-3 py-1.5 rounded-xl border border-[#1E2D4A]">
          {total} Profiled Hosts
        </div>
      </div>

      {/* Search & Filters */}
      <div className="p-4 rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Search Input */}
        <form onSubmit={handleSearchSubmit} className="relative w-full md:w-80">
          <Search size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8]" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search IP address or network..."
            className="w-full pl-9 pr-3 py-2 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-xs text-[#F1F5F9] focus:outline-none focus:border-[#00C8FF]"
          />
        </form>

        {/* Threat Status Filter Tabs */}
        <div className="flex items-center gap-1.5 p-1 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-xs font-semibold overflow-x-auto w-full md:w-auto">
          {['All', 'Critical', 'High', 'Medium', 'Low', 'Clean'].map((status) => (
            <button
              key={status}
              onClick={() => setThreatStatusFilter(status)}
              className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
                threatStatusFilter === status
                  ? 'bg-[#087FE5] text-white shadow-neon-blue'
                  : 'text-[#94A3B8] hover:text-[#F1F5F9]'
              }`}
            >
              {status}
            </button>
          ))}
        </div>

        {/* Min Risk Slider */}
        <div className="flex items-center gap-2 text-xs text-[#94A3B8] w-full md:w-auto">
          <span>Min Risk:</span>
          <input
            type="range"
            min="0"
            max="80"
            step="10"
            value={minRisk}
            onChange={(e) => setMinRisk(Number(e.target.value))}
            className="w-24 accent-[#00C8FF]"
          />
          <span className="font-mono text-[#00C8FF] font-bold min-w-[25px]">{minRisk}</span>
        </div>
      </div>

      {/* IP Profiles Grid / Table */}
      <div className="rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-[#0D1526] text-[#94A3B8] border-b border-[#1E2D4A] text-[11px]">
                <th className="p-3.5 font-semibold">IP Address</th>
                <th className="p-3.5 font-semibold">Location / Country</th>
                <th className="p-3.5 font-semibold">Autonomous System / ISP</th>
                <th className="p-3.5 font-semibold">Total Telemetry</th>
                <th className="p-3.5 font-semibold">Flagged Hostile</th>
                <th className="p-3.5 font-semibold">Risk Score</th>
                <th className="p-3.5 font-semibold text-right">Threat Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D4A]/60">
              {loading ? (
                <tr>
                  <td colSpan="7" className="p-8 text-center text-[#94A3B8]">
                    <RefreshCw className="w-6 h-6 text-[#00C8FF] animate-spin mx-auto mb-2" />
                    Loading IP intelligence data...
                  </td>
                </tr>
              ) : ips.length === 0 ? (
                <tr>
                  <td colSpan="7" className="p-8 text-center text-[#94A3B8]">
                    No IP addresses found matching filter parameters.
                  </td>
                </tr>
              ) : (
                ips.map((item) => {
                  const risk = item.risk_score || 0;
                  const isCrit = item.threat_status === 'Critical' || risk >= 80;
                  const isHigh = item.threat_status === 'High' || (risk >= 50 && risk < 80);
                  const isMed = item.threat_status === 'Medium';
                  const sevBadge = isCrit
                    ? 'bg-[#FF4560] text-white shadow-neon-red'
                    : isHigh
                    ? 'bg-[#FFB020] text-black font-bold'
                    : isMed
                    ? 'bg-[#FFB020]/20 text-[#FFB020] border border-[#FFB020]/40'
                    : 'bg-[#00D68F]/20 text-[#00D68F] border border-[#00D68F]/40';

                  return (
                    <tr
                      key={item.ip_address}
                      onClick={() => setSelectedIP(item)}
                      className="hover:bg-[#16253e] cursor-pointer transition-colors"
                    >
                      <td className="p-3.5 font-mono text-[#00C8FF] font-semibold whitespace-nowrap">
                        {item.ip_address}
                      </td>
                      <td className="p-3.5 text-[#F1F5F9] whitespace-nowrap">
                        <span className="flex items-center gap-1.5">
                          <MapPin size={13} className="text-[#94A3B8]" />
                          {item.city}, {item.country}
                        </span>
                      </td>
                      <td className="p-3.5 text-[#94A3B8] whitespace-nowrap">
                        <span className="flex items-center gap-1.5">
                          <Server size={13} className="text-[#8B5CF6]" />
                          {item.isp || 'Enterprise Gateway'}
                        </span>
                      </td>
                      <td className="p-3.5 font-mono text-[#F1F5F9] whitespace-nowrap">
                        {item.total_events}
                      </td>
                      <td className="p-3.5 font-mono text-[#FF4560] font-bold whitespace-nowrap">
                        {item.suspicious_events}
                      </td>
                      <td className="p-3.5 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-2 rounded-full bg-[#080D19] overflow-hidden">
                            <div
                              className="h-full rounded-full"
                              style={{
                                width: `${risk}%`,
                                backgroundColor: isCrit ? '#FF4560' : isHigh ? '#FFB020' : '#00D68F'
                              }}
                            />
                          </div>
                          <span className="font-mono text-[11px] font-bold text-[#F1F5F9]">{risk}</span>
                        </div>
                      </td>
                      <td className="p-3.5 text-right whitespace-nowrap">
                        <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase ${sevBadge}`}>
                          {item.threat_status || 'Clean'}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Drilldown Modal */}
      {selectedIP && (
        <IPDetailModal
          ipProfile={selectedIP}
          onClose={() => setSelectedIP(null)}
        />
      )}
    </div>
  );
};
