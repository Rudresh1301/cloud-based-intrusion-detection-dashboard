import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Shield,
  Home,
  CloudUpload,
  Activity,
  ShieldAlert,
  Globe,
  TrendingUp,
  FileText,
  AlertTriangle,
  FileCheck,
  Settings,
  Info,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';

const NAV_ITEMS = [
  { name: 'Dashboard', path: '/', icon: Home },
  { name: 'Upload Logs', path: '/upload', icon: CloudUpload },
  { name: 'Live Monitoring', path: '/live-monitoring', icon: Activity },
  { name: 'Threat Analysis', path: '/threats', icon: ShieldAlert },
  { name: 'IP Intelligence', path: '/ip-intelligence', icon: Globe },
  { name: 'Attack Analytics', path: '/analytics', icon: TrendingUp },
  { name: 'Security Logs', path: '/logs', icon: FileText },
  { name: 'Alerts Center', path: '/alerts', icon: AlertTriangle },
  { name: 'Reports', path: '/reports', icon: FileCheck },
  { name: 'Settings', path: '/settings', icon: Settings },
  { name: 'About Project', path: '/about', icon: Info },
];

export const Sidebar = ({ isCollapsed, setIsCollapsed }) => {
  return (
    <aside
      className={`relative z-40 h-screen flex-shrink-0 transition-all duration-300 ease-in-out bg-[#0D1526] border-r border-[#1E2D4A] flex flex-col justify-between select-none ${
        isCollapsed ? 'w-20' : 'w-64'
      }`}
    >
      {/* Top Header / Branding */}
      <div className="flex flex-col flex-1 min-h-0">
        <div className="flex items-center justify-between p-4 border-b border-[#1E2D4A]/60 flex-shrink-0">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="relative flex items-center justify-center w-11 h-11 rounded-xl bg-gradient-to-br from-[#087FE5]/20 to-[#00C8FF]/10 border border-[#00C8FF]/40 shadow-neon-cyan flex-shrink-0">
              <Shield className="w-6 h-6 text-[#00C8FF] animate-pulse-glow" />
              <div className="absolute inset-0 rounded-xl bg-[#00C8FF]/10 blur-sm pointer-events-none" />
            </div>

            {!isCollapsed && (
              <div className="flex flex-col">
                <span className="font-bold text-sm tracking-tight text-[#F1F5F9] leading-tight line-clamp-2">
                  Cloud-Based Intrusion Detection Dashboard
                </span>
                <span className="text-[11px] font-medium text-[#00A8FF] mt-0.5 tracking-wider uppercase">
                  Monitor • Detect • Protect
                </span>
              </div>
            )}
          </div>

          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="p-1 rounded-lg text-[#94A3B8] hover:text-[#F1F5F9] hover:bg-[#121E32] transition-colors flex-shrink-0 cursor-pointer"
            title={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {isCollapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
          </button>
        </div>

        {/* Navigation Links (Flex-1 with its own clean scroll) */}
        <nav className="p-3 space-y-1.5 overflow-y-auto flex-1">
          {NAV_ITEMS.map((item) => {
            const IconComponent = item.icon;
            return (
              <NavLink
                key={item.name}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all duration-200 ${
                    isActive
                      ? 'bg-gradient-to-r from-[#087FE5] to-[#00A8FF] text-white shadow-neon-blue font-semibold border border-[#00C8FF]/40'
                      : 'text-[#94A3B8] hover:text-[#F1F5F9] hover:bg-[#121E32]'
                  }`
                }
              >
                <IconComponent className="w-5 h-5 flex-shrink-0" />
                {!isCollapsed && <span className="truncate">{item.name}</span>}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Bottom System Status Widget */}
      <div className="p-3 border-t border-[#1E2D4A]/60 flex-shrink-0">
        {!isCollapsed ? (
          <div className="bg-[#121E32] rounded-xl p-3 border border-[#1E2D4A] shadow-soc-card">
            <div className="flex items-center gap-2 mb-1.5">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00D68F] opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-[#00D68F]"></span>
              </span>
              <span className="text-xs font-semibold text-[#00D68F] tracking-wide">
                System Online
              </span>
            </div>
            <div className="text-[11px] text-[#94A3B8]">
              <span>Last Updated:</span>
              <p className="font-mono text-[#F1F5F9] text-[10px] mt-0.5">
                {new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}, {new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </p>
            </div>
          </div>
        ) : (
          <div className="flex justify-center py-2" title="System Online">
            <span className="relative flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00D68F] opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-[#00D68F]"></span>
            </span>
          </div>
        )}
      </div>
    </aside>
  );
};
