import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  Bell,
  Calendar,
  Cloud,
  ChevronDown,
  LogOut,
  User,
  ShieldCheck,
  AlertCircle
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { getCloudHealth } from '../services/api';

const PAGE_TITLES = {
  '/': 'Dashboard',
  '/dashboard': 'Dashboard',
  '/upload': 'Upload Logs',
  '/live-monitoring': 'Live Monitoring',
  '/threats': 'Threat Analysis',
  '/ip-intelligence': 'IP Intelligence',
  '/analytics': 'Attack Analytics',
  '/logs': 'Security Logs',
  '/alerts': 'Alerts Center',
  '/reports': 'Reports',
  '/settings': 'Settings',
  '/about': 'About Project',
};

export const Navbar = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const [timeframe, setTimeframe] = useState('Last 24 Hours');
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [showNotificationMenu, setShowNotificationMenu] = useState(false);
  const [cloudStatus, setCloudStatus] = useState({ active_database: 'Connecting...', services: [] });
  const [currentTime, setCurrentTime] = useState(new Date().toLocaleTimeString());

  const currentTitle = PAGE_TITLES[location.pathname] || 'Security Operations Center';

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toLocaleTimeString());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    getCloudHealth()
      .then((res) => setCloudStatus(res.data))
      .catch(() => setCloudStatus({ active_database: 'Local SQLite Fallback', services: [] }));
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header className="w-full h-16 flex-shrink-0 bg-[#080D19] border-b border-[#1E2D4A] flex items-center justify-between px-6 z-30 relative select-none shadow-md">
      {/* Left: Page Title & Live Heartbeat indicator */}
      <div className="flex items-center gap-6">
        <h1 className="text-xl font-bold text-[#F1F5F9] tracking-tight">
          {currentTitle}
        </h1>

        {/* Live Monitoring ECG Status (matching reference image) */}
        <div className="hidden md:flex items-center gap-2.5 px-3 py-1 rounded-full bg-[#121E32] border border-[#1E2D4A] shadow-inner">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00D68F] opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-[#00D68F]"></span>
          </span>
          <span className="text-xs font-medium text-[#00D68F]">
            Live Monitoring Active
          </span>
          {/* Heartbeat EKG line SVG */}
          <svg className="w-16 h-4 text-[#00D68F] animate-ekg" viewBox="0 0 64 16" fill="none">
            <path
              d="M0 8h15l3-6 4 12 4-9 3 5 4-2h31"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-4">
        {/* Timeframe Dropdown */}
        <div className="relative hidden lg:block">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-[#121E32] border border-[#1E2D4A] text-xs text-[#F1F5F9] font-medium shadow-soc-card">
            <Calendar size={14} className="text-[#00A8FF]" />
            <select
              value={timeframe}
              onChange={(e) => setTimeframe(e.target.value)}
              className="bg-transparent text-[#F1F5F9] focus:outline-none cursor-pointer pr-1"
            >
              <option value="Last 24 Hours" className="bg-[#121E32]">Last 24 Hours</option>
              <option value="Last 7 Days" className="bg-[#121E32]">Last 7 Days</option>
              <option value="Last 30 Days" className="bg-[#121E32]">Last 30 Days</option>
              <option value="All Time" className="bg-[#121E32]">All Time</option>
            </select>
          </div>
        </div>

        {/* Cloud Status Pill */}
        <div
          className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-[#121E32] border border-[#1E2D4A] text-xs font-medium text-[#94A3B8]"
          title={cloudStatus.active_database}
        >
          <Cloud size={14} className={cloudStatus.all_healthy ? "text-[#00D68F]" : "text-[#FFB020]"} />
          <span className="hidden xl:inline">
            {cloudStatus.all_healthy ? "Firebase Cloud Active" : "Local SQLite Fallback"}
          </span>
        </div>

        {/* Notifications Bell */}
        <div className="relative">
          <button
            onClick={() => setShowNotificationMenu(!showNotificationMenu)}
            className="relative p-2 rounded-xl bg-[#121E32] border border-[#1E2D4A] text-[#94A3B8] hover:text-[#F1F5F9] hover:border-[#00A8FF]/40 transition-colors cursor-pointer"
          >
            <Bell size={18} />
            <span className="absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-[#FF4560] text-[10px] font-bold text-white shadow-neon-red">
              3
            </span>
          </button>

          {showNotificationMenu && (
            <div className="absolute right-0 mt-2 w-80 rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card p-3 z-50 animate-fadeIn">
              <div className="flex items-center justify-between pb-2 border-b border-[#1E2D4A] mb-2">
                <span className="text-xs font-bold text-[#F1F5F9] uppercase tracking-wider">
                  Security Alerts
                </span>
                <span className="text-[10px] text-[#00C8FF] font-semibold">3 New Incidents</span>
              </div>
              <div className="space-y-2 text-xs">
                <div className="p-2 rounded-lg bg-[#080D19]/60 border border-[#FF4560]/30 flex items-start gap-2">
                  <AlertCircle size={14} className="text-[#FF4560] mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="font-semibold text-[#F1F5F9]">Brute Force Attempt</p>
                    <p className="text-[11px] text-[#94A3B8]">12 failed logins from 192.168.1.105</p>
                  </div>
                </div>
                <div className="p-2 rounded-lg bg-[#080D19]/60 border border-[#FFB020]/30 flex items-start gap-2">
                  <AlertCircle size={14} className="text-[#FFB020] mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="font-semibold text-[#F1F5F9]">SQL Injection Blocked</p>
                    <p className="text-[11px] text-[#94A3B8]">Target /search from 103.21.45.67</p>
                  </div>
                </div>
                <div className="p-2 rounded-lg bg-[#080D19]/60 border border-[#00C8FF]/30 flex items-start gap-2">
                  <ShieldCheck size={14} className="text-[#00C8FF] mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="font-semibold text-[#F1F5F9]">ML Anomaly Detected</p>
                    <p className="text-[11px] text-[#94A3B8]">Behavioral deviation flagged by Isolation Forest</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* User Profile Menu */}
        <div className="relative">
          <button
            onClick={() => setShowProfileMenu(!showProfileMenu)}
            className="flex items-center gap-2.5 p-1.5 pr-3 rounded-xl bg-[#121E32] border border-[#1E2D4A] hover:border-[#00C8FF]/40 transition-colors cursor-pointer"
          >
            <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-gradient-to-tr from-[#8B5CF6] to-[#087FE5] text-white font-bold text-xs shadow-neon-blue">
              {user?.full_name ? user.full_name.charAt(0).toUpperCase() : 'R'}
            </div>
            <div className="hidden md:flex flex-col text-left">
              <span className="text-xs font-semibold text-[#F1F5F9] leading-tight">
                {user?.full_name || 'Rudresh'}
              </span>
              <span className="text-[10px] text-[#94A3B8]">
                {user?.role || 'SOC Analyst'}
              </span>
            </div>
            <ChevronDown size={14} className="text-[#94A3B8]" />
          </button>

          {showProfileMenu && (
            <div className="absolute right-0 mt-2 w-56 rounded-2xl bg-[#121E32] border border-[#1E2D4A] shadow-soc-card py-2 z-50">
              <div className="px-4 py-2 border-b border-[#1E2D4A]">
                <p className="text-xs font-semibold text-[#F1F5F9]">{user?.full_name || 'Rudresh'}</p>
                <p className="text-[11px] text-[#94A3B8] truncate">{user?.email || 'admin@soc.cloud'}</p>
                <span className="inline-block mt-1 px-2 py-0.5 text-[9px] font-semibold rounded bg-[#087FE5]/20 text-[#00C8FF] border border-[#087FE5]/30">
                  {user?.role || 'SOC Administrator'}
                </span>
              </div>
              <button
                onClick={() => { setShowProfileMenu(false); navigate('/settings'); }}
                className="w-full text-left px-4 py-2 text-xs text-[#94A3B8] hover:text-[#F1F5F9] hover:bg-[#16253e] flex items-center gap-2 cursor-pointer"
              >
                <User size={14} /> Profile & Settings
              </button>
              <button
                onClick={handleLogout}
                className="w-full text-left px-4 py-2 text-xs text-[#FF4560] hover:bg-[#FF4560]/10 flex items-center gap-2 cursor-pointer"
              >
                <LogOut size={14} /> Logout
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
