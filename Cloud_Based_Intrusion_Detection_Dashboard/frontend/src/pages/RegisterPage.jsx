import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Lock, Mail, User, ArrowRight, AlertCircle, RefreshCw } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const RegisterPage = () => {
  const navigate = useNavigate();
  const { register } = useAuth();

  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('Security Analyst');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const result = await register(email, password, fullName, role);
    if (result.success) {
      navigate('/');
    } else {
      setError(result.error);
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-[#080D19] flex items-center justify-center p-4">
      <div className="relative w-full max-w-md rounded-2xl bg-[#0D1526] border border-[#1E2D4A] shadow-2xl p-8 space-y-6">
        <div className="flex flex-col items-center text-center">
          <div className="flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-[#087FE5]/30 to-[#00C8FF]/10 border border-[#00C8FF]/40 shadow-neon-blue mb-3">
            <Shield className="w-8 h-8 text-[#00C8FF] animate-pulse-glow" />
          </div>
          <h2 className="text-xl font-bold text-[#F1F5F9] tracking-tight">
            Register Analyst Identity
          </h2>
          <span className="text-xs font-semibold uppercase tracking-wider text-[#00A8FF] mt-1">
            Cloud Authentication BaaS
          </span>
        </div>

        {error && (
          <div className="p-3.5 rounded-xl bg-[#FF4560]/20 border border-[#FF4560]/50 text-[#FF4560] text-xs font-semibold flex items-center gap-2">
            <AlertCircle size={16} className="flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-[#94A3B8] font-semibold mb-1">Full Name</label>
            <div className="relative">
              <User size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8]" />
              <input
                type="text"
                required
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Rudresh"
                className="w-full pl-10 pr-3 py-2.5 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-[#F1F5F9] focus:outline-none focus:border-[#00C8FF]"
              />
            </div>
          </div>

          <div>
            <label className="block text-[#94A3B8] font-semibold mb-1">Corporate Email</label>
            <div className="relative">
              <Mail size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8]" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@soc.cloud"
                className="w-full pl-10 pr-3 py-2.5 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-[#F1F5F9] focus:outline-none focus:border-[#00C8FF]"
              />
            </div>
          </div>

          <div>
            <label className="block text-[#94A3B8] font-semibold mb-1">Create Password</label>
            <div className="relative">
              <Lock size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8]" />
              <input
                type="password"
                required
                minLength={6}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full pl-10 pr-3 py-2.5 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-[#F1F5F9] focus:outline-none focus:border-[#00C8FF]"
              />
            </div>
          </div>

          <div>
            <label className="block text-[#94A3B8] font-semibold mb-1">Analyst Role</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full p-2.5 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-[#F1F5F9] focus:outline-none focus:border-[#00C8FF]"
            >
              <option value="Security Analyst">Security Analyst (Tier 1/2)</option>
              <option value="SOC Administrator">SOC Administrator</option>
              <option value="Threat Researcher">Threat Researcher</option>
              <option value="Cloud Security Engineer">Cloud Security Engineer</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-[#087FE5] to-[#00A8FF] text-white font-bold text-xs shadow-neon-blue hover:brightness-110 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
          >
            {loading ? (
              <>
                <RefreshCw size={14} className="animate-spin" /> Provisioning Account...
              </>
            ) : (
              <>
                Register Account <ArrowRight size={14} />
              </>
            )}
          </button>
        </form>

        <div className="text-center text-xs text-[#94A3B8]">
          Already have credentials?{' '}
          <Link to="/login" className="text-[#00C8FF] font-semibold hover:underline">
            Login to Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
};
