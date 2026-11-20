import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Lock, Mail, ArrowRight, AlertCircle, RefreshCw } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const LoginPage = () => {
  const navigate = useNavigate();
  const { login } = useAuth();

  const [email, setEmail] = useState('admin@soc.cloud');
  const [password, setPassword] = useState('admin123');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const result = await login(email, password);
    if (result.success) {
      navigate('/');
    } else {
      setError(result.error);
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-[#080D19] flex items-center justify-center p-4">
      {/* Background glow effects */}
      <div className="absolute w-96 h-96 bg-[#087FE5]/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute w-96 h-96 bg-[#00C8FF]/5 rounded-full blur-3xl pointer-events-none translate-x-32 translate-y-32" />

      <div className="relative w-full max-w-md rounded-2xl bg-[#0D1526] border border-[#1E2D4A] shadow-2xl p-8 space-y-6">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center">
          <div className="flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-[#087FE5]/30 to-[#00C8FF]/10 border border-[#00C8FF]/40 shadow-neon-blue mb-3">
            <Shield className="w-8 h-8 text-[#00C8FF] animate-pulse-glow" />
          </div>
          <h2 className="text-xl font-bold text-[#F1F5F9] tracking-tight">
            Security Operations Center
          </h2>
          <span className="text-xs font-semibold uppercase tracking-wider text-[#00A8FF] mt-1">
            Cloud Intrusion Detection
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
            <label className="block text-[#94A3B8] font-semibold mb-1">Analyst Email</label>
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
            <label className="block text-[#94A3B8] font-semibold mb-1">Access Credential</label>
            <div className="relative">
              <Lock size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8]" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full pl-10 pr-3 py-2.5 rounded-xl bg-[#080D19] border border-[#1E2D4A] text-[#F1F5F9] focus:outline-none focus:border-[#00C8FF]"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-[#087FE5] to-[#00A8FF] text-white font-bold text-xs shadow-neon-blue hover:brightness-110 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
          >
            {loading ? (
              <>
                <RefreshCw size={14} className="animate-spin" /> Authenticating...
              </>
            ) : (
              <>
                Authenticate Access <ArrowRight size={14} />
              </>
            )}
          </button>
        </form>

        {/* Demo Credentials Helper */}
        <div className="p-3 rounded-xl bg-[#121E32] border border-[#1E2D4A] text-[11px] text-[#94A3B8] space-y-1">
          <span className="font-semibold text-[#00C8FF] block">Preconfigured Demo Account:</span>
          <p>Email: <span className="font-mono text-[#F1F5F9]">admin@soc.cloud</span></p>
          <p>Password: <span className="font-mono text-[#F1F5F9]">admin123</span></p>
        </div>

        <div className="text-center text-xs text-[#94A3B8]">
          Need an account?{' '}
          <Link to="/register" className="text-[#00C8FF] font-semibold hover:underline">
            Register Analyst Access
          </Link>
        </div>
      </div>
    </div>
  );
};
