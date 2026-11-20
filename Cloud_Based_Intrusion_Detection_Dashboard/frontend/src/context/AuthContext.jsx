import React, { createContext, useContext, useState, useEffect } from 'react';
import { loginUser, registerUser, getCurrentUserProfile } from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('soc_user');
    return saved ? JSON.parse(saved) : {
      uid: 'usr-admin-01',
      email: 'admin@soc.cloud',
      full_name: 'Rudresh',
      role: 'SOC Administrator',
      auth_provider: 'Firebase / Local BaaS'
    };
  });
  const [token, setToken] = useState(() => localStorage.getItem('soc_token') || 'demo-admin-token');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Save defaults on initial load
    if (!localStorage.getItem('soc_token')) {
      localStorage.setItem('soc_token', 'demo-admin-token');
      localStorage.setItem('soc_user', JSON.stringify(user));
    }
  }, []);

  const login = async (email, password) => {
    setLoading(true);
    try {
      const res = await loginUser({ email, password });
      const { token, user } = res.data;
      setToken(token);
      setUser(user);
      localStorage.setItem('soc_token', token);
      localStorage.setItem('soc_user', JSON.stringify(user));
      return { success: true };
    } catch (err) {
      return {
        success: false,
        error: err.response?.data?.detail || 'Authentication failed. Please verify credentials.'
      };
    } finally {
      setLoading(false);
    }
  };

  const register = async (email, password, full_name, role) => {
    setLoading(true);
    try {
      const res = await registerUser({ email, password, full_name, role });
      const { token, user } = res.data;
      setToken(token);
      setUser(user);
      localStorage.setItem('soc_token', token);
      localStorage.setItem('soc_user', JSON.stringify(user));
      return { success: true };
    } catch (err) {
      return {
        success: false,
        error: err.response?.data?.detail || 'Registration failed.'
      };
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('soc_token');
    localStorage.removeItem('soc_user');
  };

  return (
    <AuthContext.Provider value={{ user, token, isAuthenticated: !!user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
