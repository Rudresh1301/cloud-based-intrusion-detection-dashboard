import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach JWT token to requests if available
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('soc_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => Promise.reject(error));

// Dashboard
export const getDashboardOverview = () => api.get('/api/dashboard/overview');

// Security Logs
export const validateLogs = (formData) => api.post('/api/logs/validate', formData, {
  headers: { 'Content-Type': 'multipart/form-data' },
});
export const uploadAndAnalyzeLogs = (formData) => api.post('/api/logs/upload', formData, {
  headers: { 'Content-Type': 'multipart/form-data' },
});
export const getSecurityLogs = (params) => api.get('/api/logs', { params });
export const exportLogsCsv = (params) => api.get('/api/logs/export', { params, responseType: 'blob' });

// Threat Analysis
export const getThreats = (params) => api.get('/api/threats', { params });
export const getThreatSummary = () => api.get('/api/threats/summary');
export const getThreatDetail = (threatId) => api.get(`/api/threats/${threatId}`);

// IP Intelligence
export const getIPIntelligence = (params) => api.get('/api/ip-intelligence', { params });
export const getIPProfile = (ip) => api.get(`/api/ip-intelligence/${ip}`);

// Attack Analytics
export const getAttackAnalytics = () => api.get('/api/analytics/overview');

// Alerts Center
export const getAlerts = (params) => api.get('/api/alerts', { params });
export const updateAlertStatus = (alertId, status) => api.patch(`/api/alerts/${alertId}/status`, { status });

// Reports
export const generateReport = () => api.post('/api/reports/generate');
export const getReportsList = () => api.get('/api/reports');

// Cloud Health
export const getCloudHealth = () => api.get('/api/health');

// Settings
export const getSettings = () => api.get('/api/settings');
export const updateSettings = (settings) => api.post('/api/settings', settings);
export const clearAllLogs = () => api.post('/api/settings/clear-logs');

// Simulated Live Stream
export const getLiveStream = (params) => api.get('/api/live/stream', { params });
export const tickLiveTelemetry = () => api.post('/api/live/tick');

// Auth
export const loginUser = (creds) => api.post('/api/auth/login', creds);
export const registerUser = (creds) => api.post('/api/auth/register', creds);
export const getCurrentUserProfile = () => api.get('/api/auth/me');

export default api;
