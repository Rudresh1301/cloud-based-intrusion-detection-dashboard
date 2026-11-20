import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { DashboardLayout } from './layouts/DashboardLayout';

import { Dashboard } from './pages/Dashboard';
import { UploadLogs } from './pages/UploadLogs';
import { LiveMonitoring } from './pages/LiveMonitoring';
import { ThreatAnalysis } from './pages/ThreatAnalysis';
import { IPIntelligence } from './pages/IPIntelligence';
import { AttackAnalytics } from './pages/AttackAnalytics';
import { SecurityLogs } from './pages/SecurityLogs';
import { AlertsCenter } from './pages/AlertsCenter';
import { Reports } from './pages/Reports';
import { SettingsPage } from './pages/SettingsPage';
import { AboutProject } from './pages/AboutProject';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';

const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();
  if (loading) {
    return null;
  }
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return children;
};

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public Authentication Routes */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          {/* Protected SOC Application Routes */}
          <Route
            element={
              <ProtectedRoute>
                <DashboardLayout />
              </ProtectedRoute>
            }
          >
            <Route path="/" element={<Dashboard />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/upload" element={<UploadLogs />} />
            <Route path="/live-monitoring" element={<LiveMonitoring />} />
            <Route path="/threats" element={<ThreatAnalysis />} />
            <Route path="/ip-intelligence" element={<IPIntelligence />} />
            <Route path="/analytics" element={<AttackAnalytics />} />
            <Route path="/logs" element={<SecurityLogs />} />
            <Route path="/alerts" element={<AlertsCenter />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/about" element={<AboutProject />} />
          </Route>

          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
