import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from '../components/Sidebar';
import { Navbar } from '../components/Navbar';

export const DashboardLayout = () => {
  const [isCollapsed, setIsCollapsed] = useState(false);

  return (
    <div className="h-screen w-screen bg-[#080D19] text-[#F1F5F9] flex overflow-hidden">
      {/* Sidebar Dock on Left */}
      <Sidebar isCollapsed={isCollapsed} setIsCollapsed={setIsCollapsed} />

      {/* Main Viewport Container on Right */}
      <div className="flex-1 flex flex-col h-screen min-w-0 overflow-hidden">
        {/* Top Navigation Bar: Stationary, solid background, strictly above content */}
        <Navbar isCollapsed={isCollapsed} />

        {/* Dedicated Independent Scrollable Main Content Area */}
        <main className="flex-1 overflow-y-auto overflow-x-hidden p-6 bg-[#080D19] scroll-smooth">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
