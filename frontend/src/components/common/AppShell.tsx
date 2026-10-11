import React, { useState } from 'react';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import type { NavPage } from '../../types';

interface AppShellProps {
  currentPage: NavPage;
  onSelectPage: (page: NavPage) => void;
  apiConnected: boolean | null;
  lastUpdated: string;
  isRefreshing: boolean;
  onRefresh: () => void;
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({
  currentPage,
  onSelectPage,
  apiConnected,
  lastUpdated,
  isRefreshing,
  onRefresh,
  children,
}) => {
  const [collapsed, setCollapsed] = useState<boolean>(false);
  const [mobileOpen, setMobileOpen] = useState<boolean>(false);

  return (
    <div className="app-container">
      <Sidebar
        currentPage={currentPage}
        onSelectPage={onSelectPage}
        collapsed={collapsed}
        onToggleCollapse={() => setCollapsed(!collapsed)}
        mobileOpen={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
      />

      <div className={`app-main-layout ${collapsed ? 'collapsed' : ''}`}>
        <Header
          currentPage={currentPage}
          apiConnected={apiConnected}
          lastUpdated={lastUpdated}
          isRefreshing={isRefreshing}
          onRefresh={onRefresh}
          onOpenMobile={() => setMobileOpen(true)}
        />

        <main className="page-content" id="main-content" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
};
