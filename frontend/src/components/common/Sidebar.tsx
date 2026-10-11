import React from 'react';
import type { NavPage } from '../../types';

interface SidebarProps {
  currentPage: NavPage;
  onSelectPage: (page: NavPage) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

interface NavItemConfig {
  id: NavPage;
  label: string;
  icon: string;
}

const NAV_ITEMS: NavItemConfig[] = [
  { id: 'overview', label: 'Overview', icon: '📊' },
  { id: 'live-firewall', label: 'Live Firewall', icon: '🛡️' },
  { id: 'threat-intel', label: 'Threat Intelligence', icon: '⚡' },
  { id: 'transaction-simulator', label: 'Transaction Simulator', icon: '💳' },
  { id: 'audit-trail', label: 'Audit Trail', icon: '📜' },
  { id: 'system-health', label: 'System Health', icon: '🩺' },
];

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onSelectPage,
  collapsed,
  onToggleCollapse,
  mobileOpen,
  onCloseMobile,
}) => {
  const handleNavClick = (page: NavPage) => {
    onSelectPage(page);
    onCloseMobile();
  };

  return (
    <>
      {/* Mobile backdrop */}
      <div
        className={`mobile-nav-backdrop ${mobileOpen ? 'open' : ''}`}
        onClick={onCloseMobile}
        aria-hidden="true"
      />

      <aside
        className={`app-sidebar ${collapsed ? 'collapsed' : ''} ${
          mobileOpen ? 'mobile-open' : ''
        }`}
        aria-label="Primary Navigation"
      >
        {/* Brand header */}
        <div className="sidebar-header">
          <div className="brand-badge">
            <div className="brand-icon-box" title="Bankism Security Shield">
              🛡️
            </div>
            {!collapsed && (
              <div className="brand-text-col">
                <span className="brand-title">BANKISM</span>
                <span className="brand-subtitle">Blue-Team AI Firewall</span>
              </div>
            )}
          </div>
          <button
            type="button"
            className="btn-icon-toggle"
            onClick={onToggleCollapse}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            style={{ display: mobileOpen ? 'none' : 'flex' }}
          >
            {collapsed ? '→' : '←'}
          </button>
        </div>

        {/* Navigation list */}
        <nav className="sidebar-nav" role="navigation">
          {NAV_ITEMS.map((item) => {
            const isActive = currentPage === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => handleNavClick(item.id)}
                className={`nav-item ${isActive ? 'active' : ''}`}
                aria-current={isActive ? 'page' : undefined}
                title={collapsed ? item.label : undefined}
              >
                <span className="nav-icon" aria-hidden="true">
                  {item.icon}
                </span>
                {!collapsed && <span>{item.label}</span>}
              </button>
            );
          })}
        </nav>

        {/* Footer info */}
        {!collapsed && (
          <div className="sidebar-footer">
            <div className="sidebar-meta-row">
              <span>Environment:</span>
              <strong style={{ color: 'var(--text-main)' }}>Synthetic</strong>
            </div>
            <div className="sidebar-meta-row">
              <span>Boundary:</span>
              <strong style={{ color: 'var(--status-approve-text)' }}>Fail-Closed</strong>
            </div>
            <div className="sidebar-meta-row" style={{ marginTop: '0.2rem', fontSize: '0.7rem' }}>
              <span>Engine v1.0.0</span>
              <a
                href="/docs"
                target="_blank"
                rel="noreferrer"
                style={{ color: 'var(--emerald-primary)', textDecoration: 'none' }}
              >
                API Docs ↗
              </a>
            </div>
          </div>
        )}
      </aside>
    </>
  );
};
