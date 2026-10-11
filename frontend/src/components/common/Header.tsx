import React from 'react';
import type { NavPage } from '../../types';

interface HeaderProps {
  currentPage: NavPage;
  apiConnected: boolean | null;
  lastUpdated: string;
  isRefreshing: boolean;
  onRefresh: () => void;
  onOpenMobile: () => void;
}

const PAGE_META: Record<NavPage, { title: string; desc: string }> = {
  overview: {
    title: 'Overview & Telemetry',
    desc: 'Real-time defense metrics, decision breakdown, and security events',
  },
  'live-firewall': {
    title: 'Live Firewall Workbench',
    desc: 'Inspect untrusted prompts, multi-stage detection pipeline & cryptographic tokens',
  },
  'threat-intel': {
    title: 'Threat Intelligence',
    desc: 'Empirical classification, injection patterns & risk score distributions',
  },
  'transaction-simulator': {
    title: 'Transaction Simulator',
    desc: 'End-to-end banking boundary: request, firewall verdict & atomic ledger execution',
  },
  'audit-trail': {
    title: 'Security Audit Trail',
    desc: 'Thread-safe, sanitized inspection stream with immutable event logs',
  },
  'system-health': {
    title: 'System Health & Analytics',
    desc: 'Liveness probes, sub-millisecond latency benchmarks & defensive invariants',
  },
};

export const Header: React.FC<HeaderProps> = ({
  currentPage,
  apiConnected,
  lastUpdated,
  isRefreshing,
  onRefresh,
  onOpenMobile,
}) => {
  const meta = PAGE_META[currentPage] || {
    title: 'Bankism Defense Dashboard',
    desc: 'Blue-Team AI Firewall & Guardrail Defense',
  };

  return (
    <header className="app-header" role="banner">
      <div className="header-left">
        {/* Mobile menu toggle */}
        <button
          type="button"
          className="btn-icon-toggle"
          onClick={onOpenMobile}
          aria-label="Open mobile navigation"
          style={{ display: 'none' }}
          id="mobile-nav-btn"
        >
          ☰
        </button>
        <div>
          <h1 className="page-title">{meta.title}</h1>
          <span className="page-desc">{meta.desc}</span>
        </div>
      </div>

      <div className="header-right">
        {/* Synthetic Environment pill */}
        <div className="env-badge" title="Running in synthetic safe simulation environment">
          <span style={{ color: 'var(--emerald-primary)' }}>●</span>
          <span>DEMO / SYNTHETIC</span>
        </div>

        {/* Real API connection status */}
        <div
          className={`connection-pill ${
            apiConnected === true
              ? 'connected'
              : apiConnected === false
              ? 'disconnected'
              : ''
          }`}
          title={
            apiConnected === true
              ? 'FastAPI core is responsive and healthy'
              : apiConnected === false
              ? 'FastAPI backend connection unreachable'
              : 'Checking API health...'
          }
        >
          <span className="status-dot" aria-hidden="true" />
          <span>
            {apiConnected === true
              ? 'API CONNECTED'
              : apiConnected === false
              ? 'API DISCONNECTED'
              : 'CHECKING...'}
          </span>
        </div>

        {/* Last updated timestamp */}
        {lastUpdated && (
          <span
            style={{
              fontSize: '0.72rem',
              color: 'var(--text-secondary)',
              fontFamily: 'var(--font-mono)',
              display: 'none',
            }}
            className="timestamp-display"
          >
            {lastUpdated}
          </span>
        )}

        {/* Refresh button */}
        <button
          type="button"
          onClick={onRefresh}
          disabled={isRefreshing}
          className="btn-header-action"
          aria-label="Refresh dashboard telemetry and health"
          title="Refresh telemetry"
        >
          <span
            style={{
              display: 'inline-block',
              transform: isRefreshing ? 'rotate(180deg)' : 'none',
              transition: 'transform 0.5s ease',
            }}
          >
            🔄
          </span>
          <span>{isRefreshing ? 'Refreshing...' : 'Refresh'}</span>
        </button>
      </div>
    </header>
  );
};
