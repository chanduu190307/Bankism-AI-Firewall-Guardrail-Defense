import React, { useState, useEffect, useCallback } from 'react';
import { AppShell } from './components/common/AppShell';
import { OverviewPage } from './pages/OverviewPage';
import { LiveFirewallPage } from './pages/LiveFirewallPage';
import { ThreatIntelligencePage } from './pages/ThreatIntelligencePage';
import { TransactionSimulatorPage } from './pages/TransactionSimulatorPage';
import { AuditTrailPage } from './pages/AuditTrailPage';
import { SystemHealthPage } from './pages/SystemHealthPage';
import {
  checkApiHealth,
  fetchMetrics,
  fetchAuditLogs,
  analyzeFirewall,
} from './services/api';
import { SCENARIOS } from './data/scenarios';
import type {
  NavPage,
  HealthResponse,
  MetricsResponse,
  AuditLogRecord,
} from './types';

export function App(): React.ReactElement {
  const [currentPage, setCurrentPage] = useState<NavPage>('overview');

  // Global Telemetry State
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLogRecord[]>([]);
  const [apiConnected, setApiConnected] = useState<boolean | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string>('');
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [isRunningSuite, setIsRunningSuite] = useState<boolean>(false);

  // Fetch Telemetry from FastAPI backend
  const refreshTelemetry = useCallback(async (showLoading = true) => {
    if (showLoading) setIsRefreshing(true);
    try {
      const [healthRes, metricsRes, logsRes] = await Promise.allSettled([
        checkApiHealth(),
        fetchMetrics(),
        fetchAuditLogs(100, 0),
      ]);

      if (healthRes.status === 'fulfilled') {
        setHealth(healthRes.value);
        setApiConnected(true);
      } else {
        setApiConnected(false);
      }

      if (metricsRes.status === 'fulfilled') {
        setMetrics(metricsRes.value);
      }

      if (logsRes.status === 'fulfilled') {
        setAuditLogs(logsRes.value);
      }

      const now = new Date();
      setLastUpdated(
        `Updated ${now.getHours().toString().padStart(2, '0')}:${now
          .getMinutes()
          .toString()
          .padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`
      );
    } catch {
      setApiConnected(false);
    } finally {
      if (showLoading) setIsRefreshing(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    let isMounted = true;
    async function loadInitial() {
      try {
        const [healthRes, metricsRes, logsRes] = await Promise.allSettled([
          checkApiHealth(),
          fetchMetrics(),
          fetchAuditLogs(100, 0),
        ]);
        if (!isMounted) return;

        if (healthRes.status === 'fulfilled') {
          setHealth(healthRes.value);
          setApiConnected(true);
        } else {
          setApiConnected(false);
        }

        if (metricsRes.status === 'fulfilled') {
          setMetrics(metricsRes.value);
        }

        if (logsRes.status === 'fulfilled') {
          setAuditLogs(logsRes.value);
        }

        const now = new Date();
        setLastUpdated(
          `Updated ${now.getHours().toString().padStart(2, '0')}:${now
            .getMinutes()
            .toString()
            .padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`
        );
      } catch {
        if (isMounted) setApiConnected(false);
      }
    }
    void loadInitial();
    return () => {
      isMounted = false;
    };
  }, []);

  // Run benchmark preset suite through real backend to populate telemetry
  const handleRunDemoSuite = async () => {
    setIsRunningSuite(true);
    try {
      for (const scenario of SCENARIOS) {
        await analyzeFirewall({
          text: scenario.text,
          operation: scenario.operation,
          account_id: scenario.account_id,
          recipient_id: scenario.recipient_id,
          amount: scenario.amount,
          memo: scenario.memo,
        }).catch(() => null);
      }
      await refreshTelemetry();
    } finally {
      setIsRunningSuite(false);
    }
  };

  return (
    <AppShell
      currentPage={currentPage}
      onSelectPage={setCurrentPage}
      apiConnected={apiConnected}
      lastUpdated={lastUpdated}
      isRefreshing={isRefreshing}
      onRefresh={refreshTelemetry}
    >
      {currentPage === 'overview' && (
        <OverviewPage
          metrics={metrics}
          health={health}
          recentLogs={auditLogs}
          onNavigate={setCurrentPage}
          onRunDemoSuite={handleRunDemoSuite}
          isRunningSuite={isRunningSuite}
        />
      )}

      {currentPage === 'live-firewall' && (
        <LiveFirewallPage onRefreshTelemetry={refreshTelemetry} />
      )}

      {currentPage === 'threat-intel' && (
        <ThreatIntelligencePage
          metrics={metrics}
          logs={auditLogs}
          onRefresh={refreshTelemetry}
        />
      )}

      {currentPage === 'transaction-simulator' && (
        <TransactionSimulatorPage onRefreshTelemetry={refreshTelemetry} />
      )}

      {currentPage === 'audit-trail' && (
        <AuditTrailPage
          logs={auditLogs}
          isLoading={isRefreshing}
          onRefresh={refreshTelemetry}
        />
      )}

      {currentPage === 'system-health' && (
        <SystemHealthPage
          health={health}
          metrics={metrics}
          apiConnected={apiConnected}
          onRefresh={refreshTelemetry}
          isRefreshing={isRefreshing}
        />
      )}
    </AppShell>
  );
}

export default App;
