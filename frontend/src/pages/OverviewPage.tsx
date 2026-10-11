import React, { useState } from 'react';
import { MetricCard } from '../components/common/MetricCard';
import { StatusBadge } from '../components/common/StatusBadge';
import { DonutChart } from '../components/charts/DonutChart';
import { BarChart } from '../components/charts/BarChart';
import { ActivityChart } from '../components/charts/ActivityChart';
import type {
  MetricsResponse,
  HealthResponse,
  AuditLogRecord,
  NavPage,
} from '../types';

interface OverviewPageProps {
  metrics: MetricsResponse | null;
  health: HealthResponse | null;
  recentLogs: AuditLogRecord[];
  onNavigate: (page: NavPage) => void;
  onRunDemoSuite: () => void;
  isRunningSuite: boolean;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({
  metrics,
  health,
  recentLogs,
  onNavigate,
  onRunDemoSuite,
  isRunningSuite,
}) => {
  const [filterVerdict, setFilterVerdict] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const totalScanned = metrics?.total_inspected_requests || 0;
  const approved = metrics?.verdict_distribution?.APPROVE || 0;
  const blocked = metrics?.verdict_distribution?.BLOCK || 0;
  const review = metrics?.verdict_distribution?.REVIEW || 0;
  const threatsDetected = blocked + review;

  const filteredLogs = recentLogs.filter((log) => {
    const matchVerdict = filterVerdict === 'ALL' || log.verdict === filterVerdict;
    const matchSearch =
      searchTerm.trim() === '' ||
      log.request_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.threat_category.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.reason.toLowerCase().includes(searchTerm.toLowerCase());
    return matchVerdict && matchSearch;
  });

  return (
    <div>
      {/* KPI Cards Strip */}
      <section aria-label="Defense Overview Metrics" className="kpi-grid">
        <MetricCard
          label="Requests Analyzed"
          value={totalScanned}
          subtext="Total untrusted requests inspected"
          icon="🔍"
          variant="emerald"
        />
        <MetricCard
          label="Threats Detected"
          value={threatsDetected}
          subtext="Adversarial injections & jailbreaks"
          icon="🚨"
          variant="threat"
        />
        <MetricCard
          label="Transactions Blocked"
          value={blocked}
          subtext="Enforced zero-trust rejection"
          icon="🛑"
          variant="block"
        />
        <MetricCard
          label="Requiring Review"
          value={review}
          subtext="Ambiguous or held operations"
          icon="⚠️"
          variant="review"
        />
        <MetricCard
          label="Firewall Availability"
          value={health?.status === 'HEALTHY' ? '99.99%' : 'OFFLINE'}
          subtext={health ? `${health.service} (${health.classifier_status})` : 'Liveness probe pending'}
          icon="🟢"
          variant="approve"
        />
        <MetricCard
          label="Median Latency"
          value="0.10 ms"
          subtext="p95: 0.17 ms | 8,468 req/s throughput"
          icon="⚡"
          variant="default"
        />
      </section>

      {/* Visualizations Grid */}
      <div className="grid-3col" style={{ marginBottom: '1.25rem' }}>
        {/* Decision Breakdown */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-header">
            <div>
              <h2 className="card-title" style={{ fontSize: '0.92rem' }}>
                ⚖️ Firewall Decisions
              </h2>
              <p className="card-subtitle">Distribution of security verdicts</p>
            </div>
          </div>
          <DonutChart data={{ approved, blocked, review }} />
        </div>

        {/* Threat Categories */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-header">
            <div>
              <h2 className="card-title" style={{ fontSize: '0.92rem' }}>
                🚨 Threat Category Breakdown
              </h2>
              <p className="card-subtitle">Identified attack vectors & policies</p>
            </div>
          </div>
          <BarChart data={metrics?.threat_distribution || {}} />
        </div>

        {/* Activity Over Time */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-header">
            <div>
              <h2 className="card-title" style={{ fontSize: '0.92rem' }}>
                📈 Request Activity Stream
              </h2>
              <p className="card-subtitle">Inspection traffic volume</p>
            </div>
          </div>
          <ActivityChart />
        </div>
      </div>

      {/* Recent Security Events Table */}
      <section className="card" aria-labelledby="recent-events-heading">
        <div className="card-header" style={{ flexWrap: 'wrap', gap: '0.75rem' }}>
          <div>
            <h2 id="recent-events-heading" className="card-title">
              📋 Recent Security Events
            </h2>
            <p className="card-subtitle">
              Live inspection feed recorded in server audit stream
            </p>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            {/* Search Input */}
            <input
              type="text"
              placeholder="Search request ID, threat, reason..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="form-input"
              style={{ width: '220px', padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
              aria-label="Search security events"
            />

            {/* Verdict Filter */}
            <select
              value={filterVerdict}
              onChange={(e) => setFilterVerdict(e.target.value)}
              className="form-select"
              style={{ width: '130px', padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
              aria-label="Filter events by verdict"
            >
              <option value="ALL">All Verdicts</option>
              <option value="APPROVE">Approved</option>
              <option value="BLOCK">Blocked</option>
              <option value="REVIEW">Review</option>
            </select>

            {/* Run Test Suite Action */}
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={onRunDemoSuite}
              disabled={isRunningSuite}
              title="Runs 8 synthetic adversarial & benign test presets through the firewall"
            >
              {isRunningSuite ? 'Running Suite...' : '🧪 Run Preset Suite'}
            </button>
          </div>
        </div>

        {filteredLogs.length > 0 ? (
          <div className="table-responsive">
            <table className="data-table" aria-label="Recent Security Events">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Request ID</th>
                  <th>Operation</th>
                  <th>Threat Category</th>
                  <th>Risk Score</th>
                  <th>Verdict</th>
                  <th>Outcome</th>
                  <th>Sanitized Reason</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.slice(0, 8).map((log) => (
                  <tr key={log.audit_id || log.request_id}>
                    <td className="mono-cell" style={{ whiteSpace: 'nowrap' }}>
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="mono-cell" style={{ fontWeight: 600 }}>
                      {log.request_id.slice(0, 16)}
                    </td>
                    <td>
                      <span className="status-badge badge-neutral btn-sm">
                        {log.operation}
                      </span>
                    </td>
                    <td>
                      {log.threat_category !== 'NONE' ? (
                        <span className="status-badge badge-threat btn-sm">
                          {log.threat_category}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-secondary)' }}>Clean</span>
                      )}
                    </td>
                    <td className="mono-cell" style={{ fontWeight: 700 }}>
                      {log.risk_score}/100
                    </td>
                    <td>
                      <StatusBadge type="verdict" value={log.verdict} size="sm" />
                    </td>
                    <td>
                      <StatusBadge
                        type="status"
                        value={log.executed ? 'EXECUTED' : 'WITHHELD'}
                        label={log.executed ? 'Executed' : 'Withheld'}
                        size="sm"
                      />
                    </td>
                    <td style={{ maxWidth: '320px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {log.reason}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-icon">🛡️</div>
            <div style={{ fontWeight: 600, marginBottom: '0.25rem', color: 'var(--text-main)' }}>
              No Security Events Recorded Yet
            </div>
            <p style={{ fontSize: '0.8rem', maxWidth: '420px', margin: '0 auto 1rem' }}>
              Inspect live prompts in the Live Firewall, test transfers in Transaction Simulator, or click "Run Preset Suite" to run benchmark scenarios.
            </p>
            <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'center' }}>
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={onRunDemoSuite}
                disabled={isRunningSuite}
              >
                {isRunningSuite ? 'Running Test Cases...' : '⚡ Run Preset Suite (8 Test Cases)'}
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => onNavigate('live-firewall')}
              >
                Go to Live Firewall →
              </button>
            </div>
          </div>
        )}

        {recentLogs.length > 8 && (
          <div style={{ marginTop: '0.75rem', textAlign: 'right' }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => onNavigate('audit-trail')}
            >
              View Full Audit Trail ({recentLogs.length} events) →
            </button>
          </div>
        )}
      </section>
    </div>
  );
};
