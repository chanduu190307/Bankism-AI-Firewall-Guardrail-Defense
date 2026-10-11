import React, { useState, useEffect, useRef } from 'react';
import { MetricCard } from '../components/common/MetricCard';
import { StatusBadge } from '../components/common/StatusBadge';
import { BarChart } from '../components/charts/BarChart';
import type { MetricsResponse, AuditLogRecord } from '../types';

interface ThreatIntelligencePageProps {
  metrics: MetricsResponse | null;
  logs: AuditLogRecord[];
  onRefresh: () => void;
}

export const ThreatIntelligencePage: React.FC<ThreatIntelligencePageProps> = ({
  metrics,
  logs,
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedRecord, setSelectedRecord] = useState<AuditLogRecord | null>(null);
  const modalRef = useRef<HTMLDivElement>(null);

  // Accessible keyboard trap & Escape handling for threat details modal
  useEffect(() => {
    if (!selectedRecord) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setSelectedRecord(null);
        return;
      }

      if (e.key === 'Tab' && modalRef.current) {
        const focusable = modalRef.current.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        if (focusable.length === 0) return;

        const first = focusable[0];
        const last = focusable[focusable.length - 1];

        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [selectedRecord]);

  // Filter logs for threats
  const threatLogs = logs.filter(
    (l) => l.threat_category !== 'NONE' || l.verdict === 'BLOCK' || l.verdict === 'REVIEW'
  );

  const filteredThreatLogs = threatLogs.filter((log) => {
    const matchCat =
      selectedCategory === 'ALL' || log.threat_category === selectedCategory;
    const matchSearch =
      searchQuery.trim() === '' ||
      log.request_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.reason.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.threat_category.toLowerCase().includes(searchQuery.toLowerCase());
    return matchCat && matchSearch;
  });

  // Risk Score Distribution Bands
  const riskBands = {
    low: logs.filter((l) => l.risk_score <= 25).length,
    medium: logs.filter((l) => l.risk_score > 25 && l.risk_score <= 50).length,
    high: logs.filter((l) => l.risk_score > 50 && l.risk_score <= 75).length,
    critical: logs.filter((l) => l.risk_score > 75).length,
  };
  const totalBanded = logs.length || 1;

  // Aggregate detected signals
  const signalMap: Record<string, number> = {};
  logs.forEach((log) => {
    (log.threat_signals || []).forEach((sig) => {
      signalMap[sig] = (signalMap[sig] || 0) + 1;
    });
  });
  const topSignals = Object.entries(signalMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  // Highest threat category
  const threatDist = metrics?.threat_distribution || {};
  const sortedCategories = Object.entries(threatDist)
    .filter(([cat]) => cat !== 'NONE')
    .sort((a, b) => b[1] - a[1]);
  const primaryThreat = sortedCategories.length > 0 ? sortedCategories[0][0] : 'None';
  const totalThreats = sortedCategories.reduce((acc, c) => acc + c[1], 0);

  return (
    <div>
      {/* Metrics Row */}
      <section aria-label="Threat Telemetry Summary" className="kpi-grid">
        <MetricCard
          label="Adversarial Injections"
          value={totalThreats}
          subtext="Adversarial payloads neutralized"
          icon="🚨"
          variant="threat"
        />
        <MetricCard
          label="Top Threat Category"
          value={primaryThreat.replace(/_/g, ' ')}
          subtext={sortedCategories.length > 0 ? `${sortedCategories[0][1]} instances observed` : 'No threats detected'}
          icon="🎯"
          variant="block"
        />
        <MetricCard
          label="Critical Risk Events"
          value={riskBands.critical}
          subtext="Risk score > 75/100"
          icon="🛑"
          variant="block"
        />
        <MetricCard
          label="Heuristic Coverage"
          value="100%"
          subtext="Deterministic rule-engine active"
          icon="🛡️"
          variant="approve"
        />
      </section>

      {/* Charts Row */}
      <div className="grid-2col" style={{ marginBottom: '1.25rem' }}>
        {/* Threat Category Distribution */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-header">
            <div>
              <h2 className="card-title" style={{ fontSize: '0.92rem' }}>
                📊 Threat Category Distribution
              </h2>
              <p className="card-subtitle">
                Categorized threat classifications identified by rule & heuristic engine
              </p>
            </div>
          </div>
          <BarChart data={threatDist} maxBars={8} />
        </div>

        {/* Risk Score Bands */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-header">
            <div>
              <h2 className="card-title" style={{ fontSize: '0.92rem' }}>
                ⚖️ Risk Score Distribution
              </h2>
              <p className="card-subtitle">
                Inspection risk severity breakdown across all logged requests
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
            {/* Low */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', marginBottom: '0.2rem' }}>
                <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>Low Risk (0 - 25)</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--status-approve-text)', fontWeight: 700 }}>
                  {riskBands.low} ({Math.round((riskBands.low / totalBanded) * 100)}%)
                </span>
              </div>
              <div style={{ width: '100%', height: '8px', backgroundColor: 'var(--surface-secondary)', borderRadius: '4px', border: '1px solid var(--border-default)', overflow: 'hidden' }}>
                <div style={{ width: `${(riskBands.low / totalBanded) * 100}%`, height: '100%', backgroundColor: 'var(--status-approve-text)', transition: 'width 0.3s' }} />
              </div>
            </div>

            {/* Medium */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', marginBottom: '0.2rem' }}>
                <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>Medium Risk (26 - 50)</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--status-review-text)', fontWeight: 700 }}>
                  {riskBands.medium} ({Math.round((riskBands.medium / totalBanded) * 100)}%)
                </span>
              </div>
              <div style={{ width: '100%', height: '8px', backgroundColor: 'var(--surface-secondary)', borderRadius: '4px', border: '1px solid var(--border-default)', overflow: 'hidden' }}>
                <div style={{ width: `${(riskBands.medium / totalBanded) * 100}%`, height: '100%', backgroundColor: 'var(--status-review-text)', transition: 'width 0.3s' }} />
              </div>
            </div>

            {/* High */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', marginBottom: '0.2rem' }}>
                <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>High Risk (51 - 75)</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--status-threat-text)', fontWeight: 700 }}>
                  {riskBands.high} ({Math.round((riskBands.high / totalBanded) * 100)}%)
                </span>
              </div>
              <div style={{ width: '100%', height: '8px', backgroundColor: 'var(--surface-secondary)', borderRadius: '4px', border: '1px solid var(--border-default)', overflow: 'hidden' }}>
                <div style={{ width: `${(riskBands.high / totalBanded) * 100}%`, height: '100%', backgroundColor: 'var(--status-threat-text)', transition: 'width 0.3s' }} />
              </div>
            </div>

            {/* Critical */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', marginBottom: '0.2rem' }}>
                <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>Critical Risk (76 - 100)</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--status-block-text)', fontWeight: 700 }}>
                  {riskBands.critical} ({Math.round((riskBands.critical / totalBanded) * 100)}%)
                </span>
              </div>
              <div style={{ width: '100%', height: '8px', backgroundColor: 'var(--surface-secondary)', borderRadius: '4px', border: '1px solid var(--border-default)', overflow: 'hidden' }}>
                <div style={{ width: `${(riskBands.critical / totalBanded) * 100}%`, height: '100%', backgroundColor: 'var(--status-block-text)', transition: 'width 0.3s' }} />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Top Attack Signatures Detected */}
      {topSignals.length > 0 && (
        <div className="card" style={{ marginBottom: '1.25rem' }}>
          <div className="card-header">
            <div>
              <h2 className="card-title" style={{ fontSize: '0.92rem' }}>
                🔍 Triggered Threat Indicators
              </h2>
              <p className="card-subtitle">
                Specific syntactic and behavioral heuristics flagged during inspection
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.65rem' }}>
            {topSignals.map(([sig, count]) => (
              <div
                key={sig}
                style={{
                  padding: '0.45rem 0.85rem',
                  backgroundColor: 'var(--surface-secondary)',
                  border: '1px solid var(--status-threat-border)',
                  borderRadius: 'var(--radius-md)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  fontSize: '0.78rem',
                }}
              >
                <span style={{ color: 'var(--status-threat-text)' }}>⚠️</span>
                <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>{sig}</span>
                <span
                  style={{
                    backgroundColor: 'var(--status-threat-bg)',
                    color: 'var(--status-threat-text)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '0.1rem 0.4rem',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 700,
                    fontSize: '0.72rem',
                  }}
                >
                  {count}×
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Threat Events Table */}
      <section className="card" aria-labelledby="threat-events-heading">
        <div className="card-header" style={{ flexWrap: 'wrap', gap: '0.75rem' }}>
          <div>
            <h2 id="threat-events-heading" className="card-title">
              🛑 Detected Threat Event Stream
            </h2>
            <p className="card-subtitle">
              Sanitized event logs for blocked and review-held requests
            </p>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <input
              type="text"
              placeholder="Search threat events..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="form-input"
              style={{ width: '200px', padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
              aria-label="Search threat events"
            />

            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="form-select"
              style={{ width: '180px', padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
              aria-label="Filter threat category"
            >
              <option value="ALL">All Threat Categories</option>
              {Object.keys(threatDist).map((cat) => (
                <option key={cat} value={cat}>
                  {cat}
                </option>
              ))}
            </select>
          </div>
        </div>

        {filteredThreatLogs.length > 0 ? (
          <div className="table-responsive">
            <table className="data-table" aria-label="Detected Threat Event Stream">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Request ID</th>
                  <th>Threat Category</th>
                  <th>Risk Score</th>
                  <th>Verdict</th>
                  <th>Indicators</th>
                  <th>Sanitized Reason</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredThreatLogs.map((log) => (
                  <tr key={log.audit_id || log.request_id}>
                    <td className="mono-cell" style={{ whiteSpace: 'nowrap' }}>
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="mono-cell" style={{ fontWeight: 600 }}>
                      {log.request_id.slice(0, 16)}
                    </td>
                    <td>
                      <span className="status-badge badge-threat btn-sm">
                        {log.threat_category}
                      </span>
                    </td>
                    <td className="mono-cell" style={{ fontWeight: 700 }}>
                      {log.risk_score}/100
                    </td>
                    <td>
                      <StatusBadge type="verdict" value={log.verdict} size="sm" />
                    </td>
                    <td>
                      <span className="mono-cell" style={{ fontSize: '0.72rem' }}>
                        {log.threat_signals?.length || 0} signal(s)
                      </span>
                    </td>
                    <td style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {log.reason}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={() => setSelectedRecord(log)}
                        style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
                        aria-label={`Inspect threat event details for request ${log.request_id.slice(0, 16)}`}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-icon">🛡️</div>
            <div style={{ fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.2rem' }}>
              No Threat Events Found
            </div>
            <p style={{ fontSize: '0.78rem' }}>
              No matching threat events exist in the current session. Run test scenarios in the Live Firewall or Overview page.
            </p>
          </div>
        )}
      </section>

      {/* Threat Inspection Modal */}
      {selectedRecord && (
        <div
          className="modal-backdrop"
          onClick={() => setSelectedRecord(null)}
          role="presentation"
        >
          <div
            ref={modalRef}
            className="modal-dialog"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: '580px' }}
            role="dialog"
            aria-modal="true"
            aria-labelledby="threat-modal-title"
          >
            <div className="modal-header">
              <h3 id="threat-modal-title" className="card-title">
                🛑 Sanitized Threat Event Details
              </h3>
              <button
                type="button"
                className="btn-icon-toggle"
                onClick={() => setSelectedRecord(null)}
                aria-label="Close modal"
              >
                ✕
              </button>
            </div>
            <div className="modal-body">
              <div className="verdict-meta-grid" style={{ marginTop: 0, paddingTop: 0, border: 'none' }}>
                <div>
                  <div className="meta-field-label">Request ID</div>
                  <div className="meta-field-val mono-cell">{selectedRecord.request_id}</div>
                </div>
                <div>
                  <div className="meta-field-label">Verdict</div>
                  <StatusBadge type="verdict" value={selectedRecord.verdict} size="sm" />
                </div>
                <div>
                  <div className="meta-field-label">Risk Score</div>
                  <div className="meta-field-val mono-cell">{selectedRecord.risk_score} / 100 ({selectedRecord.risk_level})</div>
                </div>
                <div>
                  <div className="meta-field-label">Threat Category</div>
                  <div className="meta-field-val mono-cell">{selectedRecord.threat_category}</div>
                </div>
              </div>

              <div style={{ marginTop: '1rem' }}>
                <div className="meta-field-label">Defense Policy Decision Reason:</div>
                <div style={{ padding: '0.65rem', backgroundColor: 'var(--surface-secondary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-default)', fontSize: '0.82rem', marginTop: '0.25rem' }}>
                  {selectedRecord.reason}
                </div>
              </div>

              {selectedRecord.threat_signals && selectedRecord.threat_signals.length > 0 && (
                <div style={{ marginTop: '1rem' }}>
                  <div className="meta-field-label">Flagged Threat Indicators:</div>
                  <div className="signals-tag-list">
                    {selectedRecord.threat_signals.map((sig, idx) => (
                      <span key={idx} className="signal-tag">
                        {sig}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div style={{ marginTop: '1rem' }}>
                <div className="meta-field-label">Target Financial Operation:</div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-main)', marginTop: '0.2rem' }}>
                  {selectedRecord.operation} {selectedRecord.amount ? `— Amount: $${selectedRecord.amount.toFixed(2)}` : ''}
                </div>
              </div>
            </div>
            <div className="modal-footer">
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setSelectedRecord(null)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
