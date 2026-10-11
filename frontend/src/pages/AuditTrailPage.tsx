import React, { useState } from 'react';
import { StatusBadge } from '../components/common/StatusBadge';
import type { AuditLogRecord } from '../types';

interface AuditTrailPageProps {
  logs: AuditLogRecord[];
  isLoading: boolean;
  onRefresh: () => void;
}

export const AuditTrailPage: React.FC<AuditTrailPageProps> = ({
  logs,
  isLoading,
  onRefresh,
}) => {
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL');
  const [executionFilter, setExecutionFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');

  // Pagination state
  const [currentPageNum, setCurrentPageNum] = useState<number>(1);
  const pageSize = 15;

  const [selectedRecord, setSelectedRecord] = useState<AuditLogRecord | null>(null);

  // Filter logs
  const filtered = logs.filter((l) => {
    const matchVerdict = verdictFilter === 'ALL' || l.verdict === verdictFilter;
    const matchExecution =
      executionFilter === 'ALL' ||
      (executionFilter === 'EXECUTED' && l.executed) ||
      (executionFilter === 'WITHHELD' && !l.executed);
    const matchCategory =
      categoryFilter === 'ALL' || l.threat_category === categoryFilter;
    const matchSearch =
      searchTerm.trim() === '' ||
      l.request_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (l.account_id && l.account_id.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (l.recipient_id && l.recipient_id.toLowerCase().includes(searchTerm.toLowerCase())) ||
      l.reason.toLowerCase().includes(searchTerm.toLowerCase());

    return matchVerdict && matchExecution && matchCategory && matchSearch;
  });

  const totalPages = Math.ceil(filtered.length / pageSize) || 1;
  const paginatedLogs = filtered.slice(
    (currentPageNum - 1) * pageSize,
    currentPageNum * pageSize
  );

  const categories = Array.from(new Set(logs.map((l) => l.threat_category))).sort();

  return (
    <div>
      {/* Header Info */}
      <div className="card" style={{ padding: '1rem 1.25rem', backgroundColor: 'var(--surface-secondary)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div>
            <h2 className="card-title" style={{ fontSize: '0.94rem' }}>
              📜 Immutable Security Inspection Stream
            </h2>
            <p className="card-subtitle">
              Thread-safe audit buffer recording every untrusted prompt inspection and execution attempt.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <span style={{ fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
              Total Logged: <strong>{logs.length}</strong>
            </span>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={onRefresh}
              disabled={isLoading}
            >
              🔄 Refresh Stream
            </button>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="card" style={{ padding: '1rem 1.25rem' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem' }}>
          {/* Search */}
          <div>
            <label htmlFor="audit-search" className="form-label" style={{ fontSize: '0.72rem' }}>
              Search Filter
            </label>
            <input
              id="audit-search"
              type="text"
              placeholder="Search request ID, account, reason..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPageNum(1);
              }}
              className="form-input"
              style={{ fontSize: '0.78rem', padding: '0.45rem 0.65rem' }}
            />
          </div>

          {/* Verdict Filter */}
          <div>
            <label htmlFor="verdict-filter-sel" className="form-label" style={{ fontSize: '0.72rem' }}>
              Verdict
            </label>
            <select
              id="verdict-filter-sel"
              value={verdictFilter}
              onChange={(e) => {
                setVerdictFilter(e.target.value);
                setCurrentPageNum(1);
              }}
              className="form-select"
              style={{ fontSize: '0.78rem', padding: '0.45rem 0.65rem' }}
            >
              <option value="ALL">All Verdicts</option>
              <option value="APPROVE">APPROVE Only</option>
              <option value="BLOCK">BLOCK Only</option>
              <option value="REVIEW">REVIEW Only</option>
            </select>
          </div>

          {/* Execution Status Filter */}
          <div>
            <label htmlFor="exec-filter-sel" className="form-label" style={{ fontSize: '0.72rem' }}>
              Execution Outcome
            </label>
            <select
              id="exec-filter-sel"
              value={executionFilter}
              onChange={(e) => {
                setExecutionFilter(e.target.value);
                setCurrentPageNum(1);
              }}
              className="form-select"
              style={{ fontSize: '0.78rem', padding: '0.45rem 0.65rem' }}
            >
              <option value="ALL">All Outcomes</option>
              <option value="EXECUTED">Executed Only</option>
              <option value="WITHHELD">Withheld / Denied Only</option>
            </select>
          </div>

          {/* Threat Category Filter */}
          <div>
            <label htmlFor="cat-filter-sel" className="form-label" style={{ fontSize: '0.72rem' }}>
              Threat Category
            </label>
            <select
              id="cat-filter-sel"
              value={categoryFilter}
              onChange={(e) => {
                setCategoryFilter(e.target.value);
                setCurrentPageNum(1);
              }}
              className="form-select"
              style={{ fontSize: '0.78rem', padding: '0.45rem 0.65rem' }}
            >
              <option value="ALL">All Categories</option>
              {categories.map((cat) => (
                <option key={cat} value={cat}>
                  {cat}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Audit Log Table */}
      <section className="card" aria-labelledby="audit-table-heading">
        <div className="card-header">
          <div>
            <h2 id="audit-table-heading" className="card-title" style={{ fontSize: '0.92rem' }}>
              📋 Sanitized Security Inspection Events ({filtered.length} matching)
            </h2>
            <p className="card-subtitle">
              Page {currentPageNum} of {totalPages}
            </p>
          </div>
        </div>

        {filtered.length > 0 ? (
          <>
            <div className="table-responsive">
              <table className="data-table" aria-label="Security Audit Trail Records">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Request ID</th>
                    <th>Operation</th>
                    <th>Accounts</th>
                    <th>Amount</th>
                    <th>Risk Score</th>
                    <th>Verdict</th>
                    <th>Outcome</th>
                    <th>Reason / Details</th>
                    <th>Inspect</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedLogs.map((log) => (
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
                      <td className="mono-cell" style={{ fontSize: '0.72rem' }}>
                        {log.account_id ? log.account_id : 'N/A'}
                        {log.recipient_id ? ` → ${log.recipient_id}` : ''}
                      </td>
                      <td className="mono-cell" style={{ fontWeight: 600 }}>
                        {log.amount ? `$${log.amount.toFixed(2)}` : '—'}
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
                      <td style={{ maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {log.reason}
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
                          onClick={() => setSelectedRecord(log)}
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginTop: '1rem',
                paddingTop: '0.75rem',
                borderTop: '1px solid var(--separator-subtle)',
              }}
            >
              <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
                Showing {(currentPageNum - 1) * pageSize + 1} to{' '}
                {Math.min(currentPageNum * pageSize, filtered.length)} of {filtered.length} records
              </div>

              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => setCurrentPageNum((p) => Math.max(1, p - 1))}
                  disabled={currentPageNum === 1}
                >
                  ← Previous
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => setCurrentPageNum((p) => Math.min(totalPages, p + 1))}
                  disabled={currentPageNum === totalPages}
                >
                  Next →
                </button>
              </div>
            </div>
          </>
        ) : (
          <div className="empty-state">
            <div className="empty-icon">📜</div>
            <div style={{ fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.2rem' }}>
              No Matching Audit Logs
            </div>
            <p style={{ fontSize: '0.78rem' }}>
              Adjust search keywords or filters, or trigger inspections in Live Firewall to populate.
            </p>
          </div>
        )}
      </section>

      {/* Record Inspection Modal */}
      {selectedRecord && (
        <div
          className="modal-backdrop"
          onClick={() => setSelectedRecord(null)}
          role="dialog"
          aria-modal="true"
          aria-labelledby="audit-record-title"
        >
          <div
            className="modal-dialog"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: '600px' }}
          >
            <div className="modal-header">
              <h3 id="audit-record-title" className="card-title">
                📋 Audit Event Record
              </h3>
              <button
                type="button"
                className="btn-icon-toggle"
                onClick={() => setSelectedRecord(null)}
                aria-label="Close dialog"
              >
                ✕
              </button>
            </div>
            <div className="modal-body">
              <div className="verdict-meta-grid" style={{ marginTop: 0, paddingTop: 0, border: 'none' }}>
                <div>
                  <div className="meta-field-label">Audit ID</div>
                  <div className="meta-field-val mono-cell">{selectedRecord.audit_id}</div>
                </div>
                <div>
                  <div className="meta-field-label">Timestamp (UTC)</div>
                  <div className="meta-field-val mono-cell">{selectedRecord.timestamp}</div>
                </div>
                <div>
                  <div className="meta-field-label">Request ID</div>
                  <div className="meta-field-val mono-cell">{selectedRecord.request_id}</div>
                </div>
                <div>
                  <div className="meta-field-label">Operation</div>
                  <div className="meta-field-val">{selectedRecord.operation}</div>
                </div>
                <div>
                  <div className="meta-field-label">Verdict</div>
                  <StatusBadge type="verdict" value={selectedRecord.verdict} size="sm" />
                </div>
                <div>
                  <div className="meta-field-label">Risk Score / Level</div>
                  <div className="meta-field-val mono-cell">
                    {selectedRecord.risk_score}/100 ({selectedRecord.risk_level})
                  </div>
                </div>
                <div>
                  <div className="meta-field-label">Threat Category</div>
                  <div className="meta-field-val mono-cell">{selectedRecord.threat_category}</div>
                </div>
                <div>
                  <div className="meta-field-label">Execution Status</div>
                  <StatusBadge
                    type="status"
                    value={selectedRecord.executed ? 'EXECUTED' : 'WITHHELD'}
                    label={selectedRecord.executed ? 'Executed' : 'Withheld'}
                    size="sm"
                  />
                </div>
              </div>

              <div style={{ marginTop: '1rem' }}>
                <div className="meta-field-label">Reason / Security Policy Note:</div>
                <div style={{ padding: '0.65rem', backgroundColor: 'var(--surface-secondary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-default)', fontSize: '0.82rem', marginTop: '0.2rem' }}>
                  {selectedRecord.reason}
                </div>
              </div>

              {selectedRecord.threat_signals && selectedRecord.threat_signals.length > 0 && (
                <div style={{ marginTop: '1rem' }}>
                  <div className="meta-field-label">Detected Threat Indicators:</div>
                  <div className="signals-tag-list">
                    {selectedRecord.threat_signals.map((sig, idx) => (
                      <span key={idx} className="signal-tag">
                        {sig}
                      </span>
                    ))}
                  </div>
                </div>
              )}
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
