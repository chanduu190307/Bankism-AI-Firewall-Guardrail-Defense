import React, { useState } from 'react';
import { SCENARIOS } from '../data/scenarios';
import { StatusBadge } from '../components/common/StatusBadge';
import { PipelineVisualizer } from '../components/common/PipelineVisualizer';
import { analyzeFirewall, executeBanking, ApiError } from '../services/api';
import type {
  BankingOperation,
  FirewallVerdict,
  BankingExecuteResponse,
  ScenarioPreset,
} from '../types';

interface LiveFirewallPageProps {
  onRefreshTelemetry: () => void;
}

export const LiveFirewallPage: React.FC<LiveFirewallPageProps> = ({
  onRefreshTelemetry,
}) => {
  // Input Form State
  const [promptText, setPromptText] = useState<string>(SCENARIOS[0].text);
  const [operation, setOperation] = useState<BankingOperation>(SCENARIOS[0].operation);
  const [accountId, setAccountId] = useState<string>('ACC-1001');
  const [recipientId, setRecipientId] = useState<string>('ACC-2002');
  const [amount, setAmount] = useState<string>('');
  const [memo, setMemo] = useState<string>('');

  // Analysis & Execution State
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [verdict, setVerdict] = useState<FirewallVerdict | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);

  const [isTestingBoundary, setIsTestingBoundary] = useState<boolean>(false);
  const [boundaryResponse, setBoundaryResponse] = useState<BankingExecuteResponse | null>(null);
  const [boundaryError, setBoundaryError] = useState<string | null>(null);

  const loadScenario = (s: ScenarioPreset) => {
    setPromptText(s.text);
    setOperation(s.operation);
    if (s.account_id) setAccountId(s.account_id);
    if (s.recipient_id) setRecipientId(s.recipient_id);
    setAmount(s.amount !== undefined ? s.amount.toString() : '');
    setMemo(s.memo || '');
    setVerdict(null);
    setAnalysisError(null);
    setBoundaryResponse(null);
    setBoundaryError(null);
  };

  const handleReset = () => {
    setPromptText('');
    setAmount('');
    setMemo('');
    setVerdict(null);
    setAnalysisError(null);
    setBoundaryResponse(null);
    setBoundaryError(null);
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!promptText.trim()) return;

    setIsAnalyzing(true);
    setAnalysisError(null);
    setBoundaryResponse(null);
    setBoundaryError(null);

    const payload = {
      text: promptText,
      operation,
      account_id: accountId || undefined,
      recipient_id: operation === 'TRANSFER' ? recipientId || undefined : undefined,
      amount: operation === 'TRANSFER' && amount ? parseFloat(amount) : undefined,
      memo: memo || undefined,
    };

    try {
      const result = await analyzeFirewall(payload);
      setVerdict(result);
      onRefreshTelemetry();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Analysis failed';
      setAnalysisError(msg);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleTestBoundary = async () => {
    if (!verdict) return;
    setIsTestingBoundary(true);
    setBoundaryResponse(null);
    setBoundaryError(null);

    const payload = {
      request_id: verdict.request_id,
      execution_token: verdict.execution_token || 'TAMPERED_OR_MISSING_TOKEN',
      operation,
      account_id: accountId,
      recipient_id: operation === 'TRANSFER' ? recipientId : undefined,
      amount: operation === 'TRANSFER' && amount ? parseFloat(amount) : undefined,
      raw_prompt: promptText,
    };

    try {
      const result = await executeBanking(payload);
      setBoundaryResponse(result);
      onRefreshTelemetry();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setBoundaryError(`[HTTP ${err.status} Fail-Closed] ${err.message}`);
      } else {
        const msg = err instanceof Error ? err.message : 'Boundary test failed';
        setBoundaryError(msg);
      }
    } finally {
      setIsTestingBoundary(false);
    }
  };

  return (
    <div>
      {/* Page description banner */}
      <div className="card" style={{ padding: '1rem 1.25rem', backgroundColor: 'var(--emerald-tint)', borderColor: 'var(--status-approve-border)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span style={{ fontSize: '1.25rem' }}>🛡️</span>
          <div>
            <strong style={{ color: 'var(--emerald-dark)', fontSize: '0.88rem' }}>
              Interactive AI Firewall Analysis Workbench
            </strong>
            <p style={{ fontSize: '0.78rem', color: 'var(--emerald-primary)', marginTop: '0.1rem' }}>
              Inspect untrusted natural language messages before any financial operation. Enforces NFKC normalization, rule-engine pattern matching, and cryptographic execution tokens.
            </p>
          </div>
        </div>
      </div>

      <div className="grid-2col">
        {/* Column 1: Request Analysis Input */}
        <section aria-labelledby="request-form-heading">
          <div className="card">
            <div className="card-header">
              <div>
                <h2 id="request-form-heading" className="card-title">
                  📝 Request Input & Scenario Presets
                </h2>
                <p className="card-subtitle">
                  Choose a preset or draft custom prompt input
                </p>
              </div>
              <button
                type="button"
                onClick={handleReset}
                className="btn btn-secondary btn-sm"
              >
                Clear / Reset
              </button>
            </div>

            {/* Presets Chips */}
            <div style={{ marginBottom: '1rem' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.4rem' }}>
                Quick Test Scenarios:
              </div>
              <div className="presets-container" role="group" aria-label="Quick test preset scenarios">
                {SCENARIOS.map((s) => (
                  <button
                    key={s.id}
                    type="button"
                    onClick={() => loadScenario(s)}
                    className={`preset-chip chip-${s.badgeType}`}
                    aria-label={`Load preset scenario: ${s.title}`}
                  >
                    <span>
                      {s.badgeType === 'attack' ? '🚨' : s.badgeType === 'benign' ? '✅' : '⚖️'}
                    </span>
                    <span>{s.title}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Form */}
            <form onSubmit={handleAnalyze}>
              <div className="form-group">
                <label htmlFor="prompt-input" className="form-label">
                  <span>Untrusted Input Text</span>
                  <span className="form-hint">
                    ({promptText.length}/4000 characters)
                  </span>
                </label>
                <textarea
                  id="prompt-input"
                  value={promptText}
                  onChange={(e) => setPromptText(e.target.value)}
                  className="form-textarea"
                  placeholder="Enter natural language inquiry or adversarial prompt payload..."
                  required
                  maxLength={4000}
                />
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="op-select" className="form-label">
                    <span>Target Operation</span>
                  </label>
                  <select
                    id="op-select"
                    value={operation}
                    onChange={(e) => setOperation(e.target.value as BankingOperation)}
                    className="form-select"
                  >
                    <option value="CUSTOMER_SUPPORT">Customer Support</option>
                    <option value="BALANCE_INQUIRY">Balance Inquiry</option>
                    <option value="TRANSFER">Simulated Transfer</option>
                  </select>
                </div>

                <div className="form-group">
                  <label htmlFor="source-acc-select" className="form-label">
                    <span>Source Account</span>
                  </label>
                  <select
                    id="source-acc-select"
                    value={accountId}
                    onChange={(e) => setAccountId(e.target.value)}
                    className="form-select"
                  >
                    <option value="ACC-1001">ACC-1001 (Alice Smith)</option>
                    <option value="ACC-2002">ACC-2002 (Bob Jones)</option>
                    <option value="ACC-3003">ACC-3003 (Charlie Brown)</option>
                  </select>
                </div>
              </div>

              {operation === 'TRANSFER' && (
                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="recipient-acc-input" className="form-label">
                      <span>Recipient Account ID</span>
                    </label>
                    <input
                      id="recipient-acc-input"
                      type="text"
                      value={recipientId}
                      onChange={(e) => setRecipientId(e.target.value)}
                      className="form-input"
                      placeholder="e.g. ACC-2002"
                    />
                  </div>

                  <div className="form-group">
                    <label htmlFor="amount-input" className="form-label">
                      <span>Amount ($ USD)</span>
                      <span className="form-hint">Max $1,000 ceiling</span>
                    </label>
                    <input
                      id="amount-input"
                      type="number"
                      step="0.01"
                      min="0.01"
                      max="100000"
                      value={amount}
                      onChange={(e) => setAmount(e.target.value)}
                      className="form-input"
                      placeholder="150.00"
                    />
                  </div>
                </div>
              )}

              {operation === 'TRANSFER' && (
                <div className="form-group">
                  <label htmlFor="memo-input" className="form-label">
                    <span>Payment Memo</span>
                    <span className="form-hint">(Inspected for secondary injection)</span>
                  </label>
                  <input
                    id="memo-input"
                    type="text"
                    value={memo}
                    onChange={(e) => setMemo(e.target.value)}
                    className="form-input"
                    placeholder="e.g. Dinner expenses"
                  />
                </div>
              )}

              {analysisError && (
                <div role="alert" className="verdict-box verdict-BLOCK" style={{ marginBottom: '1rem' }}>
                  <strong style={{ color: 'var(--status-block-text)' }}>Analysis Error:</strong> {analysisError}
                </div>
              )}

              <button
                type="submit"
                disabled={isAnalyzing || !promptText.trim()}
                className="btn btn-primary"
                style={{ width: '100%' }}
                aria-busy={isAnalyzing}
              >
                {isAnalyzing ? 'Inspecting Multi-Stage Pipeline...' : '🛡️ Analyze Untrusted Request'}
              </button>
            </form>
          </div>
        </section>

        {/* Column 2: Analysis Results & Security Boundary */}
        <section aria-labelledby="analysis-result-heading">
          <div className="card">
            <div className="card-header">
              <div>
                <h2 id="analysis-result-heading" className="card-title">
                  📋 Firewall Verdict & Defense Summary
                </h2>
                <p className="card-subtitle">
                  Deterministic server-side security decision & risk metrics
                </p>
              </div>
            </div>

            {verdict ? (
              <div
                role="region"
                aria-live="polite"
                aria-label="Firewall analysis verdict"
                className={`verdict-box verdict-${verdict.verdict}`}
              >
                <div className="verdict-header-row">
                  <StatusBadge type="verdict" value={verdict.verdict} />
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <span className="meta-field-label">Risk Score:</span>
                    <span style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
                      {verdict.risk_score}
                    </span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>/100</span>
                  </div>
                </div>

                <p style={{ fontSize: '0.86rem', lineHeight: 1.5, margin: '0.65rem 0', color: 'var(--text-main)' }}>
                  <strong>Reason:</strong> {verdict.reason}
                </p>

                <div className="verdict-meta-grid">
                  <div>
                    <div className="meta-field-label">Risk Level</div>
                    <StatusBadge type="risk" value={verdict.risk_level} size="sm" />
                  </div>
                  <div>
                    <div className="meta-field-label">Threat Category</div>
                    <div className="meta-field-val" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem' }}>
                      {verdict.threat_category}
                    </div>
                  </div>
                  <div>
                    <div className="meta-field-label">Action Allowed</div>
                    <div className="meta-field-val" style={{ color: verdict.action_allowed ? 'var(--status-approve-text)' : 'var(--status-block-text)' }}>
                      {verdict.action_allowed ? 'TRUE (Permitted)' : 'FALSE (Forbidden)'}
                    </div>
                  </div>
                  <div>
                    <div className="meta-field-label">Request ID</div>
                    <div className="meta-field-val mono-cell">
                      {verdict.request_id}
                    </div>
                  </div>
                </div>

                {verdict.threat_signals && verdict.threat_signals.length > 0 && (
                  <div style={{ marginTop: '0.75rem' }}>
                    <div className="meta-field-label">Detected Threat Indicators:</div>
                    <div className="signals-tag-list">
                      {verdict.threat_signals.map((sig, idx) => (
                        <span key={idx} className="signal-tag">
                          {sig}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {verdict.execution_token ? (
                  <div style={{ marginTop: '0.85rem', padding: '0.5rem 0.75rem', backgroundColor: 'var(--surface-main)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--status-approve-border)' }}>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginBottom: '0.2rem' }}>
                      Cryptographic Execution Token (HMAC-SHA256 Single-Use):
                    </div>
                    <code className="mono-cell" style={{ color: 'var(--status-approve-text)', wordBreak: 'break-all', fontSize: '0.72rem' }}>
                      {verdict.execution_token}
                    </code>
                  </div>
                ) : (
                  <div style={{ marginTop: '0.85rem', padding: '0.5rem 0.75rem', backgroundColor: 'var(--surface-main)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--status-block-border)', color: 'var(--status-block-text)', fontSize: '0.76rem' }}>
                    🔒 Execution Token Withheld — Request failed security policy. Direct banking execution is cryptographically barred.
                  </div>
                )}
              </div>
            ) : (
              <div className="empty-state">
                <div className="empty-icon">🛡️</div>
                <div style={{ fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.25rem' }}>
                  No Analysis Run Yet
                </div>
                <p style={{ fontSize: '0.78rem' }}>
                  Select a test scenario or enter custom prompt text, then click "Analyze Untrusted Request".
                </p>
              </div>
            )}

            {/* Test Execution Boundary */}
            <div style={{ marginTop: '1.25rem', paddingTop: '1rem', borderTop: '1px solid var(--separator-subtle)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                <h3 style={{ fontSize: '0.88rem', fontWeight: 700, color: 'var(--text-main)' }}>
                  🔒 Test Banking Execution Boundary
                </h3>
                <span className="env-badge" style={{ fontSize: '0.68rem' }}>
                  Fail-Closed Verification
                </span>
              </div>
              <p style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
                Directly submit this request payload to the mock banking execution API. Proves that without an approved HMAC token, the backend rejects with 403 Forbidden.
              </p>

              <button
                type="button"
                onClick={handleTestBoundary}
                disabled={isTestingBoundary || !verdict}
                className={`btn btn-sm ${
                  verdict?.action_allowed ? 'btn-success' : 'btn-secondary'
                }`}
                style={{ width: '100%' }}
                aria-busy={isTestingBoundary}
              >
                {isTestingBoundary
                  ? 'Verifying Boundary Defense...'
                  : verdict?.action_allowed
                  ? '⚡ Submit to Execution Boundary (Authorized)'
                  : '⚡ Test Execution Boundary (Will Reject if Blocked)'}
              </button>

              {boundaryResponse && (
                <div
                  role="region"
                  className="verdict-box verdict-APPROVE"
                  style={{ marginTop: '0.75rem' }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.3rem' }}>
                    <StatusBadge type="status" value={boundaryResponse.status} />
                    <span className="mono-cell" style={{ fontSize: '0.72rem' }}>
                      Tx: {boundaryResponse.transaction_id}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-main)' }}>
                    {boundaryResponse.message}
                  </div>
                  {boundaryResponse.new_balance !== undefined && (
                    <div style={{ marginTop: '0.35rem', fontWeight: 700, color: 'var(--status-approve-text)', fontSize: '0.82rem' }}>
                      New Account Balance: ${boundaryResponse.new_balance.toFixed(2)}
                    </div>
                  )}
                </div>
              )}

              {boundaryError && (
                <div
                  role="alert"
                  className="verdict-box verdict-BLOCK"
                  style={{ marginTop: '0.75rem' }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                    <StatusBadge type="status" value="BLOCKED" label="EXECUTION REJECTED" />
                    <span style={{ fontSize: '0.72rem', color: 'var(--status-block-text)', fontWeight: 600 }}>
                      Defense Boundary Verified
                    </span>
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-main)', marginTop: '0.3rem' }}>
                    {boundaryError}
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>
      </div>

      {/* Detection Pipeline Visualization */}
      <PipelineVisualizer verdict={verdict} isAnalyzing={isAnalyzing} />
    </div>
  );
};
