import React, { useState } from 'react';
import { StatusBadge } from '../components/common/StatusBadge';
import { ConfirmationModal } from '../components/common/ConfirmationModal';
import { analyzeFirewall, executeBanking, ApiError } from '../services/api';
import type {
  FirewallVerdict,
  BankingExecuteResponse,
  SyntheticAccount,
} from '../types';

const INITIAL_ACCOUNTS: SyntheticAccount[] = [
  {
    account_id: 'ACC-1001',
    owner_name: 'Alice Smith',
    principal_id: 'user_alice',
    balance: 5000.0,
    role: 'CUSTOMER',
    tier: 'STANDARD',
  },
  {
    account_id: 'ACC-2002',
    owner_name: 'Bob Jones',
    principal_id: 'user_bob',
    balance: 2500.0,
    role: 'CUSTOMER',
    tier: 'STANDARD',
  },
  {
    account_id: 'ACC-3003',
    owner_name: 'Charlie Brown',
    principal_id: 'user_charlie',
    balance: 10000.0,
    role: 'CUSTOMER',
    tier: 'PREMIUM',
  },
  {
    account_id: 'ACC-SAFE-CHARITY',
    owner_name: 'Community Charity',
    principal_id: 'charity_admin',
    balance: 500.0,
    role: 'NON-PROFIT',
    tier: 'CHARITY',
  },
];

interface ExecutionHistoryItem {
  id: string;
  timestamp: string;
  sourceAccount: string;
  recipientAccount: string;
  amount: number;
  status: 'EXECUTED' | 'REJECTED' | 'FAILED';
  message: string;
  transactionId?: string;
}

interface TransactionSimulatorPageProps {
  onRefreshTelemetry: () => void;
}

export const TransactionSimulatorPage: React.FC<TransactionSimulatorPageProps> = ({
  onRefreshTelemetry,
}) => {
  // Ledger state
  const [accounts, setAccounts] = useState<SyntheticAccount[]>(INITIAL_ACCOUNTS);
  const [history, setHistory] = useState<ExecutionHistoryItem[]>([]);

  // Transfer Form state
  const [sourceAcc, setSourceAcc] = useState<string>('ACC-1001');
  const [recipientAcc, setRecipientAcc] = useState<string>('ACC-2002');
  const [amount, setAmount] = useState<string>('150.00');
  const [memo, setMemo] = useState<string>('Dinner expenses with colleagues');
  const [rawPrompt, setRawPrompt] = useState<string>(
    'Please send $150.00 from my account ACC-1001 to ACC-2002 for dinner expenses.'
  );

  // Workflow state
  const [isInspecting, setIsInspecting] = useState<boolean>(false);
  const [firewallVerdict, setFirewallVerdict] = useState<FirewallVerdict | null>(null);
  const [inspectionError, setInspectionError] = useState<string | null>(null);

  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [executionResult, setExecutionResult] = useState<BankingExecuteResponse | null>(null);
  const [executionError, setExecutionError] = useState<string | null>(null);

  // Confirmation dialog
  const [showConfirmModal, setShowConfirmModal] = useState<boolean>(false);

  const currentSource = accounts.find((a) => a.account_id === sourceAcc);
  const currentRecipient = accounts.find((a) => a.account_id === recipientAcc);

  // Workflow step determination (1 to 5)
  const currentStep = executionResult
    ? 5
    : firewallVerdict?.action_allowed && firewallVerdict?.execution_token
    ? 4
    : firewallVerdict
    ? 3
    : isInspecting
    ? 2
    : 1;

  // Step 1: Submit to Firewall Analysis
  const handleInspect = async (e: React.FormEvent) => {
    e.preventDefault();
    const numAmount = parseFloat(amount);
    if (isNaN(numAmount) || numAmount <= 0) {
      setInspectionError('Please enter a valid amount greater than $0.00');
      return;
    }

    setIsInspecting(true);
    setInspectionError(null);
    setFirewallVerdict(null);
    setExecutionResult(null);
    setExecutionError(null);

    const payload = {
      text: rawPrompt || `Transfer $${numAmount} from ${sourceAcc} to ${recipientAcc}. Memo: ${memo}`,
      operation: 'TRANSFER' as const,
      account_id: sourceAcc,
      recipient_id: recipientAcc,
      amount: numAmount,
      memo: memo || undefined,
    };

    try {
      const res = await analyzeFirewall(payload);
      setFirewallVerdict(res);
      onRefreshTelemetry();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Firewall analysis failed';
      setInspectionError(msg);
    } finally {
      setIsInspecting(false);
    }
  };

  // Step 2: Open Confirmation Modal before Execution
  const handleExecuteClick = () => {
    if (!firewallVerdict || !firewallVerdict.action_allowed) return;
    setShowConfirmModal(true);
  };

  // Step 3: Atomic Backend Execution
  const handleConfirmExecution = async () => {
    setShowConfirmModal(false);
    if (!firewallVerdict) return;

    setIsExecuting(true);
    setExecutionError(null);
    setExecutionResult(null);

    const numAmount = parseFloat(amount);
    const principalId = currentSource?.principal_id || 'user_alice';

    const payload = {
      request_id: firewallVerdict.request_id,
      execution_token: firewallVerdict.execution_token || '',
      operation: 'TRANSFER' as const,
      account_id: sourceAcc,
      recipient_id: recipientAcc,
      amount: numAmount,
      raw_prompt: rawPrompt,
    };

    try {
      const res = await executeBanking(payload, principalId);
      setExecutionResult(res);

      // Only update balances if backend confirmed execution
      if (res.status === 'EXECUTED' && res.new_balance !== undefined) {
        setAccounts((prev) =>
          prev.map((acc) => {
            if (acc.account_id === sourceAcc) {
              return { ...acc, balance: res.new_balance! };
            }
            if (acc.account_id === recipientAcc) {
              return { ...acc, balance: acc.balance + numAmount };
            }
            return acc;
          })
        );

        setHistory((prev) => [
          {
            id: res.transaction_id || `tx-${Date.now()}`,
            timestamp: new Date().toISOString(),
            sourceAccount: sourceAcc,
            recipientAccount: recipientAcc,
            amount: numAmount,
            status: 'EXECUTED',
            message: res.message,
            transactionId: res.transaction_id,
          },
          ...prev,
        ]);
      }
      onRefreshTelemetry();
    } catch (err: unknown) {
      let errorMsg = 'Banking execution failed';
      if (err instanceof ApiError) {
        errorMsg = `[HTTP ${err.status}] ${err.message}`;
      } else if (err instanceof Error) {
        errorMsg = err.message;
      }
      setExecutionError(errorMsg);

      setHistory((prev) => [
        {
          id: `fail-${Date.now()}`,
          timestamp: new Date().toISOString(),
          sourceAccount: sourceAcc,
          recipientAccount: recipientAcc,
          amount: numAmount,
          status: 'REJECTED',
          message: errorMsg,
        },
        ...prev,
      ]);
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div>
      {/* Visual Workflow Steps Indicator */}
      <div className="card" style={{ padding: '1rem 1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.6rem' }}>
          <h2 className="card-title" style={{ fontSize: '0.92rem' }}>
            🔄 End-to-End Banking Execution Workflow
          </h2>
          <span style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>
            Cryptographically bounded server-side pipeline
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '0.5rem', textAlign: 'center' }}>
          {[
            { step: 1, title: '1. Request Draft', desc: 'Financial Parameters' },
            { step: 2, title: '2. Firewall Analysis', desc: 'Prompt Inspection' },
            { step: 3, title: '3. Policy Decision', desc: 'Deterministic Gate' },
            { step: 4, title: '4. Token Issuance', desc: 'HMAC-SHA256 Secret' },
            { step: 5, title: '5. Core Execution', desc: 'Atomic Balance Update' },
          ].map((s) => {
            const isCompleted = currentStep > s.step;
            const isCurrent = currentStep === s.step;
            return (
              <div
                key={s.step}
                style={{
                  padding: '0.5rem 0.35rem',
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: isCompleted
                    ? 'var(--status-approve-bg)'
                    : isCurrent
                    ? 'var(--emerald-tint)'
                    : 'var(--surface-secondary)',
                  border: `1px solid ${
                    isCompleted
                      ? 'var(--status-approve-border)'
                      : isCurrent
                      ? 'var(--emerald-primary)'
                      : 'var(--border-default)'
                  }`,
                }}
              >
                <div
                  style={{
                    fontSize: '0.74rem',
                    fontWeight: 700,
                    color: isCompleted
                      ? 'var(--status-approve-text)'
                      : isCurrent
                      ? 'var(--emerald-dark)'
                      : 'var(--text-secondary)',
                  }}
                >
                  {isCompleted ? '✓ ' : ''}{s.title}
                </div>
                <div style={{ fontSize: '0.66rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                  {s.desc}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Synthetic Account Cards */}
      <section aria-labelledby="accounts-heading" style={{ marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
          <h2 id="accounts-heading" style={{ fontSize: '0.88rem', fontWeight: 700, color: 'var(--text-main)' }}>
            💳 Synthetic Accounts (Atomic Ledger State)
          </h2>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
            Updated strictly upon backend execution response
          </span>
        </div>

        <div className="grid-2col" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))' }}>
          {accounts.map((acc) => {
            const isSelectedSource = acc.account_id === sourceAcc;
            const isSelectedRecipient = acc.account_id === recipientAcc;
            return (
              <div
                key={acc.account_id}
                className="card"
                style={{
                  marginBottom: 0,
                  padding: '1rem',
                  borderColor: isSelectedSource
                    ? 'var(--emerald-primary)'
                    : isSelectedRecipient
                    ? 'var(--status-approve-border)'
                    : 'var(--border-default)',
                  backgroundColor: isSelectedSource
                    ? 'var(--emerald-tint)'
                    : isSelectedRecipient
                    ? 'var(--status-approve-bg)'
                    : 'var(--surface-main)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.4rem' }}>
                  <div>
                    <span className="mono-cell" style={{ fontWeight: 700, fontSize: '0.82rem' }}>
                      {acc.account_id}
                    </span>
                    <div style={{ fontSize: '0.84rem', fontWeight: 600, color: 'var(--text-main)', marginTop: '0.1rem' }}>
                      {acc.owner_name}
                    </div>
                  </div>
                  <span className="status-badge badge-neutral btn-sm" style={{ fontSize: '0.68rem' }}>
                    {acc.role}
                  </span>
                </div>

                <div style={{ marginTop: '0.5rem' }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Available Balance:</div>
                  <div style={{ fontSize: '1.35rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--text-main)' }}>
                    ${acc.balance.toFixed(2)}
                  </div>
                </div>

                <div style={{ marginTop: '0.5rem', display: 'flex', gap: '0.4rem' }}>
                  {isSelectedSource && (
                    <span className="status-badge badge-approve btn-sm" style={{ fontSize: '0.68rem' }}>
                      Source
                    </span>
                  )}
                  {isSelectedRecipient && (
                    <span className="status-badge badge-review btn-sm" style={{ fontSize: '0.68rem' }}>
                      Recipient
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Simulator Grid */}
      <div className="grid-2col">
        {/* Transfer Form */}
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title" style={{ fontSize: '0.94rem' }}>
                💸 Simulated Transfer Request
              </h2>
              <p className="card-subtitle">
                Configure transfer parameters & draft customer instruction
              </p>
            </div>
          </div>

          <form onSubmit={handleInspect}>
            <div className="form-row">
              <div className="form-group">
                <label htmlFor="source-acc-sel" className="form-label">
                  <span>Source Account</span>
                </label>
                <select
                  id="source-acc-sel"
                  value={sourceAcc}
                  onChange={(e) => {
                    setSourceAcc(e.target.value);
                    setFirewallVerdict(null);
                    setExecutionResult(null);
                  }}
                  className="form-select"
                >
                  {accounts.map((a) => (
                    <option key={a.account_id} value={a.account_id}>
                      {a.account_id} ({a.owner_name} - ${a.balance.toFixed(2)})
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label htmlFor="recipient-acc-sel" className="form-label">
                  <span>Recipient Account</span>
                </label>
                <select
                  id="recipient-acc-sel"
                  value={recipientAcc}
                  onChange={(e) => {
                    setRecipientAcc(e.target.value);
                    setFirewallVerdict(null);
                    setExecutionResult(null);
                  }}
                  className="form-select"
                >
                  {accounts
                    .filter((a) => a.account_id !== sourceAcc)
                    .map((a) => (
                      <option key={a.account_id} value={a.account_id}>
                        {a.account_id} ({a.owner_name})
                      </option>
                    ))}
                  <option value="ACC-UNKNOWN">ACC-UNKNOWN (Adversarial Target)</option>
                </select>
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label htmlFor="transfer-amt-in" className="form-label">
                  <span>Amount ($ USD)</span>
                  <span className="form-hint">Ceiling: $1,000.00</span>
                </label>
                <input
                  id="transfer-amt-in"
                  type="number"
                  step="0.01"
                  min="0.01"
                  max="50000"
                  value={amount}
                  onChange={(e) => {
                    setAmount(e.target.value);
                    setFirewallVerdict(null);
                    setExecutionResult(null);
                  }}
                  className="form-input"
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="transfer-memo-in" className="form-label">
                  <span>Payment Memo</span>
                  <span className="form-hint">(Inspected)</span>
                </label>
                <input
                  id="transfer-memo-in"
                  type="text"
                  value={memo}
                  onChange={(e) => {
                    setMemo(e.target.value);
                    setFirewallVerdict(null);
                    setExecutionResult(null);
                  }}
                  className="form-input"
                  placeholder="e.g. Dinner expenses"
                />
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="transfer-prompt-in" className="form-label">
                <span>Associated Natural Language Prompt</span>
                <span className="form-hint">Inspected by Firewall Gateway</span>
              </label>
              <textarea
                id="transfer-prompt-in"
                value={rawPrompt}
                onChange={(e) => {
                  setRawPrompt(e.target.value);
                  setFirewallVerdict(null);
                  setExecutionResult(null);
                }}
                className="form-textarea"
                rows={3}
              />
            </div>

            {inspectionError && (
              <div role="alert" className="verdict-box verdict-BLOCK" style={{ marginBottom: '1rem' }}>
                <strong>Validation Error:</strong> {inspectionError}
              </div>
            )}

            <button
              type="submit"
              disabled={isInspecting}
              className="btn btn-primary"
              style={{ width: '100%' }}
              aria-busy={isInspecting}
            >
              {isInspecting ? 'Inspecting with AI Firewall...' : '1. Analyze Transfer with Firewall'}
            </button>
          </form>
        </div>

        {/* Boundary & Execution Panel */}
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title" style={{ fontSize: '0.94rem' }}>
                🛡️ Authorization & Execution Boundary
              </h2>
              <p className="card-subtitle">
                Enforcing cryptographic token and atomic double-spend prevention
              </p>
            </div>
          </div>

          {/* Firewall Gate Feedback */}
          {firewallVerdict ? (
            <div
              className={`verdict-box verdict-${firewallVerdict.verdict}`}
              style={{ marginBottom: '1rem' }}
            >
              <div className="verdict-header-row">
                <StatusBadge type="verdict" value={firewallVerdict.verdict} />
                <span className="mono-cell" style={{ fontWeight: 700 }}>
                  Risk Score: {firewallVerdict.risk_score}/100
                </span>
              </div>
              <div style={{ fontSize: '0.82rem', margin: '0.4rem 0', color: 'var(--text-main)' }}>
                {firewallVerdict.reason}
              </div>

              {firewallVerdict.execution_token ? (
                <div style={{ marginTop: '0.5rem', fontSize: '0.72rem', color: 'var(--status-approve-text)' }}>
                  ✓ Cryptographic Token Issued: <code>{firewallVerdict.execution_token.substring(0, 24)}...</code>
                </div>
              ) : (
                <div style={{ marginTop: '0.5rem', fontSize: '0.72rem', color: 'var(--status-block-text)' }}>
                  🔒 No token issued. Security boundary will reject any execution attempt.
                </div>
              )}
            </div>
          ) : (
            <div className="empty-state" style={{ marginBottom: '1rem', padding: '1.5rem 1rem' }}>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                Step 1 required: Submit transfer above for firewall inspection
              </div>
            </div>
          )}

          {/* Execution Button */}
          <div style={{ marginTop: '0.5rem' }}>
            <button
              type="button"
              onClick={handleExecuteClick}
              disabled={
                !firewallVerdict ||
                !firewallVerdict.action_allowed ||
                isExecuting
              }
              className="btn btn-success"
              style={{ width: '100%', marginBottom: '0.75rem' }}
              aria-busy={isExecuting}
            >
              {isExecuting
                ? 'Processing Core Transaction...'
                : firewallVerdict?.action_allowed
                ? '2. Execute Authorized Banking Transaction'
                : 'Execution Locked (Requires APPROVE Verdict)'}
            </button>

            {executionResult && (
              <div
                role="region"
                className="verdict-box verdict-APPROVE"
                style={{ marginTop: '0.5rem' }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                  <StatusBadge type="status" value={executionResult.status} />
                  <span className="mono-cell" style={{ fontSize: '0.74rem' }}>
                    Tx ID: {executionResult.transaction_id}
                  </span>
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-main)' }}>
                  {executionResult.message}
                </div>
                {executionResult.new_balance !== undefined && (
                  <div style={{ marginTop: '0.35rem', fontWeight: 700, color: 'var(--status-approve-text)', fontSize: '0.84rem' }}>
                    Updated Source Balance: ${executionResult.new_balance.toFixed(2)}
                  </div>
                )}
              </div>
            )}

            {executionError && (
              <div
                role="alert"
                className="verdict-box verdict-BLOCK"
                style={{ marginTop: '0.5rem' }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                  <StatusBadge type="status" value="FAILED" label="EXECUTION BLOCKED" />
                  <span style={{ fontSize: '0.72rem', color: 'var(--status-block-text)', fontWeight: 600 }}>
                    Boundary Enforced
                  </span>
                </div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-main)', marginTop: '0.3rem' }}>
                  {executionError}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Transaction Activity */}
      <section className="card" style={{ marginTop: '1.25rem' }}>
        <div className="card-header">
          <div>
            <h2 className="card-title" style={{ fontSize: '0.92rem' }}>
              📜 Recent Simulated Banking Activity
            </h2>
            <p className="card-subtitle">
              Confirmed executions recorded in session ledger
            </p>
          </div>
        </div>

        {history.length > 0 ? (
          <div className="table-responsive">
            <table className="data-table" aria-label="Recent Simulated Banking Activity">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Transaction ID</th>
                  <th>From</th>
                  <th>To</th>
                  <th>Amount</th>
                  <th>Status</th>
                  <th>Confirmation Message</th>
                </tr>
              </thead>
              <tbody>
                {history.map((item) => (
                  <tr key={item.id}>
                    <td className="mono-cell">{new Date(item.timestamp).toLocaleTimeString()}</td>
                    <td className="mono-cell" style={{ fontWeight: 600 }}>
                      {item.transactionId || item.id}
                    </td>
                    <td className="mono-cell">{item.sourceAccount}</td>
                    <td className="mono-cell">{item.recipientAccount}</td>
                    <td className="mono-cell" style={{ fontWeight: 700 }}>
                      ${item.amount.toFixed(2)}
                    </td>
                    <td>
                      <StatusBadge type="status" value={item.status} size="sm" />
                    </td>
                    <td style={{ fontSize: '0.78rem' }}>{item.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-icon">💳</div>
            <div style={{ fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.2rem' }}>
              No Simulated Transactions Executed Yet
            </div>
            <p style={{ fontSize: '0.78rem' }}>
              Submit a transfer above to inspect it through the firewall and execute it upon approval.
            </p>
          </div>
        )}
      </section>

      {/* Confirmation Modal */}
      <ConfirmationModal
        isOpen={showConfirmModal}
        title="Confirm Simulated Banking Transfer"
        message={`Are you sure you want to execute a transfer of $${amount} from ${sourceAcc} (${currentSource?.owner_name}) to ${recipientAcc} (${currentRecipient?.owner_name || 'Recipient'})? This will verify the cryptographic token and atomically update the synthetic ledger.`}
        confirmLabel="Confirm & Execute Transfer"
        cancelLabel="Cancel"
        onConfirm={handleConfirmExecution}
        onCancel={() => setShowConfirmModal(false)}
      />
    </div>
  );
};
