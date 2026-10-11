export type Verdict = 'APPROVE' | 'BLOCK' | 'REVIEW';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ThreatCategory =
  | 'NONE'
  | 'PROMPT_INJECTION'
  | 'JAILBREAK'
  | 'OBFUSCATION'
  | 'POLICY_VIOLATION'
  | 'UNAUTHORIZED_ACTION'
  | 'INVALID_INPUT'
  | 'AMBIGUOUS_REQUEST'
  | 'CLASSIFIER_FAILURE';

export type BankingOperation = 'CUSTOMER_SUPPORT' | 'BALANCE_INQUIRY' | 'TRANSFER';

export type NavPage =
  | 'overview'
  | 'live-firewall'
  | 'threat-intel'
  | 'transaction-simulator'
  | 'audit-trail'
  | 'system-health';

export interface FirewallAnalyzeRequest {
  request_id?: string;
  text: string;
  operation: BankingOperation;
  account_id?: string;
  recipient_id?: string;
  amount?: number;
  memo?: string;
}

export interface FirewallVerdict {
  request_id: string;
  verdict: Verdict;
  risk_level: RiskLevel;
  risk_score: number;
  threat_category: ThreatCategory;
  reason: string;
  action_allowed: boolean;
  requires_review: boolean;
  execution_token?: string | null;
  threat_signals?: string[];
  normalized_text?: string;
  timestamp: string;
}

export interface BankingExecuteRequest {
  request_id: string;
  execution_token: string;
  operation: BankingOperation;
  account_id: string;
  recipient_id?: string;
  amount?: number;
  raw_prompt?: string;
  idempotency_key?: string;
}

export interface BankingExecuteResponse {
  transaction_id: string;
  request_id: string;
  status: 'EXECUTED' | 'REJECTED' | 'FAILED';
  operation: BankingOperation;
  account_id: string;
  recipient_id?: string;
  amount?: number;
  new_balance?: number;
  message: string;
  timestamp: string;
}

export interface AuditLogRecord {
  audit_id: string;
  timestamp: string;
  request_id: string;
  operation: string;
  account_id?: string | null;
  recipient_id?: string | null;
  amount?: number | null;
  risk_score: number;
  risk_level: string;
  verdict: string;
  threat_category: string;
  threat_signals: string[];
  executed: boolean;
  reason: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  service: string;
  classifier_status: string;
  uptime_seconds: number;
}

export interface MetricsResponse {
  total_inspected_requests: number;
  verdict_distribution: {
    APPROVE: number;
    BLOCK: number;
    REVIEW: number;
    [key: string]: number;
  };
  threat_distribution: Record<string, number>;
  recorded_audit_entries: number;
}

export interface SyntheticAccount {
  account_id: string;
  owner_name: string;
  principal_id: string;
  balance: number;
  role: string;
  tier: string;
}

export interface ScenarioPreset {
  id: string;
  title: string;
  badge: string;
  badgeType: 'benign' | 'attack' | 'review';
  text: string;
  operation: BankingOperation;
  account_id?: string;
  recipient_id?: string;
  amount?: number;
  memo?: string;
  description: string;
}
