import type {
  FirewallAnalyzeRequest,
  FirewallVerdict,
  BankingExecuteRequest,
  BankingExecuteResponse,
  HealthResponse,
  MetricsResponse,
  AuditLogRecord,
} from '../types';

const API_BASE = '/api/v1';

export class ApiError extends Error {
  status: number;
  data: unknown;

  constructor(message: string, status: number, data?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const errorData = await res.json().catch(() => null);
    const detailMsg =
      errorData && typeof errorData === 'object' && 'detail' in errorData
        ? typeof errorData.detail === 'string'
          ? errorData.detail
          : JSON.stringify(errorData.detail)
        : errorData && typeof errorData === 'object' && 'message' in errorData
        ? String(errorData.message)
        : `Request failed with HTTP status ${res.status}`;
    throw new ApiError(detailMsg, res.status, errorData);
  }
  return res.json() as Promise<T>;
}

export async function checkApiHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE}/health`, {
    headers: { Accept: 'application/json' },
  });
  return handleResponse<HealthResponse>(res);
}

export async function analyzeFirewall(
  req: FirewallAnalyzeRequest
): Promise<FirewallVerdict> {
  const res = await fetch(`${API_BASE}/firewall/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(req),
  });
  return handleResponse<FirewallVerdict>(res);
}

export async function executeBanking(
  req: BankingExecuteRequest,
  principalId?: string
): Promise<BankingExecuteResponse> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  if (principalId) {
    headers['X-Principal-ID'] = principalId;
  }

  const res = await fetch(`${API_BASE}/banking/execute`, {
    method: 'POST',
    headers,
    body: JSON.stringify(req),
  });
  return handleResponse<BankingExecuteResponse>(res);
}

export async function fetchAuditLogs(
  limit: number = 50,
  offset: number = 0
): Promise<AuditLogRecord[]> {
  const res = await fetch(`${API_BASE}/audit/logs?limit=${limit}&offset=${offset}`, {
    headers: { Accept: 'application/json' },
  });
  return handleResponse<AuditLogRecord[]>(res);
}

export async function fetchMetrics(): Promise<MetricsResponse> {
  const res = await fetch(`${API_BASE}/metrics`, {
    headers: { Accept: 'application/json' },
  });
  return handleResponse<MetricsResponse>(res);
}
