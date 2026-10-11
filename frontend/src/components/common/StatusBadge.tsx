import React from 'react';
import type { Verdict, RiskLevel } from '../../types';

interface StatusBadgeProps {
  type: 'verdict' | 'risk' | 'status' | 'custom';
  value: string;
  label?: string;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  type,
  value,
  label,
  size = 'md',
}) => {
  let badgeClass = 'badge-neutral';
  let icon = '•';
  const displayLabel = label || value;

  if (type === 'verdict') {
    const v = value.toUpperCase() as Verdict;
    if (v === 'APPROVE') {
      badgeClass = 'badge-approve';
      icon = '✓';
    } else if (v === 'BLOCK') {
      badgeClass = 'badge-block';
      icon = '✕';
    } else if (v === 'REVIEW') {
      badgeClass = 'badge-review';
      icon = '⚠';
    }
  } else if (type === 'risk') {
    const r = value.toUpperCase() as RiskLevel;
    if (r === 'LOW') {
      badgeClass = 'badge-approve';
      icon = '🟢';
    } else if (r === 'MEDIUM') {
      badgeClass = 'badge-review';
      icon = '🟡';
    } else if (r === 'HIGH') {
      badgeClass = 'badge-threat';
      icon = '🟠';
    } else if (r === 'CRITICAL') {
      badgeClass = 'badge-block';
      icon = '🔴';
    }
  } else if (type === 'status') {
    if (value === 'COMPLETED' || value === 'EXECUTED' || value === 'HEALTHY' || value === 'ONLINE') {
      badgeClass = 'badge-approve';
      icon = '✓';
    } else if (value === 'BLOCKED' || value === 'FAILED' || value === 'ERROR') {
      badgeClass = 'badge-block';
      icon = '✕';
    } else if (value === 'PENDING' || value === 'REVIEW' || value === 'DEGRADED') {
      badgeClass = 'badge-review';
      icon = '⏳';
    }
  }

  return (
    <span
      className={`status-badge ${badgeClass} ${size === 'sm' ? 'btn-sm' : ''}`}
      role="status"
    >
      <span aria-hidden="true" style={{ fontSize: '0.9em' }}>{icon}</span>
      <span>{displayLabel}</span>
    </span>
  );
};
