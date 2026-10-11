import React from 'react';

interface MetricCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  icon?: string;
  variant?: 'default' | 'approve' | 'block' | 'review' | 'threat' | 'emerald';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  subtext,
  icon,
  variant = 'default',
}) => {
  const variantClass = variant !== 'default' ? `kpi-${variant}` : '';

  return (
    <div className={`kpi-card ${variantClass}`}>
      <div className="kpi-card-header">
        <span className="kpi-label">{label}</span>
        {icon && <span className="kpi-icon" aria-hidden="true">{icon}</span>}
      </div>
      <div className="kpi-value">{value}</div>
      {subtext && <div className="kpi-subtext">{subtext}</div>}
    </div>
  );
};
