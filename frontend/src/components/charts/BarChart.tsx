import React from 'react';

interface BarData {
  category: string;
  count: number;
}

interface BarChartProps {
  data: Record<string, number>;
  maxBars?: number;
}

export const BarChart: React.FC<BarChartProps> = ({ data, maxBars = 6 }) => {
  const items: BarData[] = Object.entries(data)
    .filter(([cat]) => cat !== 'NONE')
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, maxBars);

  const maxVal = Math.max(...items.map((i) => i.count), 1);

  if (items.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '140px', color: 'var(--text-secondary)' }}>
        <div style={{ fontSize: '0.82rem' }}>No threat category events logged</div>
        <div style={{ fontSize: '0.72rem', color: 'var(--chart-gray)', marginTop: '0.2rem' }}>All analyzed queries have been clean or unpopulated</div>
      </div>
    );
  }

  // Format label for display
  const formatLabel = (cat: string) => {
    return cat
      .replace(/_/g, ' ')
      .toLowerCase()
      .replace(/\b\w/g, (c) => c.toUpperCase());
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
      {items.map((item) => {
        const percentage = Math.round((item.count / maxVal) * 100);
        return (
          <div key={item.category} style={{ fontSize: '0.78rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
              <span style={{ color: 'var(--text-main)', fontWeight: 600 }}>
                {formatLabel(item.category)}
              </span>
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--status-threat-text)', fontWeight: 700 }}>
                {item.count} detections
              </span>
            </div>
            <div
              style={{
                width: '100%',
                height: '8px',
                backgroundColor: 'var(--surface-secondary)',
                borderRadius: '4px',
                overflow: 'hidden',
                border: '1px solid var(--border-default)',
              }}
            >
              <div
                style={{
                  width: `${percentage}%`,
                  height: '100%',
                  backgroundColor: 'var(--status-threat-text)',
                  borderRadius: '3px',
                  transition: 'width 0.3s ease',
                }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
};
