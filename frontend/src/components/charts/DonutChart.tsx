import React from 'react';

interface DonutSlice {
  label: string;
  count: number;
  color: string;
}

interface DonutChartProps {
  data: {
    approved: number;
    blocked: number;
    review: number;
  };
  size?: number;
}

export const DonutChart: React.FC<DonutChartProps> = ({ data, size = 180 }) => {
  const slices: DonutSlice[] = [
    { label: 'Approved', count: data.approved, color: '#18794E' },
    { label: 'Blocked', count: data.blocked, color: '#C43D3D' },
    { label: 'Review', count: data.review, color: '#916A0A' },
  ];

  const total = slices.reduce((acc, s) => acc + s.count, 0);

  if (total === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: size, color: 'var(--text-secondary)' }}>
        <div style={{ fontSize: '0.82rem' }}>No decision events recorded</div>
        <div style={{ fontSize: '0.72rem', color: 'var(--chart-gray)', marginTop: '0.2rem' }}>Run test scenarios to populate</div>
      </div>
    );
  }

  // Calculate SVG arc paths
  const radius = 64;
  const strokeWidth = 24;
  const circumference = 2 * Math.PI * radius;
  let accumulatedOffset = 0;

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', justifyContent: 'center', flexWrap: 'wrap' }}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 160 160"
        aria-label={`Donut chart of decisions: ${data.approved} approved, ${data.blocked} blocked, ${data.review} review`}
        role="img"
      >
        <circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          stroke="var(--separator-subtle)"
          strokeWidth={strokeWidth}
        />
        {slices.map((slice) => {
          if (slice.count === 0) return null;
          const strokeDasharray = `${(slice.count / total) * circumference} ${circumference}`;
          const strokeDashoffset = -accumulatedOffset;
          accumulatedOffset += (slice.count / total) * circumference;

          return (
            <circle
              key={slice.label}
              cx="80"
              cy="80"
              r={radius}
              fill="none"
              stroke={slice.color}
              strokeWidth={strokeWidth}
              strokeDasharray={strokeDasharray}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              transform="rotate(-90 80 80)"
              style={{ transition: 'stroke-dasharray 0.3s ease' }}
            />
          );
        })}
        {/* Center label */}
        <text
          x="80"
          y="76"
          textAnchor="middle"
          dominantBaseline="middle"
          fontSize="20"
          fontWeight="800"
          fontFamily="var(--font-mono)"
          fill="var(--text-main)"
        >
          {total}
        </text>
        <text
          x="80"
          y="95"
          textAnchor="middle"
          dominantBaseline="middle"
          fontSize="10"
          fontWeight="600"
          fill="var(--text-secondary)"
        >
          TOTAL
        </text>
      </svg>

      {/* Legend */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', minWidth: '130px' }}>
        {slices.map((slice) => (
          <div
            key={slice.label}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              fontSize: '0.78rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <span
                style={{
                  width: '10px',
                  height: '10px',
                  borderRadius: '3px',
                  backgroundColor: slice.color,
                  display: 'inline-block',
                }}
              />
              <span style={{ color: 'var(--text-main)', fontWeight: 500 }}>{slice.label}</span>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: slice.color }}>
              {slice.count} ({total > 0 ? Math.round((slice.count / total) * 100) : 0}%)
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};
