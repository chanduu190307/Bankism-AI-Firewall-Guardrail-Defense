import React from 'react';

interface ActivityPoint {
  timeLabel: string;
  count: number;
}

interface ActivityChartProps {
  data?: ActivityPoint[];
  height?: number;
}

export const ActivityChart: React.FC<ActivityChartProps> = ({ data, height = 140 }) => {
  // If no data provided, display default or recent hour points
  const points: ActivityPoint[] = data && data.length > 0 ? data : [
    { timeLabel: '10:00', count: 12 },
    { timeLabel: '11:00', count: 18 },
    { timeLabel: '12:00', count: 25 },
    { timeLabel: '13:00', count: 32 },
    { timeLabel: '14:00', count: 28 },
    { timeLabel: '15:00', count: 42 },
  ];

  const maxVal = Math.max(...points.map((p) => p.count), 10);
  const width = 360;
  const paddingX = 24;
  const paddingY = 20;
  const chartWidth = width - paddingX * 2;
  const chartHeight = height - paddingY * 2;

  const coords = points.map((p, idx) => {
    const x = paddingX + (idx / (points.length - 1)) * chartWidth;
    const y = paddingY + chartHeight - (p.count / maxVal) * chartHeight;
    return { x, y, ...p };
  });

  const pathD = coords.reduce((acc, c, idx) => {
    return idx === 0 ? `M ${c.x} ${c.y}` : `${acc} L ${c.x} ${c.y}`;
  }, '');

  const areaD = `${pathD} L ${coords[coords.length - 1].x} ${height - paddingY} L ${coords[0].x} ${height - paddingY} Z`;

  return (
    <div style={{ width: '100%', overflowX: 'auto' }}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        style={{ width: '100%', height: 'auto', display: 'block' }}
        aria-label="Activity timeline chart showing request inspection volume over time"
        role="img"
      >
        {/* Subtle grid lines */}
        <line
          x1={paddingX}
          y1={paddingY}
          x2={width - paddingX}
          y2={paddingY}
          stroke="var(--separator-subtle)"
          strokeDasharray="3 3"
        />
        <line
          x1={paddingX}
          y1={paddingY + chartHeight / 2}
          x2={width - paddingX}
          y2={paddingY + chartHeight / 2}
          stroke="var(--separator-subtle)"
          strokeDasharray="3 3"
        />
        <line
          x1={paddingX}
          y1={height - paddingY}
          x2={width - paddingX}
          y2={height - paddingY}
          stroke="var(--border-default)"
        />

        {/* Emerald Area Fill */}
        <path d={areaD} fill="var(--emerald-tint)" opacity="0.6" />

        {/* Emerald Stroke Line */}
        <path
          d={pathD}
          fill="none"
          stroke="var(--emerald-primary)"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />

        {/* Data points */}
        {coords.map((c, i) => (
          <g key={i}>
            <circle
              cx={c.x}
              cy={c.y}
              r="3.5"
              fill="var(--surface-main)"
              stroke="var(--emerald-primary)"
              strokeWidth="2"
            />
            <text
              x={c.x}
              y={height - 6}
              textAnchor="middle"
              fontSize="9"
              fill="var(--text-secondary)"
              fontFamily="var(--font-mono)"
            >
              {c.timeLabel}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
};
