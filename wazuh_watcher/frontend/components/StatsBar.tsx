'use client';
import { PipelineResult } from '@/types';

interface Props {
  data: PipelineResult | null;
  lastUpdated: Date | null;
  isRefreshing: boolean;
}

interface StatItem {
  label: string;
  value: string | number;
  color: string;
  iconBg: string;
  accentLine: string;
}

export default function StatsBar({ data, lastUpdated, isRefreshing }: Props) {
  if (!data) {
    return (
      <div className="stats-bar">
        <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: 10 }}>
          Loading statistics...
        </div>
      </div>
    );
  }

  const anomPct  = data.total_alerts > 0 ? ((data.anomaly_count / data.total_alerts) * 100).toFixed(1) : '0';
  const highConf = data.confidence_distribution?.High  ?? 0;
  const medConf  = data.confidence_distribution?.Medium ?? 0;

  const stats: StatItem[] = [
    {
      label: 'Total Alerts',
      value: data.total_alerts.toLocaleString(),
      color: 'var(--primary)', iconBg: 'var(--bg-surface)',
      accentLine: 'var(--primary)',
    },
    {
      label: 'Anomalies',
      value: data.anomaly_count.toLocaleString(),
      color: data.anomaly_count > 0 ? 'var(--red)' : 'var(--green)',
      iconBg: 'var(--bg-surface)',
      accentLine: data.anomaly_count > 0 ? 'var(--red)' : 'var(--green)',
    },
    {
      label: 'Anomaly Rate',
      value: `${anomPct}%`,
      color: parseFloat(anomPct) > 20 ? 'var(--orange)' : 'var(--primary)',
      iconBg: 'var(--bg-surface)',
      accentLine: parseFloat(anomPct) > 20 ? 'var(--orange)' : 'var(--primary)',
    },
    {
      label: 'High Confidence',
      value: highConf,
      color: highConf > 0 ? 'var(--red)' : 'var(--text-muted)',
      iconBg: 'var(--bg-surface)',
      accentLine: highConf > 0 ? 'var(--red)' : 'var(--border)',
    },
  ];

  return (
    <div className="stats-bar">
      {stats.map((s, i) => (
        <div
          key={i}
          className="stat-card"
          style={{
            '--stat-color': s.color,
            '--icon-bg': s.iconBg,
            '--accent-line': s.accentLine,
          } as React.CSSProperties}
        >
          <div className="stat-value">{s.value}</div>
          <div className="stat-label">{s.label}</div>
        </div>
      ))}
    </div>
  );
}
