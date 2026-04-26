'use client';
import { Alert } from '@/types';
import { useMemo } from 'react';
import {
  PieChart, Pie, Cell, Tooltip as PieTooltip, Legend as PieLegend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as BarTooltip, Legend as BarLegend, ResponsiveContainer
} from 'recharts';

interface Props {
  alerts: Alert[];
}

const PIE_COLORS = [
  'var(--primary)',
  'var(--text-secondary)',
  '#3b82f6',
  '#94a3b8',
  '#1d4ed8',
  '#64748b',
];

export default function DistributionCharts({ alerts }: Props) {
  const clusterData = useMemo(() => {
    const anomalies = alerts.filter(a => a.anomaly === 1);
    const counts: Record<string, number> = {};
    anomalies.forEach(a => {
      const c = a.cluster_id !== null && a.cluster_id !== undefined ? `Cluster ${a.cluster_id}` : 'Unclustered';
      counts[c] = (counts[c] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value);
  }, [alerts]);

  const ruleLevelData = useMemo(() => {
    const counts: Record<number, { level: number, Anomaly: number, Normal: number }> = {};
    alerts.forEach(a => {
      const lvl = a.rule_level;
      if (!counts[lvl]) {
        counts[lvl] = { level: lvl, Anomaly: 0, Normal: 0 };
      }
      if (a.anomaly === 1) counts[lvl].Anomaly += 1;
      else counts[lvl].Normal += 1;
    });
    return Object.values(counts).sort((a, b) => a.level - b.level);
  }, [alerts]);

  if (alerts.length === 0) return null;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 24, marginTop: 24 }}>
      
      {/* Clusters Pie Chart */}
      <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', padding: 20, boxShadow: 'var(--shadow-card)' }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 16 }}>
          Anomaly Clusters
        </div>
        {clusterData.length > 0 ? (
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer>
              <PieChart>
                <Pie
                  data={clusterData}
                  cx="50%" cy="50%"
                  innerRadius={50} outerRadius={80}
                  paddingAngle={2}
                  dataKey="value"
                  stroke="var(--bg-surface)"
                  strokeWidth={2}
                >
                  {clusterData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <PieTooltip 
                  contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 0, fontSize: 12, color: 'var(--text-primary)' }}
                  itemStyle={{ color: 'var(--text-primary)', fontSize: 12 }}
                />
                <PieLegend wrapperStyle={{ fontSize: 11, color: 'var(--text-secondary)' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div style={{ height: 220, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
            No anomalies found.
          </div>
        )}
      </div>

      {/* Rule Level Bar Chart */}
      <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', padding: 20, boxShadow: 'var(--shadow-card)' }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 16 }}>
          Rule Level Distribution
        </div>
        <div style={{ width: '100%', height: 220 }}>
          <ResponsiveContainer>
            <BarChart data={ruleLevelData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
              <XAxis dataKey="level" tick={{ fontSize: 10, fill: 'var(--text-secondary)' }} axisLine={{ stroke: 'var(--border)' }} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: 'var(--text-secondary)' }} axisLine={false} tickLine={false} allowDecimals={false} />
              <BarTooltip 
                contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 0, fontSize: 12, color: 'var(--text-primary)' }}
                cursor={{ fill: 'var(--bg-elevated)' }}
              />
              <BarLegend wrapperStyle={{ fontSize: 11, color: 'var(--text-secondary)' }} />
              <Bar dataKey="Normal" stackId="a" fill="var(--text-muted)" radius={[0,0,0,0]} />
              <Bar dataKey="Anomaly" stackId="a" fill="var(--red)" radius={[2,2,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

    </div>
  );
}
