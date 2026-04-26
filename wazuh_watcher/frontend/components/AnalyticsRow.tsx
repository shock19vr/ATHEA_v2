'use client';
import { PipelineResult } from '@/types';

interface Props { data: PipelineResult }

const CONF_COLORS: Record<string, string> = {
  High:   'var(--red)',
  Medium: 'var(--orange)',
  Low:    'var(--text-muted)',
};

export default function AnalyticsRow({ data }: Props) {
  const mitreStages = data.top_mitre_stages ?? [];
  const confDist    = data.confidence_distribution ?? {};
  const totalAnomaly = data.anomaly_count || 1;
  const maxMitre = Math.max(...mitreStages.map(([, c]) => c), 1);

  const confEntries = Object.entries(confDist).sort(
    ([a], [b]) => ['High','Medium','Low'].indexOf(a) - ['High','Medium','Low'].indexOf(b)
  );
  const totalConf = confEntries.reduce((s, [, v]) => s + v, 0) || 1;

  if (mitreStages.length === 0 && confEntries.length === 0) return null;

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: mitreStages.length > 0 && confEntries.length > 0 ? '1fr 280px' : '1fr',
      gap: 14,
    }}>

      {mitreStages.length > 0 && (
        <div style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          padding: '20px',
          boxShadow: 'var(--shadow-card)',
        }}>
          <div style={{
            fontSize: 11, fontWeight: 700, color: 'var(--text-primary)',
            textTransform: 'uppercase', letterSpacing: '0.5px',
            marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8,
          }}>
            MITRE ATT&amp;CK Distribution
            <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-muted)', fontWeight: 400, textTransform: 'none' }}>
              {data.anomaly_count} anomalies
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {mitreStages.map(([stage, count]) => {
              const pct = (count / maxMitre) * 100;
              const color = 'var(--primary)';
              return (
                <div key={stage} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div style={{
                    width: 130, minWidth: 130,
                    fontSize: 12, color: 'var(--text-secondary)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>{stage}</div>
                  <div style={{ flex: 1, height: 6, background: 'var(--border)', borderRadius: 0, overflow: 'hidden' }}>
                    <div style={{
                      height: '100%', width: `${pct}%`,
                      background: color,
                      borderRadius: 0,
                      transition: 'width 0.8s cubic-bezier(0.4,0,0.2,1)',
                    }} />
                  </div>
                  <div style={{
                    width: 24, textAlign: 'right',
                    fontFamily: 'var(--font-mono)', fontSize: 11,
                    color: 'var(--text-primary)', fontWeight: 600,
                  }}>{count}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}


      {confEntries.length > 0 && (
        <div style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          padding: '20px',
          boxShadow: 'var(--shadow-card)',
        }}>
          <div style={{
            fontSize: 11, fontWeight: 700, color: 'var(--text-primary)',
            textTransform: 'uppercase', letterSpacing: '0.5px',
            marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8,
          }}>
            Confidence Split
          </div>

          <div style={{
            display: 'flex', height: 8, borderRadius: 0, overflow: 'hidden',
            gap: 2, marginBottom: 20,
          }}>
            {confEntries.map(([tier, count]) => (
              <div
                key={tier}
                title={`${tier}: ${count}`}
                style={{
                  flex: count / totalConf,
                  background: CONF_COLORS[tier] ?? 'var(--border)',
                  borderRadius: 0,
                  transition: 'flex 0.6s ease',
                }}
              />
            ))}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {confEntries.map(([tier, count]) => {
              const pct = ((count / totalAnomaly) * 100).toFixed(0);
              const color = CONF_COLORS[tier] ?? 'var(--border)';
              return (
                <div key={tier} style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                  <div style={{
                    width: 8, height: 8, borderRadius: 0,
                    background: color, flexShrink: 0,
                  }} />
                  <span style={{ flex: 1, fontSize: 13, color: 'var(--text-secondary)' }}>{tier}</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-primary)', fontWeight: 600 }}>{count}</span>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', width: 38, textAlign: 'right' }}>({pct}%)</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
