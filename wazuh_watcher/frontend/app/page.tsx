'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { Alert, PipelineResult, ApiStatus } from '@/types';
import { fetchStatus, triggerAnalysis } from '@/lib/api';
import StatsBar from '@/components/StatsBar';
import AnomalyTable from '@/components/AnomalyTable';
import LogDetailDrawer from '@/components/LogDetailDrawer';
import AnalyticsRow from '@/components/AnalyticsRow';
import DistributionCharts from '@/components/DistributionCharts';
import Chatbot from '@/components/Chatbot';

const POLL_MS = 60_000;

export default function DashboardPage() {
  const [data, setData]               = useState<PipelineResult | null>(null);
  const [status, setStatus]           = useState<ApiStatus | null>(null);
  const [selectedAlert, setSelected]  = useState<Alert | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [isRefreshing, setRefreshing] = useState(false);
  const [error, setError]             = useState<string | null>(null);
  const [minutesBack, setMinutesBack] = useState(60);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const loadData = useCallback(async () => {
    setRefreshing(true);
    setError(null);
    try {
      const [result, st] = await Promise.all([
        triggerAnalysis(minutesBack),
        fetchStatus(),
      ]);
      setData(result);
      setStatus(st);
      setLastUpdated(new Date());
      setSelected(prev => {
        if (!prev) return null;
        const still = result.alerts.find(a => a.doc_id === prev.doc_id);
        return still ?? null;
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg.includes('503')
        ? 'Pipeline is initialising — hang on, first analysis is running…'
        : `Error: ${msg}`);
    } finally {
      setRefreshing(false);
    }
  }, [minutesBack]);

  useEffect(() => {
    loadData();

    const tick = () => {
      loadData();
      timerRef.current = setTimeout(tick, POLL_MS);
    };
    timerRef.current = setTimeout(tick, POLL_MS);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [loadData]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setSelected(null);
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const [countdown, setCountdown] = useState(POLL_MS / 1000);
  useEffect(() => {
    const interval = setInterval(() => {
      setCountdown(prev => {
        if (prev <= 1) return POLL_MS / 1000;
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [lastUpdated]);

  const anomalies = data?.alerts.filter(a => a.anomaly === 1) ?? [];

  return (
    <>
      <div className="dashboard-layout">
        <div className="main-wrapper">
          <header className="topbar">
            <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
               <div>
                 <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.3px' }}>Wazuh-ATHEA</div>
                 <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>XAI Anomaly Detection</div>
               </div>
               
               <div style={{ width: 1, height: 32, background: 'var(--border)' }}></div>

               {data && (
                 <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                   Model: <strong>{data.model_used}</strong> | Sens: <strong>{(data.contamination_used * 100).toFixed(0)}%</strong> | v{data.pipeline_version}
                 </span>
               )}
            </div>
            
            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <div className="live-badge" role="status" aria-live="polite">
                <span className="live-dot" />
                Live Monitoring
              </div>

              <select
                id="window-select"
                value={minutesBack}
                onChange={e => setMinutesBack(Number(e.target.value))}
                style={{
                  background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                  color: 'var(--text-secondary)', padding: '6px 10px', fontSize: 12, cursor: 'pointer',
                }}
                aria-label="Alert time window"
              >
                <option value={30}>Last 30m</option>
                <option value={60}>Last 60m</option>
                <option value={180}>Last 3h</option>
                <option value={360}>Last 6h</option>
                <option value={720}>Last 12h</option>
              </select>

              <button
                id="refresh-btn"
                onClick={() => loadData()}
                disabled={isRefreshing}
                style={{
                  padding: '6px 14px',
                  border: '1px solid var(--primary)',
                  background: 'var(--primary)',
                  color: '#ffffff',
                  fontSize: 12, display: 'flex', alignItems: 'center', gap: 6,
                  opacity: isRefreshing ? 0.5 : 1,
                  cursor: isRefreshing ? 'not-allowed' : 'pointer',
                  fontWeight: 500
                }}
                aria-label="Refresh data now"
              >
                {isRefreshing ? 'Refreshing…' : `Refresh (${countdown}s)`}
              </button>
            </div>
          </header>

          <main className="content-grid" role="main">
            {error && (
              <div className="error-banner" role="alert">
                <span>{error}</span>
                <button
                  onClick={() => loadData()}
                  style={{ fontSize: 11, color: 'inherit', textDecoration: 'underline', background: 'none', border: 'none', cursor: 'pointer' }}
                >
                  Retry
                </button>
              </div>
            )}

            <StatsBar data={data} lastUpdated={lastUpdated} isRefreshing={isRefreshing} />

            <div className="analytics-section">
               {data && data.anomaly_count > 0 ? (
                 <AnalyticsRow data={data} />
               ) : (
                 <div style={{ padding: 24, background: 'var(--bg-surface)', border: '1px solid var(--border)', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                   No anomalies detected. Analytics not available.
                 </div>
               )}

               <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', padding: 20 }}>
                 <div className="section-header" style={{ marginBottom: 16 }}>
                    <h2 className="section-title">
                      <span className="dot" style={{ background: 'var(--red)' }} />
                      Recent High Anomalies
                    </h2>
                 </div>
                 {anomalies.length > 0 ? (
                   <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                     {anomalies
                       .sort((a, b) => (b.anomaly_score ?? 0) - (a.anomaly_score ?? 0))
                       .slice(0, 5)
                       .map((a, i) => (
                         <div
                           key={i}
                           onClick={() => setSelected(a)}
                           style={{
                             border: '1px solid var(--border)',
                             padding: '10px 12px',
                             cursor: 'pointer',
                             background: 'var(--bg-elevated)',
                           }}
                           onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--red)'; }}
                           onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; }}
                         >
                           <div style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 500, marginBottom: 6, lineHeight: 1.4 }}>
                             {a.rule_description?.slice(0, 60)}
                             {(a.rule_description?.length ?? 0) > 60 ? '…' : ''}
                           </div>
                           <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                              <span style={{ color: 'var(--text-muted)' }}>{a.agent_name || '—'}</span>
                              <span style={{ color: 'var(--red)', fontWeight: 600 }}>{((a.anomaly_score ?? 0) * 100).toFixed(0)}%</span>
                           </div>
                         </div>
                       ))}
                   </div>
                 ) : (
                   <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '20px 0', textAlign: 'center' }}>
                     No recent anomalies.
                   </div>
                 )}
               </div>
            </div>

            {data && data.total_alerts > 0 && (
              <DistributionCharts alerts={data.alerts} />
            )}

            <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
              <div className="section-header" style={{ padding: '20px 20px 0 20px', borderBottom: 'none' }}>
                <h1 className="section-title">
                  <span className="dot" />
                  Alert Stream
                  {data && <span style={{ color: 'var(--text-muted)', fontWeight: 400, marginLeft: 6 }}>({data.total_alerts})</span>}
                </h1>
              </div>
              
              {!data && !error ? (
                <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
                   Loading data...
                </div>
              ) : data ? (
                <div style={{ padding: '0 20px 20px 20px' }}>
                  <AnomalyTable
                    alerts={data.alerts}
                    onSelectAlert={setSelected}
                    selectedId={selectedAlert?.doc_id ?? null}
                  />
                </div>
              ) : null}
            </div>

          </main>
        </div>
      </div>

      {selectedAlert && (
        <LogDetailDrawer
          alert={selectedAlert}
          onClose={() => setSelected(null)}
        />
      )}

      <Chatbot data={data} />
    </>
  );
}
