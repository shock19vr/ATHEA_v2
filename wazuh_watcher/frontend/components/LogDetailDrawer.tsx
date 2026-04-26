'use client';
import { Alert } from '@/types';

interface Props {
  alert: Alert;
  onClose: () => void;
}

function Field({ label, value, full }: { label: string; value?: string | number | null; full?: boolean }) {
  return (
    <div className={`drawer-field ${full ? 'full' : ''}`}>
      <div className="drawer-field-label">{label}</div>
      <div className="drawer-field-value">{value ?? '—'}</div>
    </div>
  );
}

function getLevelClass(l: number) {
  if (l >= 12) return 'badge-high';
  if (l >= 8)  return 'badge-medium';
  if (l >= 5)  return 'badge-low';
  return 'badge-normal';
}

export default function LogDetailDrawer({ alert, onClose }: Props) {
  const isAnom = alert.anomaly === 1;
  const scoreColor = isAnom
    ? alert.anomaly_score! >= 0.7 ? 'var(--red)'
    : alert.anomaly_score! >= 0.4 ? 'var(--orange)'
    : 'var(--text-muted)'
    : 'var(--green)';

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Alert Details">

        <div className="drawer-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <span className={`badge ${getLevelClass(alert.rule_level)}`}>
                Level {alert.rule_level}
              </span>
              {isAnom && alert.confidence && (
                <span className={`badge badge-${alert.confidence.toLowerCase()}`}>
                  {alert.confidence} Confidence
                </span>
              )}
              {alert.mitre_stage && (
                <span className="badge badge-mitre">{alert.mitre_stage}</span>
              )}
            </div>
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', lineHeight: 1.4, maxWidth: 420 }}>
              {alert.rule_description || 'No description'}
            </div>
            <div style={{ marginTop: 4, fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {alert.doc_id}
            </div>
          </div>
          <button className="drawer-close" onClick={onClose} aria-label="Close">✕</button>
        </div>

        <div className="drawer-body">

          {isAnom && (
            <div style={{
              padding: '12px 16px', borderRadius: 'var(--radius)',
              background: 'var(--red-bg)',
              border: '1px solid var(--red-border)',
              marginBottom: 20, display: 'flex', alignItems: 'center', gap: 12,
            }}>
              <span style={{ fontSize: 22 }}></span>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--red)', marginBottom: 2 }}>
                  Anomaly Detected
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  Score: <span style={{ color: scoreColor, fontFamily: 'var(--font-mono)' }}>
                    {((alert.anomaly_score ?? 0) * 100).toFixed(1)}%
                  </span>
                  {alert.cluster_id !== null && ` · Cluster ${alert.cluster_id}`}
                  {alert.mitre_stage && ` · ${alert.mitre_stage}`}
                </div>
              </div>
            </div>
          )}


          <div className="drawer-section">
            <div className="drawer-section-title">Identity</div>
            <div className="drawer-grid">
              <Field label="Timestamp" value={alert.timestamp ? new Date(alert.timestamp).toLocaleString() : undefined} full />
              <Field label="Agent Name"  value={alert.agent_name  || alert.computer} />
              <Field label="Agent IP"    value={alert.agent_ip} />
              <Field label="Agent ID"    value={alert.agent_id} />
              <Field label="Manager"     value={alert.manager_name} />
            </div>
          </div>


          <div className="drawer-section">
            <div className="drawer-section-title">Rule & MITRE ATT&CK</div>
            <div className="drawer-grid">
              <Field label="Rule ID"    value={alert.rule_id} />
              <Field label="Rule Level" value={alert.rule_level} />
              <Field label="Rule Groups" value={alert.rule_groups?.join(', ')} full />
              <Field label="MITRE IDs"       value={alert.mitre_ids?.join(', ')}       />
              <Field label="MITRE Tactics"   value={alert.mitre_tactics?.join(', ')}   />
              <Field label="MITRE Techniques" value={alert.mitre_techniques?.join(', ')} full />
            </div>
          </div>


          {(alert.event_id || alert.channel || alert.provider_name) && (
            <div className="drawer-section">
              <div className="drawer-section-title">Windows Event</div>
              <div className="drawer-grid">
                <Field label="Event ID"     value={alert.event_id} />
                <Field label="Process ID"   value={alert.process_id} />
                <Field label="Channel"      value={alert.channel} />
                <Field label="Provider"     value={alert.provider_name} />
                <Field label="Computer"     value={alert.computer} />
              </div>
            </div>
          )}


          {(alert.target_user || alert.subject_user) && (
            <div className="drawer-section">
              <div className="drawer-section-title">User Context</div>
              <div className="drawer-grid">
                <Field label="Target User"  value={alert.target_user} />
                <Field label="Subject User" value={alert.subject_user} />
              </div>
            </div>
          )}


          {(alert.command_line || alert.src_ip) && (
            <div className="drawer-section">
              <div className="drawer-section-title">Process & Network</div>
              <div className="drawer-grid">
                <Field label="Command Line"     value={alert.command_line}  full />
                <Field label="Parent Command"   value={alert.parent_cmd}    full />
                <Field label="Source IP"   value={alert.src_ip} />
                <Field label="Source Port" value={alert.src_port} />
              </div>
            </div>
          )}


          {alert.shap_values?.length > 0 && (
            <div className="drawer-section">
              <div className="drawer-section-title">SHAP Feature Contributions</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {alert.shap_values.map((sv, i) => (
                  <div key={i} style={{
                    background: 'var(--bg-elevated)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '8px 12px',
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  }}>
                    <div>
                      <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', marginBottom: 2 }}>
                        {sv.feature}
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        value: <code style={{ color: 'var(--cyan)' }}>{sv.alert_value}</code>
                      </div>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', fontWeight: 600, color: sv.shap_value > 0 ? 'var(--red)' : 'var(--green)' }}>
                        {sv.shap_value > 0 ? '+' : ''}{sv.shap_value.toFixed(4)}
                      </div>
                      <div style={{ fontSize: 10, color: sv.shap_value > 0 ? 'var(--red)' : 'var(--green)' }}>
                        {sv.direction}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}


          {alert.full_log && (
            <div className="drawer-section">
              <div className="drawer-section-title">Raw Log</div>
              <pre className="log-pre">{alert.full_log}</pre>
            </div>
          )}


          <div className="drawer-section">
            <div className="drawer-section-title">Source</div>
            <div className="drawer-grid">
              <Field label="Location"    value={alert.location} />
              <Field label="Decoder"     value={alert.decoder_name} />
            </div>
          </div>
        </div>
      </aside>
    </>
  );
}
