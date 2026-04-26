'use client';
import { Alert } from '@/types';

interface Props { alert: Alert; onClick: () => void; isSelected: boolean; }

function getLevelClass(level: number) {
  if (level >= 12) return 'l-crit';
  if (level >= 8)  return 'l-high';
  if (level >= 5)  return 'l-med';
  return 'l-low';
}

function getScoreColor(score: number) {
  if (score >= 0.7) return 'var(--red)';
  if (score >= 0.4) return 'var(--orange)';
  return 'var(--text-muted)';
}

function timeAgo(ts: string) {
  const diff = Date.now() - new Date(ts).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 2)  return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function AlertRow({ alert, onClick, isSelected }: Props) {
  const isAnom = alert.anomaly === 1;
  const score  = alert.anomaly_score ?? 0;
  const isHighConf = isAnom && alert.confidence === 'High';

  return (
    <tr
      className={`${isAnom ? 'is-anomaly' : ''} ${isHighConf ? 'high-conf' : ''} ${isSelected ? 'selected' : ''}`}
      onClick={onClick}
      title={alert.rule_description}
    >

      <td className="mono text-sm" style={{ color: 'var(--text-muted)', minWidth: 90 }}>
        {alert.timestamp ? timeAgo(alert.timestamp) : '—'}
      </td>


      <td style={{ minWidth: 50 }}>
        <span className={`level-dot ${getLevelClass(alert.rule_level)}`}>
          {alert.rule_level}
        </span>
      </td>


      <td className="primary truncate" style={{ maxWidth: 280 }}>
        {alert.rule_description || '—'}
      </td>


      <td className="mono text-sm truncate" style={{ maxWidth: 140 }}>
        {alert.agent_name || alert.computer || '—'}
      </td>


      <td>
        {alert.event_id
          ? <code>{alert.event_id}</code>
          : <span style={{ color: 'var(--text-muted)' }}>—</span>
        }
      </td>


      <td style={{ minWidth: 130 }}>
        {alert.mitre_stage
          ? <span className="badge badge-mitre">{alert.mitre_stage}</span>
          : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
        }
      </td>


      <td style={{ minWidth: 120 }}>
        {isAnom ? (
          <div className="score-bar-wrap">
            <div className="score-bar">
              <div
                className="score-bar-fill"
                style={{ width: `${score * 100}%`, background: getScoreColor(score) }}
              />
            </div>
            <span className="score-text">{(score * 100).toFixed(0)}%</span>
          </div>
        ) : (
          <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>normal</span>
        )}
      </td>


      <td style={{ minWidth: 80 }}>
        {isAnom && alert.confidence ? (
          <span className={`badge badge-${alert.confidence.toLowerCase()}`}>
            {alert.confidence}
          </span>
        ) : isAnom ? (
          <span className="badge badge-low">—</span>
        ) : (
          <span className="badge badge-normal">normal</span>
        )}
      </td>


      <td style={{ minWidth: 60 }}>
        {alert.cluster_id !== null && alert.cluster_id !== undefined && isAnom
          ? <span className="badge badge-cluster">C{alert.cluster_id}</span>
          : <span style={{ color: 'var(--text-muted)' }}>—</span>
        }
      </td>
    </tr>
  );
}
