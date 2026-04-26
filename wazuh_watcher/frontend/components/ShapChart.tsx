'use client';
import { ShapValue } from '@/types';

interface Props {
  shapValues: ShapValue[];
  alertDesc?: string;
}

export default function ShapChart({ shapValues, alertDesc }: Props) {
  if (!shapValues || shapValues.length === 0) {
    return (
      <div className="shap-panel">
        <div className="section-header" style={{ marginBottom: 16 }}>
          <span className="section-title"><span className="dot" />SHAP Explanation</span>
        </div>
        <div className="shap-empty">
          <span style={{ fontSize: 32 }}></span>
          <span>Select an anomalous alert to see<br/>its SHAP feature contributions</span>
        </div>
      </div>
    );
  }

  const maxImpact = Math.max(...shapValues.map(s => s.abs_impact), 0.001);

  return (
    <div className="shap-panel">
      <div className="section-header" style={{ marginBottom: 4 }}>
        <span className="section-title"><span className="dot" />SHAP Explanation</span>
      </div>
      {alertDesc && (
        <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.5 }}>
          {alertDesc}
        </p>
      )}

      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 14, display: 'flex', gap: 16 }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{ display: 'inline-block', width: 10, height: 4, borderRadius: 0, background: 'var(--red)' }} />
          ↑ Pushes toward anomaly
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{ display: 'inline-block', width: 10, height: 4, borderRadius: 0, background: 'var(--green)' }} />
          ↓ Pushes toward normal
        </span>
      </div>

      <div className="shap-list">
        {shapValues.map((sv, i) => {
          const pct = (sv.abs_impact / maxImpact) * 100;
          const isUp = sv.shap_value > 0;
          return (
            <div key={i} className="shap-row">
              <div className="shap-feat-name" title={sv.feature}>{sv.feature}</div>
              <div className="shap-bar-wrap">
                <div className="shap-bar-bg">
                  <div
                    className={`shap-bar-fill ${isUp ? 'shap-bar-up' : 'shap-bar-down'}`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>
              <div
                className="shap-val"
                style={{ color: isUp ? 'var(--red)' : 'var(--green)' }}
              >
                {sv.shap_value > 0 ? '+' : ''}{sv.shap_value.toFixed(3)}
              </div>
              <div className={`shap-direction ${isUp ? 'up' : 'down'}`}>
                {isUp ? '↑ anomalous' : '↓ normal'}
              </div>
            </div>
          );
        })}
      </div>

      <div style={{
        marginTop: 16, paddingTop: 12,
        borderTop: '1px solid var(--border)',
        fontSize: 11, color: 'var(--text-muted)',
        display: 'flex', justifyContent: 'space-between',
      }}>
        <span>Top {shapValues.length} contributing features</span>
        <span>Alert value shown in alert detail →</span>
      </div>
    </div>
  );
}
