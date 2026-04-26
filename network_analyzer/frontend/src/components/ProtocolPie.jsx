import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

const PROTOCOL_COLORS = {
    TCP: '#3b82f6',
    UDP: '#f59e0b',
    DNS: '#22c55e',
    TLS: '#8b5cf6',
    DATA: '#ec4899',
    ICMP: '#ef4444',
    ARP: '#06b6d4',
    DHCP: '#f97316',
    XMPP: '#14b8a6',
    DISCARD: '#6b7280',
    Unknown: '#64748b',
};

const getColor = (name) => PROTOCOL_COLORS[name] || '#64748b';

const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
        const d = payload[0].payload;
        return (
            <div style={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '8px', padding: '8px 12px' }}>
                <div style={{ color: getColor(d.name), fontWeight: 'bold', fontSize: '13px' }}>{d.name}</div>
                <div style={{ color: '#94a3b8', fontSize: '12px' }}>{d.value} packets ({d.percent}%)</div>
            </div>
        );
    }
    return null;
};

const ProtocolPie = ({ data }) => {
    const total = data.reduce((sum, d) => sum + d.value, 0);

    // Add percentage, sort by value descending
    const sorted = [...data]
        .map(d => ({ ...d, percent: total > 0 ? ((d.value / total) * 100).toFixed(1) : '0' }))
        .sort((a, b) => b.value - a.value);

    return (
        <div style={{ backgroundColor: '#1e293b', padding: '16px', borderRadius: '8px', boxShadow: '0 4px 6px rgba(0,0,0,0.3)' }}>
            <h3 style={{ fontSize: '1.125rem', fontWeight: 'bold', marginBottom: '12px', color: '#f1f5f9' }}>Protocol Distribution</h3>

            {sorted.length === 0 ? (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '240px', color: '#64748b', fontSize: '14px' }}>
                    No data yet — start a capture
                </div>
            ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    {/* Donut chart */}
                    <div style={{ width: '140px', height: '140px', flexShrink: 0 }}>
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <Pie
                                    data={sorted}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={40}
                                    outerRadius={65}
                                    paddingAngle={2}
                                    dataKey="value"
                                    isAnimationActive={false}
                                    stroke="none"
                                >
                                    {sorted.map((entry, i) => (
                                        <Cell key={i} fill={getColor(entry.name)} />
                                    ))}
                                </Pie>
                                <Tooltip content={<CustomTooltip />} />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>

                    {/* Legend list */}
                    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '4px', overflow: 'auto', maxHeight: '180px' }}>
                        {sorted.map((item, i) => (
                            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px' }}>
                                <span style={{
                                    width: '8px', height: '8px', borderRadius: '2px', flexShrink: 0,
                                    backgroundColor: getColor(item.name),
                                }}></span>
                                <span style={{ color: '#e2e8f0', flex: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                    {item.name}
                                </span>
                                <span style={{ color: '#94a3b8', fontFamily: 'monospace', fontSize: '11px' }}>
                                    {item.percent}%
                                </span>
                                <span style={{ color: '#64748b', fontFamily: 'monospace', fontSize: '11px', minWidth: '30px', textAlign: 'right' }}>
                                    {item.value}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
};

export default ProtocolPie;
