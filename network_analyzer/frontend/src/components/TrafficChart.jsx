import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const PROTOCOL_LINES = [
    { key: 'TCP', color: '#3b82f6', width: 2.5 },
    { key: 'UDP', color: '#f59e0b', width: 2.5 },
    { key: 'DNS', color: '#22c55e', width: 2.5 },
    { key: 'TLS', color: '#8b5cf6', width: 2.5 },
    { key: 'DATA', color: '#ec4899', width: 2.5 },
];

const TrafficChart = ({ data }) => {
    // Only show protocol lines that have at least one data point
    const activeProtocols = PROTOCOL_LINES.filter(p =>
        data.some(d => (d[p.key] || 0) > 0)
    );

    return (
        <div style={{ backgroundColor: '#1e293b', padding: '16px', borderRadius: '8px', boxShadow: '0 4px 6px rgba(0,0,0,0.3)' }}>
            <h3 style={{ fontSize: '1.125rem', fontWeight: 'bold', marginBottom: '16px', color: '#f1f5f9' }}>
                Protocol Traffic Over Time
            </h3>
            <div style={{ height: '280px' }}>
                <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={data}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                        <XAxis dataKey="time" stroke="#9ca3af" fontSize={11} />
                        <YAxis stroke="#9ca3af" fontSize={11} allowDecimals={false} />
                        <Tooltip
                            contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '8px', color: '#fff', fontSize: '13px' }}
                            labelStyle={{ color: '#94a3b8', marginBottom: '4px' }}
                        />
                        <Legend
                            wrapperStyle={{ fontSize: '12px', paddingTop: '8px' }}
                            iconType="circle"
                        />
                        {/* Total as a faint dashed reference line */}
                        <Line
                            type="monotone" dataKey="total" name="Total"
                            stroke="#475569" strokeWidth={1} strokeDasharray="4 4"
                            dot={false} isAnimationActive={false}
                        />
                        {/* Per-protocol lines */}
                        {activeProtocols.map(proto => (
                            <Line
                                key={proto.key}
                                type="monotone"
                                dataKey={proto.key}
                                name={proto.key}
                                stroke={proto.color}
                                strokeWidth={proto.width}
                                dot={false}
                                isAnimationActive={false}
                                connectNulls={false}
                            />
                        ))}
                    </LineChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
};

export default TrafficChart;
