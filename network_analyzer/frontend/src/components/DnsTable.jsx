import React from 'react';

// DNS query type numbers to human-readable names
const QUERY_TYPES = {
    '1': 'A', '2': 'NS', '5': 'CNAME', '6': 'SOA',
    '12': 'PTR', '15': 'MX', '16': 'TXT', '28': 'AAAA',
    '33': 'SRV', '255': 'ANY', '65': 'HTTPS',
};

const cellStyle = {
    padding: '8px 10px',
    borderBottom: '1px solid #334155',
    fontSize: '13px',
    color: '#cbd5e1',
};

const headerCellStyle = {
    ...cellStyle,
    color: '#94a3b8',
    fontWeight: '600',
    fontSize: '12px',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    position: 'sticky',
    top: 0,
    backgroundColor: '#1e293b',
    zIndex: 1,
};

const DnsTable = ({ queries }) => {
    return (
        <div style={{
            backgroundColor: '#1e293b',
            padding: '16px',
            borderRadius: '8px',
            boxShadow: '0 4px 6px rgba(0,0,0,0.3)',
            marginBottom: '24px',
        }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 'bold', color: '#f1f5f9' }}>
                    🌐 DNS Queries
                </h3>
                <span style={{ fontSize: '12px', color: '#64748b' }}>
                    {queries.length} {queries.length === 1 ? 'query' : 'queries'} captured
                </span>
            </div>

            <div style={{ overflowX: 'auto', maxHeight: '320px', overflowY: 'auto' }}>
                <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
                    <thead>
                        <tr>
                            <th style={headerCellStyle}>Time</th>
                            <th style={headerCellStyle}>Domain</th>
                            <th style={headerCellStyle}>Type</th>
                            <th style={headerCellStyle}>Resolved IP</th>
                            <th style={headerCellStyle}>Answers</th>
                            <th style={headerCellStyle}>Client</th>
                        </tr>
                    </thead>
                    <tbody>
                        {queries.length === 0 ? (
                            <tr>
                                <td colSpan={6} style={{ ...cellStyle, textAlign: 'center', color: '#64748b', padding: '32px' }}>
                                    No DNS queries captured yet — start a capture to see DNS activity
                                </td>
                            </tr>
                        ) : (
                            queries.map((q, i) => {
                                const typeNum = q['Query Type'] || '';
                                const typeName = QUERY_TYPES[typeNum] || typeNum;
                                const time = q.Timestamp ? q.Timestamp.split(' ').pop()?.substring(0, 8) : '—';

                                return (
                                    <tr key={i}
                                        style={{ transition: 'background-color 0.2s' }}
                                        onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#334155'}
                                        onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                                    >
                                        <td style={{ ...cellStyle, fontFamily: 'monospace', fontSize: '12px', whiteSpace: 'nowrap' }}>
                                            {time}
                                        </td>
                                        <td style={{ ...cellStyle, fontWeight: '500', color: '#93c5fd', maxWidth: '260px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                                            title={q['Query Name']}>
                                            {q['Query Name'] || '—'}
                                        </td>
                                        <td style={cellStyle}>
                                            <span style={{
                                                padding: '2px 6px',
                                                borderRadius: '4px',
                                                fontSize: '11px',
                                                fontWeight: 'bold',
                                                backgroundColor: typeName === 'A' ? '#14352a' : typeName === 'AAAA' ? '#1d3a5f' : '#2e1a4e',
                                                color: typeName === 'A' ? '#86efac' : typeName === 'AAAA' ? '#93c5fd' : '#c4b5fd',
                                            }}>
                                                {typeName}
                                            </span>
                                        </td>
                                        <td style={{ ...cellStyle, fontFamily: 'monospace', fontSize: '12px', color: q['Resolved IP'] ? '#4ade80' : '#64748b' }}>
                                            {q['Resolved IP'] || '—'}
                                        </td>
                                        <td style={{ ...cellStyle, textAlign: 'center' }}>
                                            {q['Answer Count'] || '0'}
                                        </td>
                                        <td style={{ ...cellStyle, fontFamily: 'monospace', fontSize: '12px' }}>
                                            {q['Source IP'] || '—'}
                                        </td>
                                    </tr>
                                );
                            })
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default DnsTable;
