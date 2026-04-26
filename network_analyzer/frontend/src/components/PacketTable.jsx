import React, { useState, useMemo } from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';

const PROTOCOL_STYLES = {
    TCP:     { bg: '#1d3a5f', text: '#93c5fd', border: '#3b82f6' },
    UDP:     { bg: '#4a3419', text: '#fcd34d', border: '#f59e0b' },
    DNS:     { bg: '#14352a', text: '#86efac', border: '#22c55e' },
    TLS:     { bg: '#2e1a4e', text: '#c4b5fd', border: '#8b5cf6' },
    DATA:    { bg: '#4a1942', text: '#f9a8d4', border: '#ec4899' },
    ICMP:    { bg: '#4a1919', text: '#fca5a5', border: '#ef4444' },
    ARP:     { bg: '#0e3a3a', text: '#67e8f9', border: '#06b6d4' },
    DHCP:    { bg: '#4a2a0e', text: '#fdba74', border: '#f97316' },
    XMPP:    { bg: '#0e3a32', text: '#5eead4', border: '#14b8a6' },
    DISCARD: { bg: '#27272a', text: '#a1a1aa', border: '#6b7280' },
};

const KEY_PROTOCOLS = ['TCP', 'UDP', 'DNS', 'TLS', 'DATA'];
const PAGE_SIZE = 50;

const getProtocolStyle = (protocol) => {
    const style = PROTOCOL_STYLES[protocol] || { bg: '#334155', text: '#e2e8f0', border: '#64748b' };
    const isKey = KEY_PROTOCOLS.includes(protocol);
    return {
        padding: '2px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold',
        backgroundColor: style.bg, color: style.text, display: 'inline-block',
        border: isKey ? `1px solid ${style.border}` : 'none',
        boxShadow: isKey ? `0 0 6px ${style.border}40` : 'none',
    };
};

const cellStyle = {
    padding: '8px', borderBottom: '1px solid #334155', fontSize: '13px', color: '#cbd5e1'
};

const headerCellStyle = {
    ...cellStyle, color: '#94a3b8', fontWeight: '600', fontSize: '12px',
    textTransform: 'uppercase', letterSpacing: '0.05em'
};

const PacketTable = ({ packets, sniHostnames = {}, totalPackets, onLoadMore, hasMore, loadingMore }) => {
    const [page, setPage] = useState(0);

    // When packets prop changes (e.g. new data loaded), reset to first page
    const totalPages = Math.max(1, Math.ceil(packets.length / PAGE_SIZE));
    const safePage = Math.min(page, totalPages - 1);
    const pagePackets = useMemo(
        () => packets.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE),
        [packets, safePage]
    );

    const goToPage = (p) => setPage(Math.max(0, Math.min(p, totalPages - 1)));

    // When we're on the last page and more data is available, offer Load More
    const onLastPage = safePage === totalPages - 1;

    const btnBase = {
        display: 'flex', alignItems: 'center', gap: '4px', padding: '5px 12px',
        borderRadius: '6px', border: '1px solid #334155', backgroundColor: '#0f172a',
        color: '#94a3b8', cursor: 'pointer', fontSize: '13px', fontWeight: '600',
    };

    return (
        <div style={{ backgroundColor: '#1e293b', padding: '16px', borderRadius: '8px', boxShadow: '0 4px 6px rgba(0,0,0,0.3)' }}>
            {/* Header row */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 'bold', color: '#f1f5f9', margin: 0 }}>
                    Packets
                    {totalPackets != null && (
                        <span style={{ fontSize: '13px', color: '#64748b', fontWeight: 'normal', marginLeft: '10px' }}>
                            {packets.length.toLocaleString()} loaded / {totalPackets.toLocaleString()} total
                        </span>
                    )}
                    {totalPackets == null && packets.length > 0 && (
                        <span style={{ fontSize: '13px', color: '#64748b', fontWeight: 'normal', marginLeft: '10px' }}>
                            {packets.length.toLocaleString()} packets
                        </span>
                    )}
                </h3>

                {/* Pagination controls */}
                {packets.length > PAGE_SIZE && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <button style={{ ...btnBase, cursor: safePage === 0 ? 'not-allowed' : 'pointer', opacity: safePage === 0 ? 0.4 : 1 }}
                            onClick={() => goToPage(safePage - 1)} disabled={safePage === 0}>
                            <ChevronLeft size={16} />
                        </button>
                        <span style={{ fontSize: '13px', color: '#94a3b8' }}>
                            Page {safePage + 1} / {totalPages}
                        </span>
                        <button style={{ ...btnBase, cursor: safePage >= totalPages - 1 ? 'not-allowed' : 'pointer', opacity: safePage >= totalPages - 1 ? 0.4 : 1 }}
                            onClick={() => goToPage(safePage + 1)} disabled={safePage >= totalPages - 1}>
                            <ChevronRight size={16} />
                        </button>
                    </div>
                )}
            </div>

            <div style={{ overflowX: 'auto', maxHeight: '420px', overflowY: 'auto' }}>
                <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
                    <thead style={{ position: 'sticky', top: 0, backgroundColor: '#1e293b', zIndex: 1 }}>
                        <tr>
                            <th style={headerCellStyle}>Time</th>
                            <th style={headerCellStyle}>Source</th>
                            <th style={headerCellStyle}>Destination</th>
                            <th style={headerCellStyle}>Protocol</th>
                            <th style={headerCellStyle}>Info</th>
                        </tr>
                    </thead>
                    <tbody>
                        {pagePackets.length === 0 ? (
                            <tr>
                                <td colSpan={5} style={{ ...cellStyle, textAlign: 'center', color: '#64748b', padding: '32px' }}>
                                    No packets captured yet — click Start Capture
                                </td>
                            </tr>
                        ) : (
                            pagePackets.map((packet, index) => {
                                const isKey = KEY_PROTOCOLS.includes(packet.Protocol);
                                const rowBorderColor = isKey ? (PROTOCOL_STYLES[packet.Protocol]?.border || 'transparent') : 'transparent';
                                return (
                                    <tr key={safePage * PAGE_SIZE + index}
                                        style={{ transition: 'background-color 0.15s', borderLeft: isKey ? `2px solid ${rowBorderColor}` : '2px solid transparent' }}
                                        onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#334155'}
                                        onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
                                    >
                                        <td style={{ ...cellStyle, fontFamily: 'monospace', fontSize: '12px' }}>{packet.Timestamp}</td>
                                        <td style={cellStyle}>{packet['Source IP'] || '—'}</td>
                                        <td style={cellStyle}>
                                            {packet['Destination IP'] || '—'}
                                            {sniHostnames[packet['Destination IP']] && (
                                                <span style={{ color: '#60a5fa', fontSize: '11px', marginLeft: '6px' }}>
                                                    ({sniHostnames[packet['Destination IP']]})
                                                </span>
                                            )}
                                        </td>
                                        <td style={cellStyle}>
                                            <span style={getProtocolStyle(packet.Protocol)}>{packet.Protocol || 'Unknown'}</span>
                                        </td>
                                        <td style={{ ...cellStyle, maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                                            title={JSON.stringify(packet)}>
                                            {packet.SNI
                                                ? `SNI: ${packet.SNI}`
                                                : packet['Source Port'] ? `Port: ${packet['Source Port']} → ${packet['Destination Port']}` : '—'}
                                        </td>
                                    </tr>
                                );
                            })
                        )}
                    </tbody>
                </table>
            </div>

            {/* Load More from server (history view) */}
            {onLastPage && hasMore && onLoadMore && (
                <div style={{ textAlign: 'center', marginTop: '12px' }}>
                    <button onClick={onLoadMore} disabled={loadingMore} style={{
                        padding: '8px 24px', borderRadius: '8px', border: '1px solid #3b82f6',
                        backgroundColor: 'transparent', color: loadingMore ? '#64748b' : '#3b82f6',
                        cursor: loadingMore ? 'not-allowed' : 'pointer', fontWeight: 'bold', fontSize: '14px',
                        transition: 'all 0.2s',
                    }}>
                        {loadingMore ? '⏳ Loading...' : `⬇ Load next 200 packets`}
                    </button>
                    <p style={{ fontSize: '12px', color: '#475569', marginTop: '6px' }}>
                        Showing {packets.length.toLocaleString()} of {(totalPackets || 0).toLocaleString()} packets
                    </p>
                </div>
            )}
        </div>
    );
};

export default PacketTable;
