import React, { useState, useEffect, useRef, useCallback } from 'react';
import TrafficChart from './TrafficChart';
import ProtocolPie from './ProtocolPie';
import PacketTable from './PacketTable';
import DnsTable from './DnsTable';
import GeoMap from './GeoMap';
import HistoryModal from './HistoryModal';
import { Play, Square, Activity, Shield, Save, Clock, Trash2 } from 'lucide-react';

const WS_URL = 'ws://localhost:8000/ws';
const API_URL = 'http://localhost:8000/api';

const KEY_PROTOCOLS = ['TCP', 'UDP', 'DNS', 'TLS', 'DATA'];

const Dashboard = () => {
    const [packets, setPackets] = useState([]);
    const [isCapturing, setIsCapturing] = useState(false);
    const [stats, setStats] = useState({ total: 0, protocols: {} });
    const [chartData, setChartData] = useState([]);
    const [dnsQueries, setDnsQueries] = useState([]);
    const [wsStatus, setWsStatus] = useState('connecting');
    const [error, setError] = useState(null);
    const ws = useRef(null);
    const reconnectTimer = useRef(null);

    const [interfaceName, setInterfaceName] = useState('');
    const [interfaces, setInterfaces] = useState([]);
    const [loadingInterfaces, setLoadingInterfaces] = useState(true);
    const [showHistoryModal, setShowHistoryModal] = useState(false);
    const [saving, setSaving] = useState(false);

    // Pagination state for history mode (daily log loading)
    const [historyMeta, setHistoryMeta] = useState(null);
    // { date, totalPackets, hasMore, loadingMore }

    // Check if selected interface is internet-facing (carries public IPs)
    const isInternetFacing = interfaces.find(i => i.name === interfaceName)?.internet_facing ?? false;

    // IP Reputation tracking
    const [ipReputation, setIpReputation] = useState({});  // ip -> result
    const checkedIps = useRef(new Set());                   // IPs already queued
    const checkQueue = useRef([]);                          // pending IPs
    const checkingRef = useRef(false);

    // IP → hostname mapping (from TLS SNI)
    const [sniHostnames, setSniHostnames] = useState({});  // ip -> hostname

    const isPrivateIp = useCallback((ip) => {
        if (!ip) return true;
        return ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.') ||
            ip.startsWith('172.16.') || ip.startsWith('172.17.') || ip.startsWith('172.18.') ||
            ip.startsWith('172.19.') || ip.startsWith('172.2') || ip.startsWith('172.30.') ||
            ip.startsWith('172.31.') || ip === '::1' || ip.startsWith('fe80') || ip.startsWith('0.') || ip.startsWith('169.254.');
    }, []);

    const processCheckQueue = useCallback(async () => {
        if (checkingRef.current || checkQueue.current.length === 0) return;
        checkingRef.current = true;
        while (checkQueue.current.length > 0) {
            const ip = checkQueue.current.shift();
            try {
                const res = await fetch(`${API_URL}/check_ip?ip=${encodeURIComponent(ip)}`);
                if (!res.ok) { console.warn('IP check HTTP error', ip, res.status); continue; }
                const data = await res.json();
                if (!data.skipped && data.ip) {
                    setIpReputation(prev => ({ ...prev, [ip]: data }));
                }
            } catch (e) { console.error('IP check failed', ip, e); }
            // Small delay between checks to be polite to the API
            await new Promise(r => setTimeout(r, 300));
        }
        checkingRef.current = false;
    }, []);

    const queueIpCheck = useCallback((ip) => {
        if (!ip || ip === 'N/A') return;
        if (checkedIps.current.has(ip)) return;
        if (checkedIps.current.size >= 50) return;  // cap per session
        if (isPrivateIp(ip)) {
            return;
        }
        console.log('[reputation] Queuing IP for check:', ip);
        checkedIps.current.add(ip);
        checkQueue.current.push(ip);
        processCheckQueue();
    }, [isPrivateIp, processCheckQueue]);

    const handlePacket = useCallback((packet) => {
        try {
            setPackets(prev => {
                const newPackets = [packet, ...prev];
                if (newPackets.length > 50) return newPackets.slice(0, 50);
                return newPackets;
            });

            // Track DNS queries separately
            if (packet.Protocol === 'DNS' && packet['Query Name']) {
                setDnsQueries(prev => {
                    const updated = [packet, ...prev];
                    if (updated.length > 100) return updated.slice(0, 100);
                    return updated;
                });
            }

            const protocol = packet.Protocol || 'Unknown';

            setStats(prev => {
                const newProtocols = { ...prev.protocols };
                newProtocols[protocol] = (newProtocols[protocol] || 0) + 1;
                return { total: prev.total + 1, protocols: newProtocols };
            });

            // Per-protocol traffic over time
            setChartData(prev => {
                const now = new Date().toLocaleTimeString();
                const newData = [...prev];
                if (newData.length > 0 && newData[newData.length - 1].time === now) {
                    const last = { ...newData[newData.length - 1] };
                    last[protocol] = (last[protocol] || 0) + 1;
                    last.total = (last.total || 0) + 1;
                    newData[newData.length - 1] = last;
                    return newData;
                }
                const newPoint = { time: now, total: 1, [protocol]: 1 };
                const result = [...newData, newPoint];
                if (result.length > 30) return result.slice(-30);
                return result;
            });

            // Track TLS SNI hostname → destination IP mapping
            if (packet.Protocol === 'TLS' && packet.SNI) {
                const dstIp = packet['Destination IP'];
                if (dstIp && dstIp !== 'N/A') {
                    setSniHostnames(prev => {
                        if (prev[dstIp] === packet.SNI) return prev;
                        return { ...prev, [dstIp]: packet.SNI };
                    });
                }
            }

            // Queue IPs for reputation check
            const srcIp = packet['Source IP'];
            const dstIp = packet['Destination IP'];
            if (srcIp) queueIpCheck(srcIp);
            if (dstIp) queueIpCheck(dstIp);
        } catch (err) {
            console.error("handlePacket error:", err);
        }
    }, [queueIpCheck]);

    const connectWebSocket = useCallback(() => {
        if (ws.current) {
            try { ws.current.close(); } catch (e) { }
        }
        try {
            const socket = new WebSocket(WS_URL);
            socket.onopen = () => { setWsStatus('connected'); setError(null); };
            socket.onmessage = (event) => {
                try {
                    const packet = JSON.parse(event.data);
                    handlePacket(packet);
                } catch (e) { console.error("Error parsing packet", e); }
            };
            socket.onerror = () => setWsStatus('error');
            socket.onclose = () => {
                setWsStatus('disconnected');
                reconnectTimer.current = setTimeout(() => connectWebSocket(), 3000);
            };
            ws.current = socket;
        } catch (e) {
            setWsStatus('error');
            setError('Cannot connect to backend');
        }
    }, [handlePacket]);

    useEffect(() => {
        connectWebSocket();
        return () => {
            if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
            if (ws.current) { try { ws.current.close(); } catch (e) { } }
        };
    }, [connectWebSocket]);

    useEffect(() => {
        fetch(`${API_URL}/status`).then(r => r.json()).then(d => { if (d.running) setIsCapturing(true); }).catch(() => { });

        // Fetch available network interfaces
        fetch(`${API_URL}/interfaces`)
            .then(r => r.json())
            .then(data => {
                const ifaces = data.interfaces || [];
                setInterfaces(ifaces);
                // Default to first "up" interface, or first overall
                const upIface = ifaces.find(i => i.is_up);
                if (upIface) setInterfaceName(upIface.name);
                else if (ifaces.length > 0) setInterfaceName(ifaces[0].name);
            })
            .catch(() => setError('Failed to load network interfaces'))
            .finally(() => setLoadingInterfaces(false));
    }, []);

    const toggleCapture = async () => {
        try {
            setError(null);
            if (isCapturing) {
                await fetch(`${API_URL}/stop_capture`, { method: 'POST' });
                setIsCapturing(false);
            } else {
                const res = await fetch(`${API_URL}/start_capture`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ interface: interfaceName })
                });
                const data = await res.json();
                if (data.status === 'error') setError(data.message);
                else setIsCapturing(true);
            }
        } catch (err) {
            setError("Failed to communicate with backend.");
        }
    };

    const handleSaveSnapshot = async () => {
        if (packets.length === 0) {
            alert("No packets to save! Let the capture run for a bit first.");
            return;
        }
        
        const snapshotName = prompt("Enter a name for this snapshot (visible portion of analysis):");
        if (snapshotName === null) return; // cancelled
        
        try {
            setSaving(true);
            const payload = {
                name: snapshotName || `Snapshot ${new Date().toLocaleString()}`,
                packets,
                dnsQueries,
                chartData,
                stats,
                ipReputation,
                sniHostnames
            };
            
            const res = await fetch(`${API_URL}/scans`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            
            if (!res.ok) throw new Error("Failed to save snapshot");
            alert("Snapshot saved! Find it under History → Snapshots tab.");
        } catch (err) {
            alert(`Error saving snapshot: ${err.message}`);
        } finally {
            setSaving(false);
        }
    };

    const handleLoadSession = async (sessionData) => {
        // Stop current capture if running
        if (isCapturing) {
            try {
                await fetch(`${API_URL}/stop_capture`, { method: 'POST' });
                setIsCapturing(false);
            } catch (e) {}
        }

        // Check if this came from a daily log (has date key) or a snapshot
        if (sessionData._dailyDate) {
            // Daily log: load first 200 packets (for table) + full meta in parallel
            const date = sessionData._dailyDate;
            try {
                setHistoryMeta({ date, totalPackets: 0, hasMore: false, loadingMore: true });
                setIpReputation({});
                setSniHostnames({});

                const [pageRes, metaRes] = await Promise.all([
                    fetch(`${API_URL}/daily/${date}?skip=0&limit=200`),
                    fetch(`${API_URL}/daily/${date}/meta`),
                ]);

                const [pageData, metaData] = await Promise.all([
                    pageRes.json(),
                    metaRes.json(),
                ]);

                // Packet table — first 200 only (paginated)
                setPackets(pageData.packets || []);
                setChartData(pageData.chartData || []);
                setStats(pageData.stats || { total: 0, protocols: {} });
                setHistoryMeta({
                    date,
                    totalPackets: pageData.total_packets || 0,
                    hasMore: pageData.has_more || false,
                    loadingMore: false,
                    currentSkip: pageData.limit || 200,
                });

                // DNS table — ALL queries from the full day via aggregation
                setDnsQueries(metaData.dns_queries || []);

                // IP reputation — queue ALL unique IPs from the full day
                const allIps = metaData.unique_ips || [];
                allIps.forEach(ip => queueIpCheck(ip));

            } catch (e) {
                setError('Failed to load daily log data');
                setHistoryMeta(null);
            }

        } else {
            // Snapshot: all data is inline, load directly
            setHistoryMeta(null);
            setPackets(sessionData.packets || []);
            setDnsQueries(sessionData.dnsQueries || []);
            setChartData(sessionData.chartData || []);
            setStats(sessionData.stats || { total: 0, protocols: {} });
            setIpReputation(sessionData.ipReputation || {});
            setSniHostnames(sessionData.sniHostnames || {});
            // Queue any IPs not already in the snapshot's reputation data
            const knownIps = new Set(Object.keys(sessionData.ipReputation || {}));
            (sessionData.packets || []).forEach(p => {
                if (p['Source IP'] && !knownIps.has(p['Source IP'])) queueIpCheck(p['Source IP']);
                if (p['Destination IP'] && !knownIps.has(p['Destination IP'])) queueIpCheck(p['Destination IP']);
            });
        }
    };

    const handleClearScreen = () => {
        setPackets([]);
        setDnsQueries([]);
        setChartData([]);
        setStats({ total: 0, protocols: {} });
        setIpReputation({});
        setSniHostnames({});
        setHistoryMeta(null);
        checkedIps.current.clear();
        checkQueue.current = [];
    };

    const handleLoadMore = async () => {
        if (!historyMeta || historyMeta.loadingMore || !historyMeta.hasMore) return;
        const { date, currentSkip } = historyMeta;
        setHistoryMeta(m => ({ ...m, loadingMore: true }));
        try {
            const res = await fetch(`${API_URL}/daily/${date}?skip=${currentSkip}&limit=200`);
            const data = await res.json();
            const newPackets = data.packets || [];
            setPackets(prev => [...prev, ...newPackets]);

            // Merge any new DNS queries
            const newDns = newPackets.filter(p => p.Protocol === 'DNS' && p['Query Name']);
            if (newDns.length > 0) {
                setDnsQueries(prev => [...prev, ...newDns]);
            }

            // Queue new IPs for reputation checks
            newPackets.forEach(p => {
                if (p['Source IP']) queueIpCheck(p['Source IP']);
                if (p['Destination IP']) queueIpCheck(p['Destination IP']);
            });

            setHistoryMeta(m => ({
                ...m,
                loadingMore: false,
                hasMore: data.has_more || false,
                currentSkip: currentSkip + newPackets.length,
            }));
        } catch (e) {
            setHistoryMeta(m => ({ ...m, loadingMore: false }));
        }
    };

    const protocolData = Object.entries(stats.protocols).map(([name, value]) => ({ name, value }));
    const statusBgColor = wsStatus === 'connected' ? '#22c55e' : wsStatus === 'connecting' ? '#eab308' : '#ef4444';

    return (
        <div style={{ padding: '24px', maxWidth: '1280px', margin: '0 auto' }}>
            <HistoryModal 
                isOpen={showHistoryModal} 
                onClose={() => setShowHistoryModal(false)}
                onLoadSession={handleLoadSession}
            />
            {/* Header */}
            <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', flexWrap: 'wrap', gap: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <Activity style={{ width: '32px', height: '32px', color: '#60a5fa' }} />
                    <h1 style={{ fontSize: '1.875rem', fontWeight: 'bold', background: 'linear-gradient(to right, #60a5fa, #a78bfa)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                        Network Analyzer
                    </h1>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', display: 'inline-block', backgroundColor: statusBgColor }}></span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <select
                        value={interfaceName}
                        onChange={(e) => setInterfaceName(e.target.value)}
                        disabled={loadingInterfaces || isCapturing}
                        style={{
                            backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px',
                            padding: '8px 16px', color: 'white', outline: 'none', fontSize: '14px',
                            cursor: loadingInterfaces ? 'wait' : 'pointer', minWidth: '200px',
                            appearance: 'none', WebkitAppearance: 'none',
                            backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E")`,
                            backgroundRepeat: 'no-repeat', backgroundPosition: 'right 12px center',
                            paddingRight: '36px'
                        }}
                    >
                        {loadingInterfaces ? (
                            <option>Loading interfaces...</option>
                        ) : interfaces.length === 0 ? (
                            <option>No interfaces found</option>
                        ) : (
                            interfaces.map(iface => (
                                <option key={iface.name} value={iface.name}>
                                    {iface.name}{iface.addresses.length > 0 ? ` (${iface.addresses[0]})` : ''}{iface.is_up ? '' : ' [down]'}
                                </option>
                            ))
                        )}
                    </select>
                    <button onClick={toggleCapture} style={{
                        display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 24px', borderRadius: '9999px', fontWeight: 'bold',
                        border: 'none', cursor: 'pointer', color: 'white', transition: 'all 0.3s',
                        backgroundColor: isCapturing ? '#ef4444' : '#22c55e',
                        boxShadow: isCapturing ? '0 0 20px rgba(239,68,68,0.5)' : '0 0 20px rgba(34,197,94,0.5)'
                    }}>
                        {isCapturing ? <><Square size={20} /> Stop Capture</> : <><Play size={20} /> Start Capture</>}
                    </button>
                    <div style={{ width: '1px', height: '32px', backgroundColor: '#334155', margin: '0 8px' }}></div>
                    <button onClick={handleSaveSnapshot} disabled={saving || packets.length === 0} style={{
                        display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 16px', borderRadius: '8px', fontWeight: 'bold',
                        border: '1px solid #3b82f6', cursor: (saving || packets.length === 0) ? 'not-allowed' : 'pointer', 
                        color: (saving || packets.length === 0) ? '#64748b' : '#3b82f6', transition: 'all 0.3s',
                        backgroundColor: 'transparent'
                    }}>
                        <Save size={20} /> {saving ? 'Saving...' : 'Save Snapshot'}
                    </button>
                    <button onClick={() => setShowHistoryModal(true)} style={{
                        display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 16px', borderRadius: '8px', fontWeight: 'bold',
                        border: '1px solid #a78bfa', cursor: 'pointer', color: '#a78bfa', transition: 'all 0.3s',
                        backgroundColor: 'transparent'
                    }}>
                        <Clock size={20} /> History
                    </button>
                    <button onClick={handleClearScreen} title="Clear display memory (data is safe in DB)" style={{
                        display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 16px', borderRadius: '8px', fontWeight: 'bold',
                        border: '1px solid #f59e0b', cursor: 'pointer', color: '#f59e0b', transition: 'all 0.3s',
                        backgroundColor: 'transparent'
                    }}>
                        <Trash2 size={18} /> Clear Screen
                    </button>
                </div>
            </header>

            {error && (
                <div style={{ padding: '12px 16px', marginBottom: '16px', backgroundColor: '#7f1d1d', borderRadius: '8px', color: '#fca5a5', fontSize: '14px' }}>
                    ⚠️ {error}
                </div>
            )}

            {/* Compact Stats */}
            <div style={{ display: 'flex', gap: '12px', marginBottom: '24px', flexWrap: 'wrap', alignItems: 'center' }}>
                <div style={{ backgroundColor: '#1e293b', padding: '12px 20px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase' }}>Total Packets</span>
                    <span style={{ fontSize: '20px', fontWeight: 'bold', color: '#60a5fa' }}>{stats.total}</span>
                </div>
                <div style={{ backgroundColor: '#1e293b', padding: '12px 20px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase' }}>Status</span>
                    <span style={{ fontSize: '14px', fontWeight: 'bold', color: isCapturing ? '#4ade80' : '#94a3b8' }}>
                        {isCapturing ? '● Capturing' : '○ Idle'}
                    </span>
                </div>
                <div style={{ backgroundColor: '#1e293b', padding: '12px 20px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase' }}>Protocols</span>
                    <span style={{ fontSize: '14px', fontWeight: 'bold', color: '#a78bfa' }}>{Object.keys(stats.protocols).length} detected</span>
                </div>
                {isCapturing && (
                    <div style={{
                        display: 'flex', alignItems: 'center', gap: '8px', marginLeft: 'auto',
                        padding: '8px 14px', borderRadius: '8px',
                        backgroundColor: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.25)',
                    }}>
                        <span style={{
                            width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#22c55e',
                            animation: 'pulse 1.5s ease-in-out infinite',
                            boxShadow: '0 0 6px #22c55e',
                            display: 'inline-block',
                        }} />
                        <span style={{ fontSize: '12px', color: '#4ade80', fontWeight: '600' }}>Auto-saving to DB every 3s</span>
                    </div>
                )}
            </div>


            {/* Charts Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px', marginBottom: '24px' }}>
                <TrafficChart data={chartData} />
                <ProtocolPie data={protocolData} />
            </div>

            <DnsTable queries={dnsQueries} />

            {/* IP Reputation & Geo — show when capturing on internet interface OR when data is available from history */}
            {(isInternetFacing || Object.keys(ipReputation).length > 0) && (
                <div style={{ backgroundColor: '#1e293b', borderRadius: '12px', padding: '20px', marginBottom: '24px', border: '1px solid #334155' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
                        <Shield style={{ width: '20px', height: '20px', color: '#60a5fa' }} />
                        <h2 style={{ fontSize: '1.125rem', fontWeight: 'bold', color: '#e2e8f0' }}>IP Reputation & Geo Intelligence</h2>
                        <span style={{ fontSize: '12px', color: '#64748b', marginLeft: 'auto' }}>
                            {Object.keys(ipReputation).length} IPs checked
                        </span>
                    </div>

                    <GeoMap ipReputation={ipReputation} sniHostnames={sniHostnames} />

                    <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                            <thead>
                                <tr style={{ borderBottom: '1px solid #334155' }}>
                                    <th style={{ padding: '8px 12px', textAlign: 'left', color: '#94a3b8', fontWeight: '600' }}>IP Address</th>
                                    <th style={{ padding: '8px 12px', textAlign: 'left', color: '#94a3b8', fontWeight: '600' }}>Hostname</th>
                                    <th style={{ padding: '8px 12px', textAlign: 'center', color: '#94a3b8', fontWeight: '600' }}>Abuse Score</th>
                                    <th style={{ padding: '8px 12px', textAlign: 'center', color: '#94a3b8', fontWeight: '600' }}>Status</th>
                                    <th style={{ padding: '8px 12px', textAlign: 'left', color: '#94a3b8', fontWeight: '600' }}>Country</th>
                                    <th style={{ padding: '8px 12px', textAlign: 'left', color: '#94a3b8', fontWeight: '600' }}>ISP / Domain</th>
                                    <th style={{ padding: '8px 12px', textAlign: 'center', color: '#94a3b8', fontWeight: '600' }}>Reports</th>
                                </tr>
                            </thead>
                            <tbody>
                                {Object.keys(ipReputation).length === 0 ? (
                                    <tr>
                                        <td colSpan={7} style={{ padding: '24px 12px', textAlign: 'center', color: '#64748b', fontStyle: 'italic' }}>
                                            No public IPs checked yet — start a capture to see reputation data
                                        </td>
                                    </tr>
                                ) : (
                                    Object.values(ipReputation)
                                        .sort((a, b) => (b.abuseConfidenceScore || 0) - (a.abuseConfidenceScore || 0))
                                        .map(r => {
                                            const scoreColor = r.classification === 'Unsafe' ? '#ef4444'
                                                : r.classification === 'Suspicious' ? '#f59e0b' : '#22c55e';
                                            const scoreBg = r.classification === 'Unsafe' ? 'rgba(239,68,68,0.15)'
                                                : r.classification === 'Suspicious' ? 'rgba(245,158,11,0.15)' : 'rgba(34,197,94,0.15)';
                                            return (
                                                <tr key={r.ip} style={{ borderBottom: '1px solid #1e293b' }}>
                                                    <td style={{ padding: '8px 12px', color: '#e2e8f0', fontFamily: 'monospace' }}>{r.ip}</td>
                                                    <td style={{ padding: '8px 12px', color: sniHostnames[r.ip] ? '#60a5fa' : '#475569', fontSize: '12px', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={sniHostnames[r.ip] || ''}>
                                                        {sniHostnames[r.ip] || '—'}
                                                    </td>
                                                    <td style={{ padding: '8px 12px', textAlign: 'center' }}>
                                                        <span style={{
                                                            display: 'inline-block', minWidth: '40px', padding: '2px 10px',
                                                            borderRadius: '9999px', fontWeight: 'bold', fontSize: '12px',
                                                            color: scoreColor, backgroundColor: scoreBg
                                                        }}>
                                                            {r.abuseConfidenceScore ?? 0}%
                                                        </span>
                                                    </td>
                                                    <td style={{ padding: '8px 12px', textAlign: 'center', color: scoreColor, fontWeight: '600', fontSize: '12px' }}>
                                                        {r.classification || '—'}
                                                    </td>
                                                    <td style={{ padding: '8px 12px', color: '#cbd5e1' }}>{r.country || '—'}</td>
                                                    <td style={{ padding: '8px 12px', color: '#94a3b8' }}>
                                                        {r.isp || ''}{r.domain ? ` (${r.domain})` : ''}
                                                    </td>
                                                    <td style={{ padding: '8px 12px', textAlign: 'center', color: '#cbd5e1' }}>{r.totalReports ?? 0}</td>
                                                </tr>
                                            );
                                        })
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            <PacketTable
                packets={packets}
                sniHostnames={sniHostnames}
                totalPackets={historyMeta?.totalPackets}
                hasMore={historyMeta?.hasMore}
                onLoadMore={historyMeta ? handleLoadMore : null}
                loadingMore={historyMeta?.loadingMore}
            />
        </div>
    );
};

export default Dashboard;
