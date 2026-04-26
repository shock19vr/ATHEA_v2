import React, { useState, useEffect } from 'react';
import { Clock, Trash2, DownloadCloud, X, Calendar, Bookmark } from 'lucide-react';

const API_URL = 'http://localhost:8000/api';

const HistoryModal = ({ isOpen, onClose, onLoadSession }) => {
    const [activeTab, setActiveTab] = useState('daily');     // 'daily' | 'snapshots'
    const [dailyDates, setDailyDates] = useState([]);
    const [snapshots, setSnapshots] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const fetchData = async () => {
        setLoading(true);
        setError(null);
        try {
            const [dailyRes, snapRes] = await Promise.all([
                fetch(`${API_URL}/daily`),
                fetch(`${API_URL}/scans`),
            ]);
            const dailyData = await dailyRes.json();
            const snapData = await snapRes.json();
            setDailyDates(dailyData.dates || []);
            setSnapshots(snapData.scans || []);
        } catch (err) {
            setError('Failed to load history data');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (isOpen) fetchData();
    }, [isOpen]);

    const handleLoadDaily = (dateStr) => {
        // Pass a sentinel — Dashboard will handle the paginated fetch
        onLoadSession({ _dailyDate: dateStr });
        onClose();
    };

    const handleDeleteDaily = async (e, dateStr) => {
        e.stopPropagation();
        if (!window.confirm(`Delete all captured data for ${dateStr}? This cannot be undone.`)) return;
        try {
            await fetch(`${API_URL}/daily/${dateStr}`, { method: 'DELETE' });
            fetchData();
        } catch (err) {
            console.error('Delete daily failed', err);
        }
    };

    const handleLoadSnapshot = async (id) => {
        setLoading(true);
        try {
            const res = await fetch(`${API_URL}/scans/${id}`);
            if (!res.ok) throw new Error('Failed to load snapshot');
            const data = await res.json();
            onLoadSession(data);
            onClose();
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleDeleteSnapshot = async (e, id) => {
        e.stopPropagation();
        if (!window.confirm('Delete this snapshot permanently?')) return;
        try {
            await fetch(`${API_URL}/scans/${id}`, { method: 'DELETE' });
            fetchData();
        } catch (err) {
            console.error('Delete snapshot failed', err);
        }
    };

    if (!isOpen) return null;

    const tabStyle = (tab) => ({
        padding: '10px 20px',
        border: 'none',
        cursor: 'pointer',
        fontWeight: 'bold',
        fontSize: '14px',
        borderBottom: activeTab === tab ? '2px solid #60a5fa' : '2px solid transparent',
        backgroundColor: 'transparent',
        color: activeTab === tab ? '#60a5fa' : '#64748b',
        display: 'flex',
        alignItems: 'center',
        gap: '6px',
        transition: 'color 0.2s',
    });

    return (
        <div style={{
            position: 'fixed', top: 0, left: 0, width: '100%', height: '100%',
            backgroundColor: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(6px)',
            display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000
        }}>
            <div style={{
                backgroundColor: '#1e293b', width: '90%', maxWidth: '860px', maxHeight: '82vh',
                borderRadius: '16px', border: '1px solid #334155', display: 'flex', flexDirection: 'column',
                boxShadow: '0 25px 50px rgba(0,0,0,0.6)',
            }}>
                {/* Header */}
                <div style={{
                    padding: '20px 24px 0', borderBottom: '1px solid #334155',
                    display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
                }}>
                    <div>
                        <h2 style={{ margin: '0 0 16px 0', color: '#f8fafc', fontSize: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <Clock size={22} style={{ color: '#60a5fa' }} />
                            Capture History
                        </h2>
                        <div style={{ display: 'flex', gap: '4px' }}>
                            <button style={tabStyle('daily')} onClick={() => setActiveTab('daily')}>
                                <Calendar size={16} />
                                Daily Logs
                                {dailyDates.length > 0 && (
                                    <span style={{
                                        background: '#1d4ed8', color: 'white', fontSize: '11px',
                                        padding: '1px 7px', borderRadius: '9999px', marginLeft: '4px'
                                    }}>{dailyDates.length}</span>
                                )}
                            </button>
                            <button style={tabStyle('snapshots')} onClick={() => setActiveTab('snapshots')}>
                                <Bookmark size={16} />
                                Snapshots
                                {snapshots.length > 0 && (
                                    <span style={{
                                        background: '#6d28d9', color: 'white', fontSize: '11px',
                                        padding: '1px 7px', borderRadius: '9999px', marginLeft: '4px'
                                    }}>{snapshots.length}</span>
                                )}
                            </button>
                        </div>
                    </div>
                    <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', padding: '4px' }}>
                        <X size={22} />
                    </button>
                </div>

                {/* Body */}
                <div style={{ padding: '20px 24px', overflowY: 'auto', flex: 1 }}>

                    {loading && (
                        <div style={{ color: '#60a5fa', textAlign: 'center', padding: '40px', fontSize: '15px' }}>
                            ⏳ Loading...
                        </div>
                    )}
                    {!loading && error && (
                        <div style={{ color: '#f87171', textAlign: 'center', padding: '40px' }}>{error}</div>
                    )}

                    {/* ── DAILY LOGS TAB ── */}
                    {!loading && !error && activeTab === 'daily' && (
                        <>
                            {dailyDates.length === 0 ? (
                                <div style={{ color: '#64748b', textAlign: 'center', padding: '48px 0', fontSize: '15px' }}>
                                    📭 No daily logs yet. Start a capture — packets auto-save every 3 seconds.
                                </div>
                            ) : (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                                    {dailyDates.map(({ date, stats }) => (
                                        <div key={date} style={{
                                            backgroundColor: '#0f172a', borderRadius: '10px', padding: '14px 18px',
                                            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                                            border: '1px solid #1e3a5f', transition: 'border-color 0.2s',
                                        }}>
                                            <div>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                                                    <Calendar size={16} style={{ color: '#60a5fa' }} />
                                                    <span style={{ fontWeight: 'bold', fontSize: '17px', color: '#e2e8f0' }}>{date}</span>
                                                </div>
                                                <div style={{ fontSize: '13px', color: '#64748b', display: 'flex', gap: '14px', paddingLeft: '26px' }}>
                                                    <span>📦 {stats?.total ?? 0} packets</span>
                                                    {stats?.protocols && (
                                                        <span>{Object.keys(stats.protocols).join(' · ')}</span>
                                                    )}
                                                </div>
                                            </div>
                                            <div style={{ display: 'flex', gap: '10px' }}>
                                                <button onClick={() => handleLoadDaily(date)} style={{
                                                    display: 'flex', alignItems: 'center', gap: '6px',
                                                    padding: '7px 16px', borderRadius: '8px', border: 'none',
                                                    background: 'linear-gradient(135deg, #1d4ed8, #2563eb)',
                                                    color: 'white', cursor: 'pointer', fontWeight: 'bold', fontSize: '13px',
                                                    boxShadow: '0 0 12px rgba(37,99,235,0.4)',
                                                }}>
                                                    <DownloadCloud size={15} /> Load Day
                                                </button>
                                                <button onClick={(e) => handleDeleteDaily(e, date)} style={{
                                                    display: 'flex', alignItems: 'center',
                                                    padding: '7px 12px', borderRadius: '8px',
                                                    border: '1px solid #ef4444', background: 'transparent',
                                                    color: '#ef4444', cursor: 'pointer',
                                                }}>
                                                    <Trash2 size={15} />
                                                </button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </>
                    )}

                    {/* ── SNAPSHOTS TAB ── */}
                    {!loading && !error && activeTab === 'snapshots' && (
                        <>
                            {snapshots.length === 0 ? (
                                <div style={{ color: '#64748b', textAlign: 'center', padding: '48px 0', fontSize: '15px' }}>
                                    🔖 No snapshots yet. Use "Save Snapshot" to bookmark a part of your current analysis.
                                </div>
                            ) : (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                                    {snapshots.map(snap => (
                                        <div key={snap._id} style={{
                                            backgroundColor: '#0f172a', borderRadius: '10px', padding: '14px 18px',
                                            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                                            border: '1px solid #2e1065',
                                        }}>
                                            <div>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                                                    <Bookmark size={16} style={{ color: '#a78bfa' }} />
                                                    <span style={{ fontWeight: 'bold', fontSize: '16px', color: '#e2e8f0' }}>
                                                        {snap.name || 'Unnamed Snapshot'}
                                                    </span>
                                                </div>
                                                <div style={{ fontSize: '13px', color: '#64748b', display: 'flex', gap: '14px', paddingLeft: '26px' }}>
                                                    <span>📅 {new Date(snap.timestamp).toLocaleString()}</span>
                                                    {snap.stats && <span>📦 {snap.stats.total ?? 0} packets</span>}
                                                </div>
                                            </div>
                                            <div style={{ display: 'flex', gap: '10px' }}>
                                                <button onClick={() => handleLoadSnapshot(snap._id)} style={{
                                                    display: 'flex', alignItems: 'center', gap: '6px',
                                                    padding: '7px 16px', borderRadius: '8px', border: 'none',
                                                    background: 'linear-gradient(135deg, #6d28d9, #7c3aed)',
                                                    color: 'white', cursor: 'pointer', fontWeight: 'bold', fontSize: '13px',
                                                    boxShadow: '0 0 12px rgba(124,58,237,0.4)',
                                                }}>
                                                    <DownloadCloud size={15} /> Load
                                                </button>
                                                <button onClick={(e) => handleDeleteSnapshot(e, snap._id)} style={{
                                                    display: 'flex', alignItems: 'center',
                                                    padding: '7px 12px', borderRadius: '8px',
                                                    border: '1px solid #ef4444', background: 'transparent',
                                                    color: '#ef4444', cursor: 'pointer',
                                                }}>
                                                    <Trash2 size={15} />
                                                </button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </>
                    )}
                </div>
            </div>
        </div>
    );
};

export default HistoryModal;
