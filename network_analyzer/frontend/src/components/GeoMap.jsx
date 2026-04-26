import React, { useEffect, useState, useMemo, useRef, useCallback } from 'react';
import { MapContainer, TileLayer, Polyline, Tooltip, Marker, useMap } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';
import { divIcon } from 'leaflet';
import { LocateFixed, Maximize2, Minimize2 } from 'lucide-react';

// Fix for default marker icons in React Leaflet
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
    iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
    iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
    shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

// Pre-build the four icons once — never recreated on re-render
const ICONS = {
    unsafe: divIcon({
        className: '',
        html: `<div style="background:#ef4444;width:10px;height:10px;border-radius:50%;box-shadow:0 0 8px #ef4444;border:1.5px solid #fca5a5;"></div>`,
        iconSize: [10, 10], iconAnchor: [5, 5],
    }),
    suspicious: divIcon({
        className: '',
        html: `<div style="background:#f59e0b;width:10px;height:10px;border-radius:50%;box-shadow:0 0 8px #f59e0b;border:1.5px solid #fcd34d;"></div>`,
        iconSize: [10, 10], iconAnchor: [5, 5],
    }),
    safe: divIcon({
        className: '',
        html: `<div style="background:#22c55e;width:10px;height:10px;border-radius:50%;box-shadow:0 0 8px #22c55e;border:1.5px solid #86efac;"></div>`,
        iconSize: [10, 10], iconAnchor: [5, 5],
    }),
    me: divIcon({
        className: '',
        html: `<div style="background:#3b82f6;width:12px;height:12px;border-radius:50%;box-shadow:0 0 10px #3b82f6;border:2px solid white;"></div>`,
        iconSize: [12, 12], iconAnchor: [6, 6],
    }),
};

const getIcon = (cls) => ICONS[cls === 'Unsafe' ? 'unsafe' : cls === 'Suspicious' ? 'suspicious' : 'safe'];
const getColor = (cls) => cls === 'Unsafe' ? '#ef4444' : cls === 'Suspicious' ? '#f59e0b' : '#22c55e';

// Lightweight bezier with only 10 points instead of 24
const getCurvedPath = (from, to) => {
    const pts = [];
    const midLat = (from[0] + to[0]) / 2 + (to[1] - from[1]) * 0.08;
    const midLng = (from[1] + to[1]) / 2 - (to[0] - from[0]) * 0.08;
    for (let i = 0; i <= 10; i++) {
        const t = i / 10;
        pts.push([
            (1-t)*(1-t)*from[0] + 2*(1-t)*t*midLat + t*t*to[0],
            (1-t)*(1-t)*from[1] + 2*(1-t)*t*midLng + t*t*to[1],
        ]);
    }
    return pts;
};

// Max connections to render at once to keep rendering fast
const MAX_CONNECTIONS = 30;

const AutoFitBounds = ({ markers, hasFitted, onFit }) => {
    const map = useMap();
    useEffect(() => {
        if (markers.length > 0 && !hasFitted) {
            const group = new L.FeatureGroup(markers.map(m => L.marker([m.lat, m.lon])));
            map.fitBounds(group.getBounds().pad(0.1));
            onFit();
        }
    }, [markers, hasFitted, map, onFit]);
    return null;
};

const GeoMap = ({ ipReputation, sniHostnames = {} }) => {
    const [myLocation, setMyLocation] = useState(null);
    const [hasFitted, setHasFitted] = useState(false);
    const [selectedIp, setSelectedIp] = useState(null);
    const [expanded, setExpanded] = useState(false);
    const mapRef = useRef(null);

    useEffect(() => {
        fetch('http://ip-api.com/json/')
            .then(r => r.json())
            .then(d => { if (d.status === 'success') setMyLocation({ lat: d.lat, lon: d.lon, city: d.city, country: d.country }); })
            .catch(() => {});
    }, []);

    // Sort: unsafe first, then suspicious, then safe — cap at MAX_CONNECTIONS
    const locations = useMemo(() => {
        const order = { Unsafe: 0, Suspicious: 1, Safe: 2 };
        return Object.values(ipReputation)
            .filter(r => r.lat && r.lon)
            .sort((a, b) => (order[a.classification] ?? 3) - (order[b.classification] ?? 3))
            .slice(0, MAX_CONNECTIONS);
    }, [ipReputation]);

    // Pre-compute curved paths so they're not recalculated on every render
    const paths = useMemo(() => {
        if (!myLocation) return {};
        const result = {};
        locations.forEach(loc => {
            result[loc.ip] = getCurvedPath([myLocation.lat, myLocation.lon], [loc.lat, loc.lon]);
        });
        return result;
    }, [locations, myLocation]);

    const totalAll = Object.values(ipReputation).filter(r => r.lat && r.lon).length;
    const countries = new Set(locations.map(l => l.country)).size;
    const unsafeCount = locations.filter(l => l.classification === 'Unsafe').length;
    const suspiciousCount = locations.filter(l => l.classification === 'Suspicious').length;
    const safeCount = locations.filter(l => l.classification === 'Safe').length;
    const selectedData = selectedIp ? ipReputation[selectedIp] : null;

    const handleRecenter = useCallback(() => {
        if (!mapRef.current || !myLocation) return;
        const allPoints = [myLocation, ...locations];
        const group = new L.FeatureGroup(allPoints.map(m => L.marker([m.lat, m.lon])));
        mapRef.current.fitBounds(group.getBounds().pad(0.1));
    }, [myLocation, locations]);

    const mapHeight = expanded ? '480px' : '280px';

    if (!myLocation) {
        return (
            <div style={{ padding: '36px', textAlign: 'center', color: '#64748b', background: '#0f172a', borderRadius: '12px', border: '1px solid #334155' }}>
                <div style={{ display: 'inline-block', width: '28px', height: '28px', border: '3px solid #334155', borderTopColor: '#3b82f6', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
                <div style={{ marginTop: '10px', fontSize: '13px' }}>Locating position…</div>
                <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
            </div>
        );
    }

    const safeW   = locations.length > 0 ? (safeCount / locations.length) * 100 : 0;
    const suspW   = locations.length > 0 ? (suspiciousCount / locations.length) * 100 : 0;
    const unsafeW = locations.length > 0 ? (unsafeCount / locations.length) * 100 : 0;

    return (
        <div style={{ position: 'relative', height: mapHeight, borderRadius: '12px', overflow: 'hidden', border: '1px solid #334155', marginBottom: '16px', transition: 'height 0.3s ease' }}>
            <style>{`
                .leaflet-popup-content-wrapper, .leaflet-popup-tip {
                    background:#1e293b; color:#e2e8f0; border:1px solid #475569;
                    box-shadow:0 8px 24px rgba(0,0,0,0.5); border-radius:10px;
                }
                .leaflet-popup-content { margin:12px; line-height:1.5; }
                .leaflet-container a.leaflet-popup-close-button { color:#94a3b8; }
                .geo-sidebar-enter { animation: geoSlide 0.2s ease-out; }
                @keyframes geoSlide { from { transform: translateX(100%); opacity:0; } to { transform: translateX(0); opacity:1; } }
            `}</style>

            {/* Top-right overlay: stats + controls */}
            <div style={{ position: 'absolute', top: '10px', right: '10px', zIndex: 1000, display: 'flex', gap: '6px', alignItems: 'flex-start' }}>
                {/* Stats card */}
                <div style={{
                    background: 'rgba(15,23,42,0.9)', backdropFilter: 'blur(8px)',
                    padding: '8px 12px', borderRadius: '8px', border: '1px solid #334155',
                    color: '#e2e8f0', fontSize: '12px', minWidth: '160px',
                }}>
                    <div style={{ display: 'flex', gap: '14px', marginBottom: locations.length > 0 ? '6px' : 0 }}>
                        <div>
                            <div style={{ color: '#64748b', fontSize: '9px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>IPs</div>
                            <div style={{ fontWeight: 'bold', fontSize: '15px' }}>
                                {locations.length}
                                {totalAll > MAX_CONNECTIONS && <span style={{ fontSize: '10px', color: '#64748b' }}> /{totalAll}</span>}
                            </div>
                        </div>
                        <div>
                            <div style={{ color: '#64748b', fontSize: '9px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Countries</div>
                            <div style={{ fontWeight: 'bold', fontSize: '15px' }}>{countries}</div>
                        </div>
                        {unsafeCount > 0 && (
                            <div>
                                <div style={{ color: '#ef4444', fontSize: '9px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Threats</div>
                                <div style={{ fontWeight: 'bold', fontSize: '15px', color: '#ef4444' }}>{unsafeCount}</div>
                            </div>
                        )}
                    </div>
                    {locations.length > 0 && (
                        <div style={{ display: 'flex', height: '3px', borderRadius: '2px', overflow: 'hidden', gap: '1px' }}>
                            {safeW > 0   && <div style={{ width: `${safeW}%`,   background: '#22c55e' }} />}
                            {suspW > 0   && <div style={{ width: `${suspW}%`,   background: '#f59e0b' }} />}
                            {unsafeW > 0 && <div style={{ width: `${unsafeW}%`, background: '#ef4444' }} />}
                        </div>
                    )}
                </div>

                {/* Recenter */}
                <button onClick={handleRecenter} title="Recenter" style={{
                    background: '#1e293b', border: '1px solid #334155', borderRadius: '7px',
                    width: '30px', height: '30px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                    cursor: 'pointer', color: '#60a5fa',
                }}>
                    <LocateFixed size={14} />
                </button>

                {/* Expand/collapse */}
                <button onClick={() => setExpanded(e => !e)} title={expanded ? 'Collapse' : 'Expand'} style={{
                    background: '#1e293b', border: '1px solid #334155', borderRadius: '7px',
                    width: '30px', height: '30px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                    cursor: 'pointer', color: '#94a3b8',
                }}>
                    {expanded ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
                </button>
            </div>

            {/* Detail sidebar */}
            {selectedData && (
                <div className="geo-sidebar-enter" style={{
                    position: 'absolute', top: 0, right: 0, bottom: 0, zIndex: 1001,
                    width: '240px', maxWidth: '70%',
                    background: 'rgba(15,23,42,0.95)', backdropFilter: 'blur(12px)',
                    borderLeft: '1px solid #334155', padding: '14px', overflowY: 'auto',
                }}>
                    <button onClick={() => setSelectedIp(null)} style={{
                        float: 'right', background: 'none', border: 'none',
                        color: '#64748b', cursor: 'pointer', fontSize: '16px', lineHeight: 1,
                    }}>✕</button>
                    <div style={{ fontSize: '9px', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '3px' }}>Connection</div>
                    <div style={{ fontFamily: 'monospace', fontSize: '14px', fontWeight: 'bold', color: '#e2e8f0', marginBottom: '4px', wordBreak: 'break-all' }}>
                        {selectedData.ip}
                    </div>
                    <span style={{
                        display: 'inline-block', fontSize: '10px', padding: '2px 8px', borderRadius: '6px',
                        fontWeight: 'bold', marginBottom: '12px',
                        background: getColor(selectedData.classification) + '25',
                        color: getColor(selectedData.classification),
                        border: `1px solid ${getColor(selectedData.classification)}40`,
                    }}>{selectedData.classification}</span>

                    <div style={{ textAlign: 'center', marginBottom: '14px' }}>
                        <svg width="80" height="80" viewBox="0 0 100 100">
                            <circle cx="50" cy="50" r="40" fill="none" stroke="#1e293b" strokeWidth="8" />
                            <circle cx="50" cy="50" r="40" fill="none"
                                stroke={getColor(selectedData.classification)} strokeWidth="8" strokeLinecap="round"
                                strokeDasharray={`${(selectedData.abuseConfidenceScore / 100) * 251} 251`}
                                transform="rotate(-90 50 50)"
                            />
                            <text x="50" y="46" textAnchor="middle" fill={getColor(selectedData.classification)} fontSize="22" fontWeight="bold">
                                {selectedData.abuseConfidenceScore ?? 0}
                            </text>
                            <text x="50" y="62" textAnchor="middle" fill="#64748b" fontSize="8">SCORE</text>
                        </svg>
                    </div>

                    {[
                        ['📍', `${selectedData.city ? selectedData.city + ', ' : ''}${selectedData.country || '—'}`],
                        ['🌐', sniHostnames[selectedData.ip] || '—'],
                        ['🏢', selectedData.isp || '—'],
                        ['📊', `${selectedData.totalReports ?? 0} reports`],
                    ].map(([icon, value]) => (
                        <div key={icon} style={{
                            background: 'rgba(30,41,59,0.6)', padding: '7px 10px', borderRadius: '7px',
                            border: '1px solid #1e293b', marginBottom: '6px', fontSize: '12px', color: '#cbd5e1',
                        }}>
                            {icon} {value}
                        </div>
                    ))}
                </div>
            )}

            <MapContainer
                center={[myLocation.lat, myLocation.lon]}
                zoom={2}
                style={{ height: '100%', width: '100%', background: '#020617' }}
                scrollWheelZoom={true}
                zoomControl={false}
                attributionControl={false}
                ref={mapRef}
                preferCanvas={true}
            >
                <TileLayer
                    url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                    opacity={0.85}
                    maxZoom={18}
                    keepBuffer={2}
                />

                {/* My location */}
                <Marker position={[myLocation.lat, myLocation.lon]} icon={ICONS.me}>
                    <Tooltip direction="top" offset={[0, -8]} opacity={1} permanent>
                        <span style={{ fontSize: '11px' }}>You</span>
                    </Tooltip>
                </Marker>

                {/* Connection arcs + IP markers — using pre-computed paths */}
                {locations.map(loc => {
                    const color = getColor(loc.classification);
                    const path = paths[loc.ip];
                    if (!path) return null;
                    const isSelected = selectedIp === loc.ip;

                    return (
                        <React.Fragment key={loc.ip}>
                            <Polyline
                                positions={path}
                                pathOptions={{
                                    color,
                                    weight: isSelected ? 2 : 1,
                                    opacity: isSelected ? 0.9 : 0.45,
                                    // No animation — static lines are far faster
                                }}
                            />
                            <Marker
                                position={[loc.lat, loc.lon]}
                                icon={getIcon(loc.classification)}
                                eventHandlers={{ click: () => setSelectedIp(loc.ip) }}
                            >
                                <Tooltip direction="top" offset={[0, -8]} opacity={0.95}>
                                    <div style={{ fontSize: '11px', lineHeight: '1.4' }}>
                                        <div style={{ fontWeight: 'bold', fontFamily: 'monospace' }}>{loc.ip}</div>
                                        {sniHostnames[loc.ip] && (
                                            <div style={{ color: '#60a5fa', fontSize: '10px' }}>{sniHostnames[loc.ip]}</div>
                                        )}
                                        <div style={{ color: '#94a3b8' }}>
                                            {loc.city ? `${loc.city}, ` : ''}{loc.country}
                                        </div>
                                        <div style={{ color, fontWeight: 'bold' }}>
                                            {loc.classification} · {loc.abuseConfidenceScore}%
                                        </div>
                                    </div>
                                </Tooltip>
                            </Marker>
                        </React.Fragment>
                    );
                })}

                <AutoFitBounds
                    markers={[myLocation, ...locations]}
                    hasFitted={hasFitted}
                    onFit={() => setHasFitted(true)}
                />
            </MapContainer>
        </div>
    );
};

export default GeoMap;
