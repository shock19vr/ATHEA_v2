'use client';
import { useState, useMemo } from 'react';
import { Alert } from '@/types';
import AlertRow from './AlertRow';

interface Props {
  alerts: Alert[];
  onSelectAlert: (alert: Alert | null) => void;
  selectedId: string | null;
}

type SortKey = 'timestamp' | 'rule_level' | 'anomaly_score' | 'agent_name';
type FilterMode = 'all' | 'anomaly' | 'normal';

const PAGE_SIZE = 25;

export default function AnomalyTable({ alerts, onSelectAlert, selectedId }: Props) {
  const [search, setSearch]       = useState('');
  const [filter, setFilter]       = useState<FilterMode>('all');
  const [sortKey, setSortKey]     = useState<SortKey>('timestamp');
  const [sortAsc, setSortAsc]     = useState(false);
  const [page, setPage]           = useState(1);

  const filtered = useMemo(() => {
    let list = [...alerts];


    if (filter === 'anomaly') list = list.filter(a => a.anomaly === 1);
    if (filter === 'normal')  list = list.filter(a => a.anomaly !== 1);


    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(a =>
        a.rule_description?.toLowerCase().includes(q) ||
        a.agent_name?.toLowerCase().includes(q) ||
        a.event_id?.toLowerCase().includes(q) ||
        a.mitre_stage?.toLowerCase().includes(q) ||
        a.src_ip?.toLowerCase().includes(q) ||
        a.rule_id?.includes(q)
      );
    }


    list.sort((a, b) => {
      let av: number | string, bv: number | string;
      if (sortKey === 'timestamp')    { av = a.timestamp || ''; bv = b.timestamp || ''; }
      else if (sortKey === 'rule_level')    { av = a.rule_level; bv = b.rule_level; }
      else if (sortKey === 'anomaly_score') { av = a.anomaly_score ?? -1; bv = b.anomaly_score ?? -1; }
      else { av = a.agent_name || ''; bv = b.agent_name || ''; }

      if (av < bv) return sortAsc ? -1 : 1;
      if (av > bv) return sortAsc ? 1 : -1;
      return 0;
    });

    return list;
  }, [alerts, filter, search, sortKey, sortAsc]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const paginated   = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  const anomalyCount = alerts.filter(a => a.anomaly === 1).length;

  function handleSort(key: SortKey) {
    if (sortKey === key) setSortAsc(v => !v);
    else { setSortKey(key); setSortAsc(false); }
  }

  function SortIcon({ col }: { col: SortKey }) {
    if (sortKey !== col) return null;
    return <span className="sort-icon" style={{ color: 'var(--accent)' }}>{sortAsc ? '▲' : '▼'}</span>;
  }

  return (
    <div>

      <div className="toolbar">
        <div className="search-box">
          <span style={{ color: 'var(--text-muted)', fontSize: 14 }}></span>
          <input
            type="text"
            placeholder="Search rules, agents, event IDs, IPs…"
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1); }}
          />
          {search && (
            <button onClick={() => setSearch('')} style={{ color: 'var(--text-muted)', fontSize: 12 }}>✕</button>
          )}
        </div>

        <button
          className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
          onClick={() => { setFilter('all'); setPage(1); }}
        >
          All ({alerts.length})
        </button>
        <button
          className={`filter-btn danger ${filter === 'anomaly' ? 'active' : ''}`}
          onClick={() => { setFilter('anomaly'); setPage(1); }}
        >
          Anomalies ({anomalyCount})
        </button>
        <button
          className={`filter-btn ${filter === 'normal' ? 'active' : ''}`}
          onClick={() => { setFilter('normal'); setPage(1); }}
        >
          Normal ({alerts.length - anomalyCount})
        </button>
      </div>


      <div className="table-wrapper">
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th onClick={() => handleSort('timestamp')}>Time <SortIcon col="timestamp" /></th>
                <th onClick={() => handleSort('rule_level')}>Lvl <SortIcon col="rule_level" /></th>
                <th>Description</th>
                <th onClick={() => handleSort('agent_name')}>Agent <SortIcon col="agent_name" /></th>
                <th>Event ID</th>
                <th>MITRE Stage</th>
                <th onClick={() => handleSort('anomaly_score')}>Score <SortIcon col="anomaly_score" /></th>
                <th>Confidence</th>
                <th>Cluster</th>
              </tr>
            </thead>
            <tbody>
              {paginated.length === 0 ? (
                <tr>
                  <td colSpan={9}>
                    <div className="empty-state">
                      <div className="empty-icon"></div>
                      <div className="empty-title">No alerts found</div>
                      <div className="empty-desc">
                        {search
                          ? `No results for "${search}". Try a different query.`
                          : 'No alerts match the current filter.'}
                      </div>
                    </div>
                  </td>
                </tr>
              ) : (
                paginated.map(alert => (
                  <AlertRow
                    key={alert.doc_id || `${alert.timestamp}-${alert.rule_id}`}
                    alert={alert}
                    isSelected={selectedId === alert.doc_id}
                    onClick={() => onSelectAlert(selectedId === alert.doc_id ? null : alert)}
                  />
                ))
              )}
            </tbody>
          </table>
        </div>


        <div className="table-footer">
          <span>
            {filtered.length === 0
              ? 'No results'
              : `${(currentPage - 1) * PAGE_SIZE + 1}–${Math.min(currentPage * PAGE_SIZE, filtered.length)} of ${filtered.length}`}
          </span>
          <div className="pagination">
            <button
              className="page-btn"
              onClick={() => setPage(1)}
              disabled={currentPage === 1}
              aria-label="First page"
            >«</button>
            <button
              className="page-btn"
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              aria-label="Previous page"
            >‹</button>
            <span style={{ padding: '0 8px', fontSize: 12, color: 'var(--text-secondary)' }}>
              {currentPage} / {totalPages}
            </span>
            <button
              className="page-btn"
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              aria-label="Next page"
            >›</button>
            <button
              className="page-btn"
              onClick={() => setPage(totalPages)}
              disabled={currentPage === totalPages}
              aria-label="Last page"
            >»</button>
          </div>
        </div>
      </div>
    </div>
  );
}
