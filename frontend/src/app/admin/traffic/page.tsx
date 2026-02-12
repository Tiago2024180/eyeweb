'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { supabase } from '@/lib/supabase';
import './traffic.css';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// ─── AUTH HELPER ───────────────────────────────────────
// Obtém o token Supabase para autenticar requests ao backend admin
async function getAuthHeaders(): Promise<HeadersInit> {
  try {
    const { data: { session } } = await supabase.auth.getSession();
    if (session?.access_token) {
      return { 'Authorization': `Bearer ${session.access_token}` };
    }
  } catch {}
  return {};
}

// ═══════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════

interface TrafficLog {
  id: number;
  ip: string;
  method: string;
  path: string;
  status_code: number;
  user_agent: string;
  country: string;
  city: string;
  is_vpn: boolean;
  vpn_provider: string;
  response_time_ms: number;
  created_at: string;
}

interface SuspiciousEvent {
  id: number;
  ip: string;
  event: string;
  severity: string;
  details: string;
  path: string;
  auto_blocked: boolean;
  created_at: string;
}

interface BlockedIP {
  id: number;
  ip: string;
  reason: string;
  blocked_by: string;
  request_count: number;
  country: string;
  is_vpn: boolean;
  log_snapshot: string;
  created_at: string;
}

interface Connection {
  ip: string;
  country: string;
  city: string;
  is_vpn: boolean;
  vpn_provider: string;
  method: string;
  requests: number;
  online: boolean;
}

interface Stats {
  requests_today: number;
  active_ips_5m: number;
  suspicious_today: number;
  blocked_total: number;
}

interface DetailedLogEntry {
  _type: 'request' | 'threat';
  id: string;
  ip: string;
  timestamp: string;
  method: string;
  path: string;
  status_code: number;
  user_agent: string;
  country: string;
  city: string;
  is_vpn: boolean;
  vpn_provider: string;
  response_time_ms: number;
  event: string | null;
  severity: string | null;
  details: string | null;
  auto_blocked: boolean;
}

type Tab = 'logs' | 'detailed' | 'blocked';

// ═══════════════════════════════════════════════════════
// COMPONENT
// ═══════════════════════════════════════════════════════

export default function TrafficMonitorPage() {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<Tab>('logs');
  const [connections, setConnections] = useState<Connection[]>([]);
  const [detailedLogs, setDetailedLogs] = useState<DetailedLogEntry[]>([]);
  const [blocked, setBlocked] = useState<BlockedIP[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Detailed logs filters (client-side for instant UX)
  const [detailedFilter, setDetailedFilter] = useState('');
  const [detailedTypeFilter, setDetailedTypeFilter] = useState<'all' | 'request' | 'threat'>('all');

  // Block modal
  const [showBlockModal, setShowBlockModal] = useState(false);
  const [blockTargetIp, setBlockTargetIp] = useState('');
  const [blockReason, setBlockReason] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  // ─── FETCH FUNCTIONS ─────────────────────────────────

  const fetchStats = useCallback(async () => {
    try {
      const headers = await getAuthHeaders();
      const r = await fetch(`${API}/api/admin/traffic/stats`, { headers });
      if (r.ok) setStats(await r.json());
    } catch {}
  }, []);

  const fetchConnections = useCallback(async () => {
    try {
      setError(null);
      const headers = await getAuthHeaders();
      const r = await fetch(`${API}/api/admin/traffic/connections`, { headers });
      if (r.ok) {
        const data = await r.json();
        setConnections(data.connections || []);
      }
    } catch {
      setError('Erro ao carregar conexões');
    } finally {
      setIsLoading(false);
    }
  }, []);

  const fetchDetailedLogs = useCallback(async () => {
    try {
      setError(null);
      const headers = await getAuthHeaders();
      const r = await fetch(`${API}/api/admin/traffic/detailed-logs?limit=200`, { headers });
      if (r.ok) {
        const data = await r.json();
        setDetailedLogs(data.entries || []);
      }
    } catch {
      setError('Erro ao carregar logs detalhados');
    } finally {
      setIsLoading(false);
    }
  }, []);

  const fetchBlocked = useCallback(async () => {
    try {
      setError(null);
      const headers = await getAuthHeaders();
      const r = await fetch(`${API}/api/admin/traffic/blocked`, { headers });
      if (r.ok) {
        const data = await r.json();
        setBlocked(data.blocked || []);
      }
    } catch {
      setError('Erro ao carregar IPs bloqueados');
    } finally {
      setIsLoading(false);
    }
  }, []);

  // ─── EFFECTS ─────────────────────────────────────────

  // Initial load
  useEffect(() => {
    fetchStats();
    fetchConnections();
  }, [fetchStats, fetchConnections]);

  // Tab change
  useEffect(() => {
    setIsLoading(true);
    if (activeTab === 'logs') fetchConnections();
    else if (activeTab === 'detailed') fetchDetailedLogs();
    else fetchBlocked();
  }, [activeTab, fetchConnections, fetchDetailedLogs, fetchBlocked]);

  // Auto-refresh
  useEffect(() => {
    if (!autoRefresh) return;
    const ms = activeTab === 'logs' ? 5000 : activeTab === 'detailed' ? 3000 : 10000;
    const interval = setInterval(() => {
      fetchStats();
      if (activeTab === 'logs') fetchConnections();
      else if (activeTab === 'detailed') fetchDetailedLogs();
      else fetchBlocked();
    }, ms);
    return () => clearInterval(interval);
  }, [autoRefresh, activeTab, fetchStats, fetchConnections, fetchDetailedLogs, fetchBlocked]);

  // ─── ACTIONS ─────────────────────────────────────────

  const handleBlock = async () => {
    if (!blockTargetIp || !blockReason.trim()) return;
    setActionLoading(true);
    try {
      const authHeaders = await getAuthHeaders();
      const r = await fetch(`${API}/api/admin/traffic/block-ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders },
        body: JSON.stringify({ ip: blockTargetIp, reason: blockReason }),
      });
      if (r.ok) {
        setShowBlockModal(false);
        setBlockTargetIp('');
        setBlockReason('');
        fetchStats();
        fetchBlocked();
        if (activeTab === 'logs') fetchConnections();
      }
    } catch {} finally {
      setActionLoading(false);
    }
  };

  const handleUnblock = async (ip: string) => {
    if (!confirm(`Desbloquear o IP ${ip}?`)) return;
    try {
      const authHeaders = await getAuthHeaders();
      await fetch(`${API}/api/admin/traffic/unblock-ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders },
        body: JSON.stringify({ ip }),
      });
      fetchStats();
      fetchBlocked();
    } catch {}
  };

  const openBlockModal = (ip: string) => {
    setBlockTargetIp(ip);
    setBlockReason('');
    setShowBlockModal(true);
  };

  const downloadSnapshot = (snapshot: string, ip: string) => {
    const blob = new Blob([snapshot || 'Sem dados de logs disponíveis'], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `blocked_${ip.replace(/\./g, '_')}_logs.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // ─── HELPERS ─────────────────────────────────────────

  const formatTime = (dt: string) => {
    try {
      return new Date(dt).toLocaleString('pt-PT', {
        day: '2-digit', month: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
      });
    } catch { return dt; }
  };

  const getMethodClass = (m: string) => {
    switch (m) {
      case 'GET': return 'method-get';
      case 'POST': return 'method-post';
      case 'PUT': case 'PATCH': return 'method-put';
      case 'DELETE': return 'method-delete';
      case 'PAGE': return 'method-page';
      default: return '';
    }
  };

  const getSeverityClass = (s: string) => {
    switch (s) {
      case 'low': return 'severity-low';
      case 'medium': return 'severity-medium';
      case 'high': return 'severity-high';
      case 'critical': return 'severity-critical';
      default: return '';
    }
  };

  const getEventLabel = (e: string) => {
    const labels: Record<string, string> = {
      rate_limit: 'Rate Limit',
      scanner: 'Scanner',
      sql_injection: 'SQL Injection',
      path_traversal: 'Path Traversal',
      brute_force: 'Brute Force',
    };
    return labels[e] || e;
  };

  const getEventIcon = (e: string) => {
    const icons: Record<string, string> = {
      rate_limit: 'fa-gauge-high',
      scanner: 'fa-radar',
      sql_injection: 'fa-database',
      path_traversal: 'fa-folder-tree',
      brute_force: 'fa-key',
    };
    return icons[e] || 'fa-triangle-exclamation';
  };

  // ─── WIRESHARK-STYLE HELPERS ─────────────────────

  const formatTimeWS = (dt: string) => {
    try {
      return new Date(dt).toLocaleTimeString('pt-PT', {
        hour: '2-digit', minute: '2-digit', second: '2-digit',
      });
    } catch { return dt; }
  };

  const getStatusClass = (code: number) => {
    if (code >= 500) return 'status-5xx';
    if (code >= 400) return 'status-4xx';
    if (code >= 300) return 'status-3xx';
    return 'status-2xx';
  };

  const getDetailedRowClass = (entry: DetailedLogEntry) => {
    if (entry._type === 'threat') {
      switch (entry.severity) {
        case 'critical': return 'ws-row ws-threat ws-critical';
        case 'high': return 'ws-row ws-threat ws-high';
        case 'medium': return 'ws-row ws-threat ws-medium';
        case 'low': return 'ws-row ws-threat ws-low';
        default: return 'ws-row ws-threat';
      }
    }
    if (entry.method === 'PAGE') return 'ws-row ws-page';
    return 'ws-row ws-request';
  };

  const getTypeIcon = (entry: DetailedLogEntry) => {
    if (entry._type === 'threat') return getEventIcon(entry.event || '');
    if (entry.method === 'PAGE') return 'fa-eye';
    return 'fa-arrow-right-arrow-left';
  };

  const getTypeLabel = (entry: DetailedLogEntry) => {
    if (entry._type === 'threat') return 'Ameaça';
    if (entry.method === 'PAGE') return 'Visita';
    return 'Request';
  };

  // Filtered detailed logs (client-side filtering for instant UX)
  const filteredDetailedLogs = detailedLogs.filter(entry => {
    if (detailedFilter && !entry.ip.includes(detailedFilter)) return false;
    if (detailedTypeFilter === 'request' && entry._type !== 'request') return false;
    if (detailedTypeFilter === 'threat' && entry._type !== 'threat') return false;
    return true;
  });

  // Set of blocked IPs for quick lookup in logs tab
  const blockedSet = new Set(blocked.map(b => b.ip));

  // ─── RENDER ──────────────────────────────────────────

  return (
    <div className="traffic-container">
      {/* ═══ HEADER ═══ */}
      <div className="traffic-header">
        <button className="back-btn" onClick={() => router.push('/admin')}>
          <i className="fa-solid fa-arrow-left"></i>
          Voltar
        </button>
        <h1>
          <i className="fa-solid fa-shield-halved"></i>
          Monitor de Tráfego
        </h1>
        <div className="header-actions">
          <label className="auto-refresh-toggle">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            <span>Auto-refresh</span>
          </label>
          {autoRefresh && (
            <span className="live-indicator">
              <span className="live-dot"></span>
              LIVE
            </span>
          )}
        </div>
      </div>

      {/* ═══ STATS ═══ */}
      {stats && (
        <div className="traffic-stats">
          <div className="stat-card">
            <div className="stat-icon"><i className="fa-solid fa-chart-line"></i></div>
            <div className="stat-info">
              <div className="stat-value">{stats.requests_today.toLocaleString()}</div>
              <div className="stat-label">Requests (hoje)</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon"><i className="fa-solid fa-users"></i></div>
            <div className="stat-info">
              <div className="stat-value">{connections.filter(c => c.online).length}</div>
              <div className="stat-label">IPs Online</div>
            </div>
          </div>
          <div className="stat-card stat-warning">
            <div className="stat-icon"><i className="fa-solid fa-triangle-exclamation"></i></div>
            <div className="stat-info">
              <div className="stat-value">{stats.suspicious_today}</div>
              <div className="stat-label">Suspeitos</div>
            </div>
          </div>
          <div className="stat-card stat-danger">
            <div className="stat-icon"><i className="fa-solid fa-ban"></i></div>
            <div className="stat-info">
              <div className="stat-value">{stats.blocked_total}</div>
              <div className="stat-label">Bloqueados</div>
            </div>
          </div>
        </div>
      )}

      {/* ═══ TABS ═══ */}
      <div className="traffic-tabs">
        <button
          className={`tab-btn ${activeTab === 'logs' ? 'active' : ''}`}
          onClick={() => setActiveTab('logs')}
        >
          <i className="fa-solid fa-list"></i>
          <span>Logs</span>
        </button>
        <button
          className={`tab-btn ${activeTab === 'detailed' ? 'active' : ''}`}
          onClick={() => setActiveTab('detailed')}
        >
          <i className="fa-solid fa-tower-broadcast"></i>
          <span>Logs Detalhados</span>
        </button>
        <button
          className={`tab-btn ${activeTab === 'blocked' ? 'active' : ''}`}
          onClick={() => setActiveTab('blocked')}
        >
          <i className="fa-solid fa-ban"></i>
          <span>IPs Bloqueados</span>
        </button>
      </div>

      {/* ═══ ERROR ═══ */}
      {error && (
        <div className="traffic-error">
          <i className="fa-solid fa-circle-exclamation"></i>
          <span>{error}</span>
        </div>
      )}

      {/* ═══ LOADING ═══ */}
      {isLoading && (
        <div className="traffic-loading">
          <i className="fa-solid fa-spinner fa-spin"></i>
          <span>A carregar dados...</span>
        </div>
      )}

      {/* ═══════════════════════════════════════════════ */}
      {/* TAB 1: LOGS (Conexões únicas hoje)              */}
      {/* ═══════════════════════════════════════════════ */}
      {!isLoading && activeTab === 'logs' && (
        <div className="traffic-table-wrapper">
          <div className="connections-header">
            <span className="connections-date">
              <i className="fa-regular fa-calendar"></i>
              {new Date().toLocaleDateString('pt-PT', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' })
                .replace(/\b\w/g, c => c.toUpperCase())}
            </span>
            <span className="connections-count">
              {connections.length} conexão{connections.length !== 1 ? 'ões' : ''}
              {' · '}
              <span className="online-count">{connections.filter(c => c.online).length} online</span>
            </span>
          </div>
          {connections.length === 0 ? (
            <div className="empty-state">
              <i className="fa-solid fa-plug-circle-xmark"></i>
              <p>Sem conexões registadas hoje</p>
              <span className="empty-hint">As conexões aparecem quando alguém visita o site</span>
            </div>
          ) : (
            <table className="traffic-table">
              <thead>
                <tr>
                  <th>Estado</th>
                  <th>IP</th>
                  <th>Localização</th>
                  <th>Tipo</th>
                  <th>VPN</th>
                  <th>Requests</th>
                  <th>Ações</th>
                </tr>
              </thead>
              <tbody>
                {connections.map((conn) => (
                  <tr
                    key={conn.ip}
                    className={
                      blockedSet.has(conn.ip) ? 'row-blocked' :
                      conn.is_vpn ? 'row-vpn' :
                      conn.online ? 'row-online' : ''
                    }
                  >
                    <td>
                      <span className={`online-badge ${conn.online ? 'is-online' : 'is-offline'}`}>
                        <span className="online-dot"></span>
                        {conn.online ? 'Online' : 'Offline'}
                      </span>
                    </td>
                    <td className="col-ip"><code>{conn.ip}</code></td>
                    <td className="col-location">
                      {conn.country || '—'}
                      {conn.city ? `, ${conn.city}` : ''}
                    </td>
                    <td>
                      <span className={`method-badge ${getMethodClass(conn.method)}`}>
                        {conn.method}
                      </span>
                    </td>
                    <td>
                      {conn.is_vpn ? (
                        <span className="vpn-badge" title={conn.vpn_provider || 'VPN/Proxy detetado'}>
                          Sim
                        </span>
                      ) : (
                        <span className="no-vpn">Não</span>
                      )}
                    </td>
                    <td className="col-requests">
                      <span className="requests-count">{conn.requests}</span>
                    </td>
                    <td className="col-actions">
                      {!blockedSet.has(conn.ip) && conn.ip !== '127.0.0.1' && (
                        <button
                          className="action-btn block-btn"
                          onClick={() => openBlockModal(conn.ip)}
                          title="Bloquear IP"
                        >
                          <i className="fa-solid fa-ban"></i>
                        </button>
                      )}
                      {blockedSet.has(conn.ip) && (
                        <span className="already-blocked" title="IP já bloqueado">
                          <i className="fa-solid fa-lock"></i>
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ═══════════════════════════════════════════════ */}
      {/* TAB 2: LOGS DETALHADOS (Wireshark-style)       */}
      {/* ═══════════════════════════════════════════════ */}
      {!isLoading && activeTab === 'detailed' && (
        <div className="traffic-table-wrapper detailed-wrapper">
          {/* ─── Filter Toolbar ─── */}
          <div className="detailed-toolbar">
            <div className="detailed-search">
              <i className="fa-solid fa-magnifying-glass"></i>
              <input
                type="text"
                placeholder="Filtrar por IP..."
                value={detailedFilter}
                onChange={(e) => setDetailedFilter(e.target.value)}
              />
            </div>
            <div className="detailed-type-filters">
              <button
                className={`type-filter-btn ${detailedTypeFilter === 'all' ? 'active' : ''}`}
                onClick={() => setDetailedTypeFilter('all')}
              >
                Todos
              </button>
              <button
                className={`type-filter-btn ${detailedTypeFilter === 'request' ? 'active' : ''}`}
                onClick={() => setDetailedTypeFilter('request')}
              >
                <i className="fa-solid fa-arrow-right-arrow-left"></i> Requests
              </button>
              <button
                className={`type-filter-btn ${detailedTypeFilter === 'threat' ? 'active' : ''}`}
                onClick={() => setDetailedTypeFilter('threat')}
              >
                <i className="fa-solid fa-skull-crossbones"></i> Ameaças
              </button>
            </div>
            <span className="detailed-count">
              {filteredDetailedLogs.length} entrada{filteredDetailedLogs.length !== 1 ? 's' : ''}
            </span>
          </div>

          {filteredDetailedLogs.length === 0 ? (
            <div className="empty-state">
              <i className="fa-solid fa-satellite-dish"></i>
              <p>Sem atividade registada</p>
              <span className="empty-hint">Os logs aparecem em tempo real quando há tráfego</span>
            </div>
          ) : (
            <table className="traffic-table wireshark-table">
              <thead>
                <tr>
                  <th>Hora</th>
                  <th>Tipo</th>
                  <th>IP</th>
                  <th>Método</th>
                  <th>Caminho</th>
                  <th>Estado</th>
                  <th>Localização</th>
                  <th>Informação</th>
                </tr>
              </thead>
              <tbody>
                {filteredDetailedLogs.map((entry) => (
                  <tr key={entry.id} className={getDetailedRowClass(entry)}>
                    <td className="col-time-ws">{formatTimeWS(entry.timestamp)}</td>
                    <td>
                      <span className={`type-badge type-${entry._type === 'threat' ? 'threat' : entry.method === 'PAGE' ? 'page' : 'request'}`}>
                        <i className={`fa-solid ${getTypeIcon(entry)}`}></i>
                        {getTypeLabel(entry)}
                      </span>
                    </td>
                    <td className="col-ip"><code>{entry.ip}</code></td>
                    <td>
                      {entry._type === 'threat' ? (
                        <span className={`event-badge event-${entry.event}`}>
                          <i className={`fa-solid ${getEventIcon(entry.event || '')}`}></i>
                          {getEventLabel(entry.event || '')}
                        </span>
                      ) : (
                        <span className={`method-badge ${getMethodClass(entry.method)}`}>
                          {entry.method}
                        </span>
                      )}
                    </td>
                    <td className="col-path" title={entry.path}>{entry.path}</td>
                    <td>
                      {entry._type === 'threat' ? (
                        <span className={`severity-badge ${getSeverityClass(entry.severity || '')}`}>
                          {(entry.severity || '').toUpperCase()}
                        </span>
                      ) : (
                        <span className={`status-badge ${getStatusClass(entry.status_code)}`}>
                          {entry.status_code}
                        </span>
                      )}
                    </td>
                    <td className="col-location">
                      {entry.country || '—'}
                      {entry.city ? `, ${entry.city}` : ''}
                    </td>
                    <td className="col-info">
                      {entry._type === 'threat' ? (
                        <div className="threat-info">
                          <span className="threat-detail">{entry.details}</span>
                          {entry.auto_blocked && (
                            <span className="auto-blocked-badge">
                              <i className="fa-solid fa-robot"></i>
                              Auto-bloqueado
                            </span>
                          )}
                        </div>
                      ) : (
                        <div className="request-info">
                          {entry.response_time_ms > 0 && (
                            <span className="response-time">{entry.response_time_ms}ms</span>
                          )}
                          {entry.is_vpn && (
                            <span className="vpn-badge small">VPN</span>
                          )}
                          {entry.method === 'PAGE' && !entry.is_vpn && (
                            <span className="info-label-page">
                              <i className="fa-solid fa-eye"></i> Visita de página
                            </span>
                          )}
                          {entry.method !== 'PAGE' && entry.response_time_ms === 0 && !entry.is_vpn && (
                            <span className="info-label-api">
                              <i className="fa-solid fa-server"></i> API call
                            </span>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ═══════════════════════════════════════════════ */}
      {/* TAB 3: IPs BLOQUEADOS                          */}
      {/* ═══════════════════════════════════════════════ */}
      {!isLoading && activeTab === 'blocked' && (
        <div className="traffic-table-wrapper">
          {blocked.length === 0 ? (
            <div className="empty-state">
              <i className="fa-solid fa-unlock"></i>
              <p>Nenhum IP bloqueado</p>
            </div>
          ) : (
            <table className="traffic-table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>País</th>
                  <th>Motivo</th>
                  <th>Bloqueado por</th>
                  <th>Requests</th>
                  <th>Data</th>
                  <th>Ações</th>
                </tr>
              </thead>
              <tbody>
                {blocked.map((b) => (
                  <tr key={b.id}>
                    <td className="col-ip">
                      <code>{b.ip}</code>
                      {b.is_vpn && <span className="vpn-badge small">VPN</span>}
                    </td>
                    <td>{b.country || '—'}</td>
                    <td className="col-reason">{b.reason}</td>
                    <td>
                      <span className={`blocker-badge ${b.blocked_by === 'system' ? 'auto' : 'manual'}`}>
                        {b.blocked_by === 'system' ? '🤖 Auto' : '👤 Manual'}
                      </span>
                    </td>
                    <td>{b.request_count}</td>
                    <td className="col-time">{formatTime(b.created_at)}</td>
                    <td className="col-actions">
                      <button
                        className="action-btn unblock-btn"
                        onClick={() => handleUnblock(b.ip)}
                        title="Desbloquear"
                      >
                        <i className="fa-solid fa-unlock"></i>
                      </button>
                      {b.log_snapshot && (
                        <button
                          className="action-btn download-btn"
                          onClick={() => downloadSnapshot(b.log_snapshot, b.ip)}
                          title="Download logs"
                        >
                          <i className="fa-solid fa-download"></i>
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ═══ BLOCK MODAL ═══ */}
      {showBlockModal && (
        <div className="modal-overlay" onClick={() => setShowBlockModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>
              <i className="fa-solid fa-ban"></i>
              Bloquear IP
            </h3>
            <p className="modal-ip">{blockTargetIp}</p>
            <div className="modal-field">
              <label>Motivo do bloqueio</label>
              <textarea
                value={blockReason}
                onChange={(e) => setBlockReason(e.target.value)}
                placeholder="Ex: Atividade suspeita, tentativas de brute force..."
                rows={3}
                autoFocus
              />
            </div>
            <div className="modal-actions">
              <button className="modal-cancel" onClick={() => setShowBlockModal(false)}>
                Cancelar
              </button>
              <button
                className="modal-confirm"
                onClick={handleBlock}
                disabled={!blockReason.trim() || actionLoading}
              >
                {actionLoading ? (
                  <i className="fa-solid fa-spinner fa-spin"></i>
                ) : (
                  <i className="fa-solid fa-ban"></i>
                )}
                Bloquear
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
