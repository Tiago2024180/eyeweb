'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import './traffic.css';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

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

interface Stats {
  requests_24h: number;
  active_ips_5m: number;
  suspicious_24h: number;
  blocked_total: number;
}

type Tab = 'logs' | 'suspicious' | 'blocked';

// ═══════════════════════════════════════════════════════
// COMPONENT
// ═══════════════════════════════════════════════════════

export default function TrafficMonitorPage() {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<Tab>('logs');
  const [logs, setLogs] = useState<TrafficLog[]>([]);
  const [suspicious, setSuspicious] = useState<SuspiciousEvent[]>([]);
  const [blocked, setBlocked] = useState<BlockedIP[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Block modal
  const [showBlockModal, setShowBlockModal] = useState(false);
  const [blockTargetIp, setBlockTargetIp] = useState('');
  const [blockReason, setBlockReason] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  // ─── FETCH FUNCTIONS ─────────────────────────────────

  const fetchStats = useCallback(async () => {
    try {
      const r = await fetch(`${API}/api/admin/traffic/stats`);
      if (r.ok) setStats(await r.json());
    } catch {}
  }, []);

  const fetchLogs = useCallback(async () => {
    try {
      setError(null);
      const r = await fetch(`${API}/api/admin/traffic/logs?limit=100`);
      if (r.ok) {
        const data = await r.json();
        setLogs(data.logs || []);
      }
    } catch {
      setError('Erro ao carregar logs de tráfego');
    } finally {
      setIsLoading(false);
    }
  }, []);

  const fetchSuspicious = useCallback(async () => {
    try {
      setError(null);
      const r = await fetch(`${API}/api/admin/traffic/suspicious?limit=100`);
      if (r.ok) {
        const data = await r.json();
        setSuspicious(data.events || []);
      }
    } catch {
      setError('Erro ao carregar atividade suspeita');
    } finally {
      setIsLoading(false);
    }
  }, []);

  const fetchBlocked = useCallback(async () => {
    try {
      setError(null);
      const r = await fetch(`${API}/api/admin/traffic/blocked`);
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
    fetchLogs();
  }, [fetchStats, fetchLogs]);

  // Tab change
  useEffect(() => {
    setIsLoading(true);
    if (activeTab === 'logs') fetchLogs();
    else if (activeTab === 'suspicious') fetchSuspicious();
    else fetchBlocked();
  }, [activeTab, fetchLogs, fetchSuspicious, fetchBlocked]);

  // Auto-refresh
  useEffect(() => {
    if (!autoRefresh) return;
    const ms = activeTab === 'logs' ? 3000 : activeTab === 'suspicious' ? 5000 : 10000;
    const interval = setInterval(() => {
      fetchStats();
      if (activeTab === 'logs') fetchLogs();
      else if (activeTab === 'suspicious') fetchSuspicious();
      else fetchBlocked();
    }, ms);
    return () => clearInterval(interval);
  }, [autoRefresh, activeTab, fetchStats, fetchLogs, fetchSuspicious, fetchBlocked]);

  // ─── ACTIONS ─────────────────────────────────────────

  const handleBlock = async () => {
    if (!blockTargetIp || !blockReason.trim()) return;
    setActionLoading(true);
    try {
      const r = await fetch(`${API}/api/admin/traffic/block-ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: blockTargetIp, reason: blockReason }),
      });
      if (r.ok) {
        setShowBlockModal(false);
        setBlockTargetIp('');
        setBlockReason('');
        fetchStats();
        fetchBlocked();
        if (activeTab === 'logs') fetchLogs();
      }
    } catch {} finally {
      setActionLoading(false);
    }
  };

  const handleUnblock = async (ip: string) => {
    if (!confirm(`Desbloquear o IP ${ip}?`)) return;
    try {
      await fetch(`${API}/api/admin/traffic/unblock-ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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
              <div className="stat-value">{stats.requests_24h.toLocaleString()}</div>
              <div className="stat-label">Requests (24h)</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-icon"><i className="fa-solid fa-users"></i></div>
            <div className="stat-info">
              <div className="stat-value">{stats.active_ips_5m}</div>
              <div className="stat-label">IPs Ativos (5min)</div>
            </div>
          </div>
          <div className="stat-card stat-warning">
            <div className="stat-icon"><i className="fa-solid fa-triangle-exclamation"></i></div>
            <div className="stat-info">
              <div className="stat-value">{stats.suspicious_24h}</div>
              <div className="stat-label">Suspeitos (24h)</div>
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
          className={`tab-btn ${activeTab === 'suspicious' ? 'active' : ''}`}
          onClick={() => setActiveTab('suspicious')}
        >
          <i className="fa-solid fa-triangle-exclamation"></i>
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
      {/* TAB 1: LOGS (Conexões em tempo real)            */}
      {/* ═══════════════════════════════════════════════ */}
      {!isLoading && activeTab === 'logs' && (
        <div className="traffic-table-wrapper">
          {logs.length === 0 ? (
            <div className="empty-state">
              <i className="fa-solid fa-inbox"></i>
              <p>Sem logs de tráfego registados</p>
            </div>
          ) : (
            <table className="traffic-table">
              <thead>
                <tr>
                  <th>Hora</th>
                  <th>IP</th>
                  <th>Localização</th>
                  <th>Método</th>
                  <th>Path</th>
                  <th>Status</th>
                  <th>VPN</th>
                  <th>Tempo</th>
                  <th>Ações</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr
                    key={log.id}
                    className={
                      blockedSet.has(log.ip) ? 'row-blocked' : log.is_vpn ? 'row-vpn' : ''
                    }
                  >
                    <td className="col-time">{formatTime(log.created_at)}</td>
                    <td className="col-ip"><code>{log.ip}</code></td>
                    <td className="col-location">
                      {log.country || '—'}
                      {log.city ? `, ${log.city}` : ''}
                    </td>
                    <td>
                      <span className={`method-badge ${getMethodClass(log.method)}`}>
                        {log.method}
                      </span>
                    </td>
                    <td className="col-path" title={log.path}>{log.path}</td>
                    <td>
                      <span className={`status-badge status-${Math.floor(log.status_code / 100)}xx`}>
                        {log.status_code}
                      </span>
                    </td>
                    <td>
                      {log.is_vpn ? (
                        <span className="vpn-badge" title={log.vpn_provider || 'VPN/Proxy detetado'}>
                          <i className="fa-solid fa-mask"></i> VPN
                        </span>
                      ) : (
                        <span className="no-vpn">—</span>
                      )}
                    </td>
                    <td className="col-time-ms">{log.response_time_ms}ms</td>
                    <td className="col-actions">
                      {!blockedSet.has(log.ip) && log.ip !== '127.0.0.1' && (
                        <button
                          className="action-btn block-btn"
                          onClick={() => openBlockModal(log.ip)}
                          title="Bloquear IP"
                        >
                          <i className="fa-solid fa-ban"></i>
                        </button>
                      )}
                      {blockedSet.has(log.ip) && (
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
      {/* TAB 2: LOGS DETALHADOS (Atividade Suspeita)    */}
      {/* ═══════════════════════════════════════════════ */}
      {!isLoading && activeTab === 'suspicious' && (
        <div className="traffic-table-wrapper">
          {suspicious.length === 0 ? (
            <div className="empty-state">
              <i className="fa-solid fa-shield-halved"></i>
              <p>Sem atividade suspeita detetada</p>
              <span className="empty-hint">O sistema de defesa está a monitorizar o tráfego</span>
            </div>
          ) : (
            <table className="traffic-table">
              <thead>
                <tr>
                  <th>Hora</th>
                  <th>IP</th>
                  <th>Evento</th>
                  <th>Severidade</th>
                  <th>Detalhes</th>
                  <th>Path</th>
                  <th>Ações</th>
                </tr>
              </thead>
              <tbody>
                {suspicious.map((evt) => (
                  <tr key={evt.id} className={`severity-row ${getSeverityClass(evt.severity)}`}>
                    <td className="col-time">{formatTime(evt.created_at)}</td>
                    <td className="col-ip"><code>{evt.ip}</code></td>
                    <td>
                      <span className={`event-badge event-${evt.event}`}>
                        <i className={`fa-solid ${getEventIcon(evt.event)}`}></i>
                        {getEventLabel(evt.event)}
                      </span>
                    </td>
                    <td>
                      <span className={`severity-badge ${getSeverityClass(evt.severity)}`}>
                        {evt.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="col-details">{evt.details}</td>
                    <td className="col-path" title={evt.path}>{evt.path}</td>
                    <td className="col-actions">
                      {!blockedSet.has(evt.ip) ? (
                        <button
                          className="action-btn block-btn"
                          onClick={() => openBlockModal(evt.ip)}
                          title="Bloquear IP"
                        >
                          <i className="fa-solid fa-ban"></i>
                        </button>
                      ) : (
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
