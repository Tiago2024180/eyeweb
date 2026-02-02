'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import './health.css';

interface ServiceStatus {
  name: string;
  status: 'online' | 'offline' | 'degraded' | 'unknown';
  response_time_ms: number | null;
  message: string | null;
  details: Record<string, any> | null;
  category: string | null;
  url: string | null;
}

interface HealthCheckResponse {
  overall_status: 'healthy' | 'degraded' | 'critical' | 'unknown';
  timestamp: string;
  services: ServiceStatus[];
  summary: {
    online: number;
    offline: number;
    degraded: number;
    unknown: number;
  };
  categories: Record<string, ServiceStatus[]>;
}

export default function HealthMonitorPage() {
  const router = useRouter();
  const [healthData, setHealthData] = useState<HealthCheckResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());

  const fetchHealthData = useCallback(async () => {
    try {
      setError(null);
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/admin/health-check`);
      
      if (!response.ok) {
        throw new Error(`Erro ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      setHealthData(data);
      setLastUpdate(new Date());
      
      // Expandir todas as categorias por defeito
      if (data.categories) {
        setExpandedCategories(new Set(Object.keys(data.categories)));
      }
    } catch (err: any) {
      console.error('Erro ao obter dados de saúde:', err);
      setError(err.message || 'Erro ao conectar ao backend');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHealthData();
  }, [fetchHealthData]);

  useEffect(() => {
    if (!autoRefresh) return;
    
    const interval = setInterval(() => {
      fetchHealthData();
    }, 30000);
    
    return () => clearInterval(interval);
  }, [autoRefresh, fetchHealthData]);

  const toggleCategory = (category: string) => {
    setExpandedCategories(prev => {
      const newSet = new Set(prev);
      if (newSet.has(category)) {
        newSet.delete(category);
      } else {
        newSet.add(category);
      }
      return newSet;
    });
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'online':
        return <i className="fa-solid fa-circle-check status-icon online"></i>;
      case 'offline':
        return <i className="fa-solid fa-circle-xmark status-icon offline"></i>;
      case 'degraded':
        return <i className="fa-solid fa-circle-exclamation status-icon degraded"></i>;
      default:
        return <i className="fa-solid fa-circle-question status-icon unknown"></i>;
    }
  };

  const getOverallStatusClass = (status: string) => {
    switch (status) {
      case 'healthy': return 'overall-healthy';
      case 'degraded': return 'overall-degraded';
      case 'critical': return 'overall-critical';
      default: return 'overall-unknown';
    }
  };

  const getOverallStatusText = (status: string) => {
    switch (status) {
      case 'healthy': return 'Sistemas operacionais';
      case 'degraded': return 'Alguns serviços com problemas';
      case 'critical': return 'Serviços críticos offline';
      default: return 'Estado desconhecido';
    }
  };

  const getCategoryIcon = (category: string) => {
    const icons: Record<string, string> = {
      'Backend': 'fa-server',
      'Supabase': 'fa-database',
      'Hugging Face': 'fa-brain',
      'APIs Externas': 'fa-plug',
      'Infraestrutura': 'fa-cloud',
    };
    return icons[category] || 'fa-folder';
  };

  const getCategoryStatus = (services: ServiceStatus[]) => {
    const hasOffline = services.some(s => s.status === 'offline');
    const hasDegraded = services.some(s => s.status === 'degraded');
    const allOnline = services.every(s => s.status === 'online');
    
    if (hasOffline) return 'offline';
    if (hasDegraded) return 'degraded';
    if (allOnline) return 'online';
    return 'unknown';
  };

  const formatResponseTime = (ms: number | null) => {
    if (ms === null) return '-';
    if (ms < 100) return `${ms.toFixed(0)}ms`;
    if (ms < 1000) return `${ms.toFixed(0)}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  };

  // Ordenar categorias
  const categoryOrder = ['Backend', 'Supabase', 'Hugging Face', 'APIs Externas', 'Infraestrutura'];
  const sortedCategories = healthData?.categories 
    ? Object.entries(healthData.categories).sort(([a], [b]) => {
        const indexA = categoryOrder.indexOf(a);
        const indexB = categoryOrder.indexOf(b);
        return (indexA === -1 ? 999 : indexA) - (indexB === -1 ? 999 : indexB);
      })
    : [];

  return (
    <div className="health-container">
      {/* Header */}
      <div className="health-header">
        <button className="back-btn" onClick={() => router.push('/admin')}>
          <i className="fa-solid fa-arrow-left"></i>
          Voltar
        </button>
        <h1>
          <i className="fa-solid fa-heart-pulse"></i>
          Monitor de Saúde
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
          <button 
            className="refresh-btn" 
            onClick={() => { setIsLoading(true); fetchHealthData(); }}
            disabled={isLoading}
          >
            <i className={`fa-solid fa-rotate ${isLoading ? 'fa-spin' : ''}`}></i>
            Atualizar
          </button>
        </div>
      </div>

      {/* Overall Status */}
      {healthData && (
        <div className={`overall-status ${getOverallStatusClass(healthData.overall_status)}`}>
          <div className="overall-info">
            <h2>{getOverallStatusText(healthData.overall_status)}</h2>
            <div className="stats-row">
              <span className="stat-item online">
                <i className="fa-solid fa-circle"></i>
                Online: {healthData.summary.online}
              </span>
              <span className="stat-item offline">
                <i className="fa-solid fa-circle"></i>
                Offline: {healthData.summary.offline}
              </span>
              <span className="stat-item degraded">
                <i className="fa-solid fa-circle"></i>
                Degradado: {healthData.summary.degraded}
              </span>
              <span className="stat-item unknown">
                <i className="fa-solid fa-circle"></i>
                Desconhecido: {healthData.summary.unknown}
              </span>
            </div>
          </div>
          {lastUpdate && (
            <div className="last-update">
              Atualizado: {lastUpdate.toLocaleTimeString('pt-PT')}
            </div>
          )}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="health-error">
          <i className="fa-solid fa-triangle-exclamation"></i>
          <span>{error}</span>
        </div>
      )}

      {/* Loading */}
      {isLoading && !healthData && (
        <div className="health-loading">
          <i className="fa-solid fa-spinner fa-spin"></i>
          <span>A verificar serviços...</span>
        </div>
      )}

      {/* Categories */}
      {healthData && (
        <div className="categories-container">
          {sortedCategories.map(([category, services]) => {
            const categoryStatus = getCategoryStatus(services);
            const isExpanded = expandedCategories.has(category);
            const onlineCount = services.filter(s => s.status === 'online').length;
            
            return (
              <div key={category} className={`category-section ${categoryStatus}`}>
                <div 
                  className="category-header"
                  onClick={() => toggleCategory(category)}
                >
                  <div className="category-info">
                    <div className="category-icon-wrapper">
                      <i className={`fa-solid ${getCategoryIcon(category)}`}></i>
                    </div>
                    <h3>{category}</h3>
                    <span className="category-count">
                      {onlineCount}/{services.length} online
                    </span>
                  </div>
                  <div className="category-status">
                    {getStatusIcon(categoryStatus)}
                    <i className={`fa-solid fa-chevron-${isExpanded ? 'up' : 'down'} expand-icon`}></i>
                  </div>
                </div>
                
                {isExpanded && (
                  <div className="category-services">
                    {services.map((service, index) => (
                      <div key={index} className={`service-item ${service.status}`}>
                        <div className="service-main">
                          <div className="service-name">
                            {getStatusIcon(service.status)}
                            <span>{service.name}</span>
                            {service.url && (
                              <a 
                                href={service.url} 
                                target="_blank" 
                                rel="noopener noreferrer"
                                className="service-link"
                                title="Verificar manualmente"
                                onClick={(e) => e.stopPropagation()}
                              >
                                <i className="fa-solid fa-arrow-up-right-from-square"></i>
                              </a>
                            )}
                          </div>
                          <div className="service-time">
                            {formatResponseTime(service.response_time_ms)}
                          </div>
                        </div>
                        
                        {service.message && (
                          <div className="service-message">
                            {service.message}
                          </div>
                        )}
                        
                        {service.details && Object.keys(service.details).length > 0 && (
                          <div className="service-details">
                            {Object.entries(service.details).map(([key, value]) => (
                              <span key={key} className="detail-tag">
                                {key}: {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
