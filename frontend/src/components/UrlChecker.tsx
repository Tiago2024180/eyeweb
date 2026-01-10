'use client';

import { useState } from 'react';
import { checkUrlSecurity } from '@/lib/api';

export default function UrlChecker() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<{
    safe: boolean;
    warnings: string[];
    details: { https: boolean; suspiciousTLD: boolean; ipAddress: boolean };
    checked: boolean;
  } | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!url.trim()) return;
    
    const data = checkUrlSecurity(url);
    setResult({ ...data, checked: true });
  };

  return (
    <div className="card">
      <form onSubmit={handleSubmit}>
        <div className="input-group">
          <input
            type="text"
            className="input"
            placeholder="Introduz um URL para verificar..."
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            required
          />
        </div>
        <button type="submit" className="btn" disabled={!url.trim()}>
          Verificar URL
        </button>
      </form>

      {result && result.checked && (
        <div className="result-container">
          {result.safe ? (
            <div className="no-breaches">
              <div className="icon">🔒</div>
              <span className="status-badge safe">URL Seguro</span>
              <p>Não foram detetados indicadores suspeitos.</p>
            </div>
          ) : (
            <>
              <span className="status-badge warning">
                <i className="fa-solid fa-triangle-exclamation"></i> Avisos Detetados
              </span>
              <h3>Problemas encontrados:</h3>
              {result.warnings.map((warning, idx) => (
                <div key={idx} className="breach-item" style={{ borderLeftColor: 'var(--warning)' }}>
                  <p><i className="fa-solid fa-exclamation-circle" style={{ color: 'var(--warning)' }}></i> {warning}</p>
                </div>
              ))}
            </>
          )}
          
          <div style={{ marginTop: '1rem', fontSize: '0.9rem', color: 'var(--gray)' }}>
            <p><strong>Detalhes:</strong></p>
            <p>• HTTPS: {result.details.https ? '✅ Sim' : '❌ Não'}</p>
            <p>• TLD Suspeito: {result.details.suspiciousTLD ? '⚠️ Sim' : '✅ Não'}</p>
            <p>• IP Direto: {result.details.ipAddress ? '⚠️ Sim' : '✅ Não'}</p>
          </div>
        </div>
      )}

      <p style={{ color: 'var(--gray)', fontSize: '0.8rem', marginTop: '1rem', textAlign: 'center' }}>
        🛡️ Verificação feita localmente - nenhum dado enviado
      </p>
    </div>
  );
}
