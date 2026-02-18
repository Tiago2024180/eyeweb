'use client';

import { useState } from 'react';
import { searchNews, NewsSearchResult, NewsArticle } from '@/lib/api';

export default function NewsSearch() {
  const [query, setQuery] = useState('');
  const [searchType, setSearchType] = useState<'domain' | 'email' | 'url'>('domain');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<NewsSearchResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await searchNews(query, searchType);
      setResult(data);
    } catch (err) {
      console.error('News search error:', err);
      setError('Erro ao pesquisar notícias. Tenta novamente mais tarde.');
    } finally {
      setLoading(false);
    }
  };

  const getAiBadge = (article: NewsArticle) => {
    const ai = article.aiClassification;
    if (!ai) return null;

    const color = ai.isSecurityRelated
      ? ai.securityScore >= 70
        ? '#ff4444'
        : '#ffaa00'
      : '#4ade80';

    const label = ai.isSecurityRelated
      ? ai.topLabel.replace('cybersecurity ', '').replace(' or ', '/')
      : 'Não relacionado';

    return (
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.3rem',
          padding: '0.2rem 0.6rem',
          borderRadius: '12px',
          fontSize: '0.7rem',
          fontWeight: 600,
          background: `${color}22`,
          color: color,
          border: `1px solid ${color}44`,
          whiteSpace: 'nowrap',
        }}
      >
        🤖 {label} ({ai.securityScore}%)
      </span>
    );
  };

  const formatDate = (dateStr: string) => {
    if (!dateStr) return '';
    try {
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return dateStr;
      return d.toLocaleDateString('pt-PT', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      });
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="card" style={{ maxWidth: '600px' }}>
      <form onSubmit={handleSubmit}>
        {/* Search type selector */}
        <div
          style={{
            display: 'flex',
            gap: '0.5rem',
            marginBottom: '0.75rem',
            justifyContent: 'center',
          }}
        >
          {(['domain', 'email', 'url'] as const).map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setSearchType(t)}
              style={{
                padding: '0.35rem 0.75rem',
                borderRadius: '4px',
                border: `1px solid ${searchType === t ? 'var(--blue)' : 'var(--gray)'}`,
                background: searchType === t ? 'var(--blue)' : 'transparent',
                color: searchType === t ? '#fff' : 'var(--gray)',
                cursor: 'pointer',
                fontSize: '0.85rem',
                transition: 'all 0.2s',
              }}
            >
              {t === 'domain' ? '🌐 Domínio' : t === 'email' ? '📧 Email' : '🔗 URL'}
            </button>
          ))}
        </div>

        <div className="input-group">
          <input
            type="text"
            className="input"
            placeholder={
              searchType === 'email'
                ? 'ex: user@empresa.com'
                : searchType === 'url'
                ? 'ex: https://empresa.com/login'
                : 'ex: facebook.com'
            }
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            disabled={loading}
            required
          />
        </div>
        <button type="submit" className="btn" disabled={!query.trim() || loading}>
          {loading ? '🔄 A pesquisar...' : '🔍 Pesquisar Notícias'}
        </button>
      </form>

      {loading && (
        <div className="loading">
          <div className="spinner"></div>
          <span>A pesquisar em 14+ fontes de notícias...</span>
        </div>
      )}

      {error && (
        <div className="result-container">
          <p style={{ color: 'var(--danger)' }}>{error}</p>
        </div>
      )}

      {result && !loading && (
        <div className="result-container">
          {/* Summary header */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: '1rem',
              flexWrap: 'wrap',
              gap: '0.5rem',
            }}
          >
            <h3 style={{ margin: 0 }}>
              {result.totalResults} resultado{result.totalResults !== 1 ? 's' : ''} encontrado{result.totalResults !== 1 ? 's' : ''}
            </h3>
            {result.aiEnabled && (
              <span
                style={{
                  padding: '0.25rem 0.6rem',
                  borderRadius: '12px',
                  fontSize: '0.7rem',
                  background: 'rgba(59, 130, 246, 0.15)',
                  color: '#3b82f6',
                  border: '1px solid rgba(59, 130, 246, 0.3)',
                }}
              >
                🤖 IA Ativa
              </span>
            )}
          </div>

          {/* Sources breakdown */}
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '0.5rem',
              marginBottom: '1.25rem',
              fontSize: '0.75rem',
              color: 'var(--gray)',
            }}
          >
            <span>Google: {result.sourcesSearched.googleNews}</span>
            <span>|</span>
            <span>Bing: {result.sourcesSearched.bingNews}</span>
            <span>|</span>
            <span>GDELT: {result.sourcesSearched.gdelt}</span>
            <span>|</span>
            <span>RSS: {result.sourcesSearched.securityRSS}</span>
          </div>

          {/* Results list */}
          {result.results.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--gray)' }}>
              <p>Nenhuma notícia de cibersegurança encontrada para esta pesquisa.</p>
              <p style={{ fontSize: '0.85rem', marginTop: '0.5rem' }}>
                Isto pode significar que não há incidentes conhecidos reportados.
              </p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {result.results.map((article, idx) => (
                <a
                  key={idx}
                  href={article.link}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: 'block',
                    padding: '0.75rem',
                    background: 'var(--bg)',
                    borderRadius: '6px',
                    borderLeft: `3px solid ${
                      article.aiClassification?.isSecurityRelated
                        ? article.aiClassification.securityScore >= 70
                          ? 'var(--danger)'
                          : 'var(--warning)'
                        : 'var(--gray)'
                    }`,
                    textDecoration: 'none',
                    color: 'inherit',
                    transition: 'border-color 0.2s, background 0.2s',
                  }}
                >
                  {/* Title + AI Badge */}
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'flex-start',
                      gap: '0.5rem',
                      marginBottom: '0.35rem',
                    }}
                  >
                    <h4
                      style={{
                        margin: 0,
                        fontSize: '0.9rem',
                        color: 'var(--white)',
                        lineHeight: 1.4,
                      }}
                    >
                      {article.title}
                    </h4>
                    {getAiBadge(article)}
                  </div>

                  {/* Snippet */}
                  {article.snippet && (
                    <p
                      style={{
                        color: 'var(--gray)',
                        fontSize: '0.8rem',
                        margin: '0.25rem 0',
                        lineHeight: 1.5,
                        display: '-webkit-box',
                        WebkitLineClamp: 2,
                        WebkitBoxOrient: 'vertical',
                        overflow: 'hidden',
                      }}
                    >
                      {article.snippet}
                    </p>
                  )}

                  {/* Source + Date */}
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.75rem',
                      marginTop: '0.35rem',
                      fontSize: '0.7rem',
                      color: 'var(--gray)',
                    }}
                  >
                    <span style={{ fontWeight: 600 }}>{article.source}</span>
                    {article.pubDate && <span>{formatDate(article.pubDate)}</span>}
                  </div>
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
