'use client';

import { useState, useEffect } from 'react';
import { fetchDatasetExplorer, DatasetRow } from '@/lib/api';

export default function DatasetExplorer() {
  const [rows, setRows] = useState<DatasetRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [total, setTotal] = useState(0);
  const [repo, setRepo] = useState('');
  const [sortField, setSortField] = useState<keyof DatasetRow>('checkedAt');
  const [sortAsc, setSortAsc] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchDatasetExplorer();
      setRows(data.rows || []);
      setTotal(data.total || 0);
      setRepo(data.repo || '');
    } catch (err) {
      console.error('Dataset Explorer error:', err);
      setError('Erro ao carregar dados do dataset.');
    } finally {
      setLoading(false);
    }
  };

  const handleSort = (field: keyof DatasetRow) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(true);
    }
  };

  const sortedRows = [...rows].sort((a, b) => {
    const aVal = a[sortField] ?? '';
    const bVal = b[sortField] ?? '';
    if (typeof aVal === 'number' && typeof bVal === 'number') {
      return sortAsc ? aVal - bVal : bVal - aVal;
    }
    const cmp = String(aVal).localeCompare(String(bVal));
    return sortAsc ? cmp : -cmp;
  });

  const SortIcon = ({ field }: { field: keyof DatasetRow }) => {
    if (sortField !== field) return <span style={{ opacity: 0.3, marginLeft: '4px' }}>↕</span>;
    return <span style={{ marginLeft: '4px' }}>{sortAsc ? '↑' : '↓'}</span>;
  };

  return (
    <div className="card" style={{ maxWidth: '800px', padding: '1.5rem' }}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '1rem',
        }}
      >
        <h3 style={{ margin: 0, fontSize: '1.1rem' }}>
          📊 Dataset Explorer
        </h3>
        <button
          onClick={loadData}
          disabled={loading}
          style={{
            padding: '0.35rem 0.75rem',
            borderRadius: '4px',
            border: '1px solid var(--gray)',
            background: 'transparent',
            color: 'var(--gray)',
            cursor: 'pointer',
            fontSize: '0.8rem',
            transition: 'all 0.2s',
          }}
        >
          {loading ? '⏳' : '🔄'} Atualizar
        </button>
      </div>

      {repo && (
        <p style={{ fontSize: '0.75rem', color: 'var(--gray)', marginBottom: '1rem' }}>
          Dataset:{' '}
          <a
            href={`https://huggingface.co/datasets/${repo}`}
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: 'var(--blue)', textDecoration: 'none' }}
          >
            {repo}
          </a>
          {' '}• {total} registo{total !== 1 ? 's' : ''}
        </p>
      )}

      {loading && (
        <div className="loading">
          <div className="spinner"></div>
          <span>A carregar dataset...</span>
        </div>
      )}

      {error && (
        <p style={{ color: 'var(--danger)', textAlign: 'center' }}>{error}</p>
      )}

      {!loading && !error && rows.length === 0 && (
        <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--gray)' }}>
          <p>Nenhum registo encontrado no dataset.</p>
          <p style={{ fontSize: '0.85rem', marginTop: '0.5rem' }}>
            Os registos são adicionados automaticamente quando verificas domínios.
          </p>
        </div>
      )}

      {!loading && rows.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table
            style={{
              width: '100%',
              borderCollapse: 'collapse',
              fontSize: '0.8rem',
            }}
          >
            <thead>
              <tr>
                {[
                  { key: 'domain' as keyof DatasetRow, label: 'Domínio' },
                  { key: 'breachName' as keyof DatasetRow, label: 'Breach' },
                  { key: 'breachDate' as keyof DatasetRow, label: 'Data' },
                  { key: 'pwnCount' as keyof DatasetRow, label: 'Afetados' },
                  { key: 'checkedAt' as keyof DatasetRow, label: 'Verificado' },
                ].map((col) => (
                  <th
                    key={col.key}
                    onClick={() => handleSort(col.key)}
                    style={{
                      padding: '0.6rem',
                      textAlign: 'left',
                      borderBottom: '2px solid var(--border)',
                      color: 'var(--white)',
                      cursor: 'pointer',
                      userSelect: 'none',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {col.label}
                    <SortIcon field={col.key} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sortedRows.map((row, idx) => (
                <tr
                  key={idx}
                  style={{
                    borderBottom: '1px solid var(--border)',
                    transition: 'background 0.15s',
                  }}
                  onMouseEnter={(e) =>
                    (e.currentTarget.style.background = 'rgba(255,255,255,0.03)')
                  }
                  onMouseLeave={(e) =>
                    (e.currentTarget.style.background = 'transparent')
                  }
                >
                  <td
                    style={{
                      padding: '0.5rem 0.6rem',
                      color: 'var(--blue)',
                      fontWeight: 600,
                    }}
                  >
                    {row.domain}
                  </td>
                  <td style={{ padding: '0.5rem 0.6rem', color: 'var(--white)' }}>
                    {row.breachName || row.breachTitle || '—'}
                  </td>
                  <td style={{ padding: '0.5rem 0.6rem', color: 'var(--gray)' }}>
                    {row.breachDate || '—'}
                  </td>
                  <td style={{ padding: '0.5rem 0.6rem', color: 'var(--warning)' }}>
                    {row.pwnCount
                      ? row.pwnCount.toLocaleString('pt-PT')
                      : '—'}
                  </td>
                  <td style={{ padding: '0.5rem 0.6rem', color: 'var(--gray)', fontSize: '0.75rem' }}>
                    {row.checkedAt
                      ? new Date(row.checkedAt).toLocaleDateString('pt-PT')
                      : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
