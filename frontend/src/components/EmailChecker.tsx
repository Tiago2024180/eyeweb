'use client';

import { useState } from 'react';
import { checkEmailBreach, BreachInfo } from '@/lib/api';
import BreachResults from './BreachResults';

export default function EmailChecker() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{
    found: boolean;
    breaches: BreachInfo[];
    searched: boolean;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!email.trim()) return;
    
    setLoading(true);
    setError(null);
    setResult(null);
    
    try {
      const data = await checkEmailBreach(email);
      setResult({
        found: data.found,
        breaches: data.breaches,
        searched: true,
      });
    } catch (err) {
      console.error('Error checking email:', err);
      setError('Erro ao verificar. Tenta novamente mais tarde.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <form onSubmit={handleSubmit}>
        <div className="input-group">
          <input
            type="email"
            className="input"
            placeholder="Introduz o teu email..."
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>
        <button type="submit" className="btn" disabled={loading || !email.trim()}>
          {loading ? 'A verificar...' : 'Verificar Email'}
        </button>
      </form>

      {loading && (
        <div className="loading">
          <div className="spinner"></div>
          <span>A procurar em fugas de dados...</span>
        </div>
      )}

      {error && (
        <div className="result-container">
          <p style={{ color: 'var(--danger)' }}>{error}</p>
        </div>
      )}

      {result && result.searched && !loading && (
        <BreachResults 
          found={result.found} 
          breaches={result.breaches} 
          type="email"
        />
      )}

      <p style={{ color: 'var(--gray)', fontSize: '0.8rem', marginTop: '1rem', textAlign: 'center' }}>
        🔒 A tua privacidade está protegida com K-Anonymity
      </p>
    </div>
  );
}
