'use client';

import { useState } from 'react';
import { checkPasswordStrength } from '@/lib/api';

export default function PasswordChecker() {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [result, setResult] = useState<{
    score: number;
    feedback: string[];
    level: 'weak' | 'medium' | 'strong' | 'very-strong';
  } | null>(null);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setPassword(value);
    
    if (value) {
      setResult(checkPasswordStrength(value));
    } else {
      setResult(null);
    }
  };

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'weak': return 'var(--danger)';
      case 'medium': return 'var(--warning)';
      case 'strong': return 'var(--success)';
      case 'very-strong': return '#00ff88';
      default: return 'var(--gray)';
    }
  };

  const getLevelText = (level: string) => {
    switch (level) {
      case 'weak': return 'Fraca';
      case 'medium': return 'Média';
      case 'strong': return 'Forte';
      case 'very-strong': return 'Muito Forte';
      default: return '';
    }
  };

  const getLevelBadgeClass = (level: string) => {
    switch (level) {
      case 'weak': return 'danger';
      case 'medium': return 'warning';
      case 'strong':
      case 'very-strong': return 'safe';
      default: return '';
    }
  };

  return (
    <div className="card">
      <div className="input-group" style={{ position: 'relative' }}>
        <input
          type={showPassword ? 'text' : 'password'}
          className="input"
          placeholder="Introduz uma password para verificar..."
          value={password}
          onChange={handleChange}
          style={{ paddingRight: '3rem' }}
        />
        <button
          type="button"
          onClick={() => setShowPassword(!showPassword)}
          style={{
            position: 'absolute',
            right: '0.75rem',
            top: '50%',
            transform: 'translateY(-50%)',
            background: 'none',
            border: 'none',
            color: 'var(--gray)',
            cursor: 'pointer',
            padding: '0.5rem',
          }}
        >
          <i className={`fa-solid ${showPassword ? 'fa-eye-slash' : 'fa-eye'}`}></i>
        </button>
      </div>

      {result && (
        <div className="result-container">
          <span className={`status-badge ${getLevelBadgeClass(result.level)}`}>
            {getLevelText(result.level)}
          </span>
          
          {/* Barra de força */}
          <div style={{ 
            marginTop: '1rem', 
            marginBottom: '1rem',
            background: 'var(--bg)', 
            borderRadius: '4px', 
            height: '8px',
            overflow: 'hidden'
          }}>
            <div style={{
              width: `${(result.score / 10) * 100}%`,
              height: '100%',
              background: getLevelColor(result.level),
              transition: 'width 0.3s, background 0.3s',
            }}></div>
          </div>
          
          <p style={{ color: 'var(--gray)', marginBottom: '0.5rem' }}>
            Pontuação: {result.score}/10
          </p>

          {result.feedback.length > 0 && (
            <>
              <h4 style={{ marginTop: '1rem', marginBottom: '0.5rem' }}>Sugestões:</h4>
              <ul style={{ paddingLeft: '1.25rem', color: 'var(--gray)' }}>
                {result.feedback.map((tip, idx) => (
                  <li key={idx} style={{ marginBottom: '0.25rem' }}>{tip}</li>
                ))}
              </ul>
            </>
          )}

          {result.level === 'very-strong' && (
            <p style={{ marginTop: '1rem', color: 'var(--success)' }}>
              ✨ Excelente! Esta password é muito segura.
            </p>
          )}
        </div>
      )}

      <p style={{ color: 'var(--gray)', fontSize: '0.8rem', marginTop: '1rem', textAlign: 'center' }}>
        🔐 Verificação 100% local - a password nunca sai do teu dispositivo
      </p>
    </div>
  );
}
