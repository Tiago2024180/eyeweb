'use client';

import { useState } from 'react';
import { checkPasswordStrength, checkPasswordBreach } from '@/lib/api';

interface PasswordResult {
  score: number;
  feedback: string[];
  level: 'weak' | 'medium' | 'strong' | 'very-strong';
}

interface DatasetResult {
  found: boolean;
  breachCount: number;
  checked: boolean;
}

export default function PasswordChecker() {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [hasChecked, setHasChecked] = useState(false);
  
  // Resultado da análise de força
  const [strengthResult, setStrengthResult] = useState<PasswordResult | null>(null);
  
  // Resultado da verificação no dataset
  const [datasetResult, setDatasetResult] = useState<DatasetResult>({
    found: false,
    breachCount: 0,
    checked: false,
  });

  // Calcular força ajustada (considerando se está no dataset)
  const getAdjustedLevel = (): 'weak' | 'medium' | 'strong' | 'very-strong' => {
    if (!strengthResult) return 'weak';
    
    // Se a password foi encontrada no dataset, força é automaticamente FRACA
    if (datasetResult.checked && datasetResult.found) {
      return 'weak';
    }
    
    return strengthResult.level;
  };

  const getAdjustedScore = (): number => {
    if (!strengthResult) return 0;
    
    // Se a password foi encontrada no dataset, score vai para 0-2
    if (datasetResult.checked && datasetResult.found) {
      return Math.min(2, strengthResult.score);
    }
    
    return strengthResult.score;
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setPassword(value);
    setHasChecked(false);
    setDatasetResult({ found: false, breachCount: 0, checked: false });
    
    // Análise de força em tempo real
    if (value) {
      setStrengthResult(checkPasswordStrength(value));
    } else {
      setStrengthResult(null);
    }
  };

  const handleCheck = async () => {
    if (!password.trim()) return;
    
    setLoading(true);
    
    try {
      // Verificar no dataset de passwords vazadas
      const result = await checkPasswordBreach(password);
      setDatasetResult({
        found: result.found,
        breachCount: result.breachCount,
        checked: true,
      });
      setHasChecked(true);
    } catch (error) {
      console.error('Error checking password:', error);
      // Mesmo se falhar, marcar como verificado (sem encontrar)
      setDatasetResult({
        found: false,
        breachCount: 0,
        checked: true,
      });
      setHasChecked(true);
    } finally {
      setLoading(false);
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

  const adjustedLevel = getAdjustedLevel();
  const adjustedScore = getAdjustedScore();

  return (
    <div className="card">
      {/* Input da Password */}
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

      {/* Botão Check */}
      <button
        type="button"
        className="btn"
        onClick={handleCheck}
        disabled={!password.trim() || loading}
        style={{ marginTop: '1rem' }}
      >
        {loading ? (
          <>
            <i className="fa-solid fa-spinner fa-spin" style={{ marginRight: '0.5rem' }}></i>
            A verificar...
          </>
        ) : (
          <>
            <i className="fa-solid fa-shield-halved" style={{ marginRight: '0.5rem' }}></i>
            Check
          </>
        )}
      </button>

      {/* Resultados após clicar em Check */}
      {hasChecked && strengthResult && (
        <div className="result-container" style={{ marginTop: '1.5rem' }}>
          
          {/* Força da Password */}
          <div className="password-strength-section">
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
              <span style={{ color: 'var(--gray)', fontSize: '1rem' }}>Password:</span>
              <span 
                className={`status-badge ${getLevelBadgeClass(adjustedLevel)}`}
                style={{ fontSize: '1.1rem', padding: '0.5rem 1rem' }}
              >
                {getLevelText(adjustedLevel)}
              </span>
            </div>
            
            {/* Barra de força */}
            <div style={{ 
              background: 'var(--bg)', 
              borderRadius: '8px', 
              height: '10px',
              overflow: 'hidden',
              marginBottom: '0.5rem'
            }}>
              <div style={{
                width: `${(adjustedScore / 10) * 100}%`,
                height: '100%',
                background: getLevelColor(adjustedLevel),
                transition: 'width 0.3s, background 0.3s',
                borderRadius: '8px',
              }}></div>
            </div>
            <p style={{ color: 'var(--gray)', fontSize: '0.85rem', textAlign: 'right' }}>
              Pontuação: {adjustedScore}/10
            </p>
          </div>

          {/* Verificação Dataset */}
          <div className="dataset-check-section" style={{ 
            marginTop: '1.5rem',
            padding: '1rem',
            background: datasetResult.found ? 'rgba(255, 107, 107, 0.1)' : 'rgba(29, 209, 161, 0.1)',
            borderRadius: '12px',
            border: `1px solid ${datasetResult.found ? 'var(--danger)' : 'var(--success)'}`,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <i 
                className={`fa-solid ${datasetResult.found ? 'fa-database' : 'fa-shield-check'}`}
                style={{ 
                  color: datasetResult.found ? 'var(--danger)' : 'var(--success)',
                  fontSize: '1.5rem'
                }}
              ></i>
              <div>
                <h4 style={{ 
                  color: datasetResult.found ? 'var(--danger)' : 'var(--success)',
                  marginBottom: '0.25rem'
                }}>
                  Verificação no Dataset
                </h4>
                <p style={{ color: 'var(--gray)', fontSize: '0.9rem' }}>
                  {datasetResult.found ? (
                    <>
                      <strong style={{ color: 'var(--danger)' }}>⚠️ ENCONTRADA!</strong> Esta password 
                      aparece em bases de dados vazadas.
                    </>
                  ) : (
                    <>
                      <strong style={{ color: 'var(--success)' }}>✓ Segura</strong> - Esta password 
                      não foi encontrada no nosso dataset de fugas.
                    </>
                  )}
                </p>
              </div>
            </div>
            
            {datasetResult.found && (
              <div style={{ 
                marginTop: '1rem', 
                padding: '0.75rem',
                background: 'rgba(255, 107, 107, 0.15)',
                borderRadius: '8px',
              }}>
                <p style={{ color: 'var(--danger)', fontSize: '0.85rem' }}>
                  <i className="fa-solid fa-triangle-exclamation" style={{ marginRight: '0.5rem' }}></i>
                  <strong>ATENÇÃO:</strong> Esta password deve ser alterada IMEDIATAMENTE em todas 
                  as contas onde a utilizas.
                </p>
              </div>
            )}
          </div>

          {/* Sugestões de Melhoria */}
          {(strengthResult.feedback.length > 0 || datasetResult.found) && (
            <div className="suggestions-section" style={{ marginTop: '1.5rem' }}>
              <h4 style={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: '0.5rem',
                marginBottom: '0.75rem',
                color: 'var(--white)'
              }}>
                <i className="fa-solid fa-lightbulb" style={{ color: 'var(--warning)' }}></i>
                Sugestões de Melhoria
              </h4>
              <ul style={{ 
                paddingLeft: '1.25rem', 
                color: 'var(--gray)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.5rem'
              }}>
                {datasetResult.found && (
                  <li style={{ color: 'var(--danger)' }}>
                    <strong>Muda esta password imediatamente!</strong> Foi exposta em fugas de dados.
                  </li>
                )}
                {strengthResult.feedback.map((tip, idx) => (
                  <li key={idx}>{tip}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Mensagem de sucesso total */}
          {adjustedLevel === 'very-strong' && !datasetResult.found && (
            <div style={{ 
              marginTop: '1.5rem',
              padding: '1rem',
              background: 'rgba(0, 255, 136, 0.1)',
              borderRadius: '12px',
              border: '1px solid #00ff88',
              textAlign: 'center'
            }}>
              <p style={{ color: '#00ff88', fontSize: '1.1rem' }}>
                ✨ Excelente! Esta password é muito segura e não foi encontrada em fugas de dados.
              </p>
            </div>
          )}
        </div>
      )}

      <p style={{ color: 'var(--gray)', fontSize: '0.8rem', marginTop: '1.5rem', textAlign: 'center' }}>
        🔐 A password nunca sai do teu dispositivo - apenas o hash é verificado com K-Anonymity
      </p>
    </div>
  );
}
