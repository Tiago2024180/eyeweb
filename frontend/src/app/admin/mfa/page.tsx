'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { supabase } from '@/lib/supabase';
import './mfa.css';

export default function AdminMFAPage() {
  const router = useRouter();
  const [code, setCode] = useState(['', '', '', '', '', '']); // 6 dígitos
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [strikes, setStrikes] = useState(0);
  const [isBanned, setIsBanned] = useState(false);
  const [banTimeLeft, setBanTimeLeft] = useState<string | null>(null);
  const [pendingLogin, setPendingLogin] = useState<{ email: string; password: string } | null>(null);
  const [timeLeft, setTimeLeft] = useState(120); // 2 minutos em segundos
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // Verificar se há login pendente OU se já está autenticado
  useEffect(() => {
    const checkAuth = async () => {
      const email = sessionStorage.getItem('admin_pending_email');
      const password = sessionStorage.getItem('admin_pending_password');
      
      // Se tem login pendente, usar esse
      if (email && password) {
        setPendingLogin({ email, password });
      } else {
        // Verificar se já está autenticado
        const { data: { user } } = await supabase.auth.getUser();
        
        if (!user) {
          // Sem login pendente e sem sessão, voltar para login
          window.location.href = '/login';
          return;
        }
        
        // Já está autenticado, só precisa verificar MFA
        // Não precisa de pending login
        setPendingLogin({ email: user.email || '', password: '' });
      }
      
      // Verificar se está banido (localStorage para persistir)
      const banData = localStorage.getItem('admin_mfa_ban');
      if (banData) {
        const { until } = JSON.parse(banData);
        const banUntil = new Date(until);
        
        if (banUntil > new Date()) {
          setIsBanned(true);
          updateBanTimeLeft(banUntil);
        } else {
          // Ban expirou
          localStorage.removeItem('admin_mfa_ban');
          localStorage.removeItem('admin_mfa_strikes');
        }
      }
      
      // Carregar strikes
      const savedStrikes = localStorage.getItem('admin_mfa_strikes');
      if (savedStrikes) {
        setStrikes(parseInt(savedStrikes, 10));
      }
    };
    
    checkAuth();
  }, []);

  // Atualizar tempo restante do ban
  const updateBanTimeLeft = (banUntil: Date) => {
    const update = () => {
      const now = new Date();
      const diff = banUntil.getTime() - now.getTime();
      
      if (diff <= 0) {
        setIsBanned(false);
        setBanTimeLeft(null);
        localStorage.removeItem('admin_mfa_ban');
        localStorage.removeItem('admin_mfa_strikes');
        setStrikes(0);
        return;
      }
      
      const days = Math.floor(diff / (1000 * 60 * 60 * 24));
      const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((diff % (1000 * 60)) / 1000);
      
      if (days > 0) {
        setBanTimeLeft(`${days}d ${hours}h ${minutes}m`);
      } else if (hours > 0) {
        setBanTimeLeft(`${hours}h ${minutes}m ${seconds}s`);
      } else {
        setBanTimeLeft(`${minutes}m ${seconds}s`);
      }
    };
    
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  };

  // Countdown de 2 minutos (apenas se veio do login, não se já estava autenticado)
  useEffect(() => {
    if (!pendingLogin || isBanned || !pendingLogin.password) return;
    
    const timer = setInterval(() => {
      setTimeLeft((prev) => {
        if (prev <= 1) {
          // Tempo esgotado - limpar e voltar para home
          clearInterval(timer);
          sessionStorage.removeItem('admin_pending_email');
          sessionStorage.removeItem('admin_pending_password');
          window.location.href = '/';
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    
    return () => clearInterval(timer);
  }, [pendingLogin, isBanned]);

  // Formatar tempo restante
  const formatTimeLeft = () => {
    const minutes = Math.floor(timeLeft / 60);
    const seconds = timeLeft % 60;
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
  };

  // Focar no primeiro input ao carregar
  useEffect(() => {
    if (inputRefs.current[0] && !isBanned) {
      inputRefs.current[0].focus();
    }
  }, [isBanned, pendingLogin]);

  // Lidar com input de cada dígito
  const handleInputChange = (index: number, value: string) => {
    if (isBanned) return;
    
    // Apenas números
    if (value && !/^\d$/.test(value)) return;

    const newCode = [...code];
    newCode[index] = value;
    setCode(newCode);
    setError(null);

    // Mover para próximo input
    if (value && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }

    // Se todos os dígitos preenchidos, verificar automaticamente
    if (value && index === 5) {
      const fullCode = newCode.join('');
      if (fullCode.length === 6) {
        handleVerify(fullCode);
      }
    }
  };

  // Lidar com teclas especiais
  const handleKeyDown = (index: number, e: React.KeyboardEvent) => {
    if (isBanned) return;
    
    if (e.key === 'Backspace' && !code[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
    
    // Permitir colar
    if (e.key === 'v' && (e.ctrlKey || e.metaKey)) {
      return;
    }
  };

  // Lidar com colar
  const handlePaste = (e: React.ClipboardEvent) => {
    if (isBanned) return;
    
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    
    if (pastedData.length === 6) {
      const newCode = pastedData.split('');
      setCode(newCode);
      inputRefs.current[5]?.focus();
      handleVerify(pastedData);
    }
  };

  // Gerar fingerprint do dispositivo (simples)
  const getFingerprint = (): string => {
    const nav = navigator;
    const screen = window.screen;
    const data = [
      nav.userAgent,
      nav.language,
      screen.width,
      screen.height,
      screen.colorDepth,
      new Date().getTimezoneOffset(),
    ].join('|');
    
    // Hash simples
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  };

  // Aplicar ban de 3 dias
  const applyBan = () => {
    const banUntil = new Date();
    banUntil.setDate(banUntil.getDate() + 3); // 3 dias
    
    const banData = {
      until: banUntil.toISOString(),
      fingerprint: getFingerprint(),
    };
    
    localStorage.setItem('admin_mfa_ban', JSON.stringify(banData));
    setIsBanned(true);
    updateBanTimeLeft(banUntil);
  };

  // Verificar código MFA
  const handleVerify = async (fullCode?: string) => {
    if (isBanned) return;
    
    const codeToVerify = fullCode || code.join('');
    
    if (codeToVerify.length !== 6) {
      setError('Introduz o código completo de 6 dígitos.');
      return;
    }

    if (!pendingLogin) {
      setError('Sessão expirada. Por favor, faz login novamente.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      // Verificar código MFA com o backend
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/admin/verify-mfa`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: pendingLogin.email,
          code: codeToVerify,
          fingerprint: getFingerprint(),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        // Código inválido - incrementar strikes
        const newStrikes = strikes + 1;
        setStrikes(newStrikes);
        localStorage.setItem('admin_mfa_strikes', newStrikes.toString());
        
        if (newStrikes >= 2) {
          // 2 falhas = BAN de 3 dias
          applyBan();
          throw new Error('Muitas tentativas falhadas. Conta bloqueada por 3 dias.');
        }
        
        throw new Error(data.detail || `Código inválido. ${2 - newStrikes} tentativa(s) restante(s).`);
      }

      // Código válido - se temos password pendente, fazer login real
      // Se não (já autenticado), apenas continuar
      if (pendingLogin.password) {
        const { error: signInError } = await supabase.auth.signInWithPassword({
          email: pendingLogin.email,
          password: pendingLogin.password,
        });

        if (signInError) {
          throw signInError;
        }
      }

      // Limpar dados temporários e strikes
      sessionStorage.removeItem('admin_pending_email');
      sessionStorage.removeItem('admin_pending_password');
      localStorage.removeItem('admin_mfa_strikes');

      // Marcar MFA como verificado (válido até fazer logout)
      sessionStorage.setItem('mfa_verified', 'true');

      // Redirecionar para admin (usar window.location para refresh completo)
      window.location.href = '/admin';

    } catch (err: any) {
      console.error('MFA verification error:', err);
      
      // Limpar código
      setCode(['', '', '', '', '', '']);
      if (!isBanned) {
        inputRefs.current[0]?.focus();
      }
      
      setError(err.message || 'Erro ao verificar código. Tenta novamente.');
    } finally {
      setIsLoading(false);
    }
  };

  // Cancelar e voltar para login
  const handleCancel = () => {
    sessionStorage.removeItem('admin_pending_email');
    sessionStorage.removeItem('admin_pending_password');
    router.push('/login');
  };

  if (!pendingLogin) {
    return (
      <div className="mfa-container">
        <div className="mfa-loading">
          <i className="fa-solid fa-spinner fa-spin"></i>
          <span>A carregar...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="mfa-container">
      <div className="mfa-card">
        {/* Header */}
        <div className="mfa-header">
          <h1>Eye Web MFA</h1>
        </div>

        {/* Ban message */}
        {isBanned && (
          <div className="mfa-banned">
            <i className="fa-solid fa-ban"></i>
            <div>
              <strong>Acesso Bloqueado</strong>
              <p>Demasiadas tentativas falhadas. Tenta novamente em:</p>
              <span className="ban-timer">{banTimeLeft}</span>
            </div>
          </div>
        )}

        {/* Erro */}
        {error && !isBanned && (
          <div className="mfa-error">
            <i className="fa-solid fa-circle-exclamation"></i>
            <span>{error}</span>
          </div>
        )}

        {/* Strikes indicator */}
        {!isBanned && strikes > 0 && (
          <div className="mfa-strikes">
            <i className="fa-solid fa-triangle-exclamation"></i>
            <span>{strikes}/2 tentativas falhadas</span>
          </div>
        )}

        {/* Inputs do código - 10 dígitos */}
        <div className={`mfa-code-inputs ${isBanned ? 'disabled' : ''}`} onPaste={handlePaste}>
          {code.map((digit, index) => (
            <input
              key={index}
              ref={(el) => { inputRefs.current[index] = el; }}
              type="text"
              inputMode="numeric"
              maxLength={1}
              value={digit}
              onChange={(e) => handleInputChange(index, e.target.value)}
              onKeyDown={(e) => handleKeyDown(index, e)}
              disabled={isLoading || isBanned}
              className={error ? 'error' : ''}
              autoComplete="off"
            />
          ))}
        </div>

        {/* Countdown - só mostrar se veio do login (tem password pendente) */}
        {!isBanned && pendingLogin?.password && (
          <div className={`mfa-countdown ${timeLeft <= 30 ? 'warning' : ''}`}>
            <i className="fa-solid fa-clock"></i>
            <span>Tempo restante: <strong>{formatTimeLeft()}</strong></span>
          </div>
        )}

        {/* Botões */}
        <div className="mfa-actions">
          {!isBanned && (
            <button 
              className="mfa-btn-verify"
              onClick={() => handleVerify()}
              disabled={isLoading || code.join('').length !== 6}
            >
              {isLoading ? (
                <>
                  <i className="fa-solid fa-spinner fa-spin"></i>
                  A verificar...
                </>
              ) : (
                <>
                  <i className="fa-solid fa-check"></i>
                  Verificar
                </>
              )}
            </button>
          )}
          
          <button 
            className="mfa-btn-cancel"
            onClick={handleCancel}
            disabled={isLoading}
          >
            <i className="fa-solid fa-arrow-left"></i>
            {isBanned ? 'Voltar' : 'Cancelar'}
          </button>
        </div>

        {/* Reset de emergência - clicar 5x no título quando bloqueado */}
        {isBanned && (
          <div 
            className="mfa-emergency-reset"
            onClick={() => {
              const clicks = parseInt(sessionStorage.getItem('emergency_clicks') || '0') + 1;
              sessionStorage.setItem('emergency_clicks', clicks.toString());
              if (clicks >= 5) {
                localStorage.removeItem('admin_mfa_ban');
                localStorage.removeItem('admin_mfa_strikes');
                sessionStorage.removeItem('emergency_clicks');
                window.location.reload();
              }
            }}
            title="Reset de emergência"
          >
            <span style={{ opacity: 0.2, fontSize: '0.7rem', cursor: 'pointer' }}>⚙️</span>
          </div>
        )}

      </div>
    </div>
  );
}
