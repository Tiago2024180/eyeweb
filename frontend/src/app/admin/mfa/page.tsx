'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { supabase } from '@/lib/supabase';
import './mfa.css';

export default function AdminMFAPage() {
  const router = useRouter();
  const [code, setCode] = useState(['', '', '', '', '', '']);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [pendingLogin, setPendingLogin] = useState<{ email: string; password: string } | null>(null);
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // Verificar se há login pendente
  useEffect(() => {
    const stored = sessionStorage.getItem('admin_pending_login');
    if (!stored) {
      // Sem login pendente, voltar para login
      router.push('/login');
      return;
    }

    try {
      const parsed = JSON.parse(stored);
      setPendingLogin(parsed);
    } catch {
      router.push('/login');
    }
  }, [router]);

  // Focar no primeiro input ao carregar
  useEffect(() => {
    if (inputRefs.current[0]) {
      inputRefs.current[0].focus();
    }
  }, []);

  // Lidar com input de cada dígito
  const handleInputChange = (index: number, value: string) => {
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
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    
    if (pastedData.length === 6) {
      const newCode = pastedData.split('');
      setCode(newCode);
      inputRefs.current[5]?.focus();
      handleVerify(pastedData);
    }
  };

  // Verificar código MFA
  const handleVerify = async (fullCode?: string) => {
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
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/admin/verify-mfa`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: pendingLogin.email,
          code: codeToVerify,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Código inválido');
      }

      // Código válido - fazer login real
      const { error: signInError } = await supabase.auth.signInWithPassword({
        email: pendingLogin.email,
        password: pendingLogin.password,
      });

      if (signInError) {
        throw signInError;
      }

      // Limpar dados temporários
      sessionStorage.removeItem('admin_pending_login');

      // Redirecionar para admin
      router.push('/admin');

    } catch (err: any) {
      console.error('MFA verification error:', err);
      
      // Limpar código
      setCode(['', '', '', '', '', '']);
      inputRefs.current[0]?.focus();
      
      if (err.message.includes('inválido') || err.message.includes('invalid')) {
        setError('Código inválido. Tenta novamente.');
      } else if (err.message.includes('expirado') || err.message.includes('expired')) {
        setError('Código expirado. Gera um novo código.');
      } else {
        setError(err.message || 'Erro ao verificar código. Tenta novamente.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  // Cancelar e voltar para login
  const handleCancel = () => {
    sessionStorage.removeItem('admin_pending_login');
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
          <div className="mfa-icon">
            <i className="fa-solid fa-shield-halved"></i>
          </div>
          <h1>Autenticação MFA</h1>
          <p>Introduz o código de 6 dígitos gerado pela aplicação Eye Web Auth</p>
        </div>

        {/* Erro */}
        {error && (
          <div className="mfa-error">
            <i className="fa-solid fa-circle-exclamation"></i>
            <span>{error}</span>
          </div>
        )}

        {/* Inputs do código */}
        <div className="mfa-code-inputs" onPaste={handlePaste}>
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
              disabled={isLoading}
              className={error ? 'error' : ''}
              autoComplete="off"
            />
          ))}
        </div>

        {/* Info */}
        <div className="mfa-info">
          <i className="fa-solid fa-info-circle"></i>
          <span>O código é válido por 30 segundos</span>
        </div>

        {/* Botões */}
        <div className="mfa-actions">
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
          
          <button 
            className="mfa-btn-cancel"
            onClick={handleCancel}
            disabled={isLoading}
          >
            <i className="fa-solid fa-arrow-left"></i>
            Cancelar
          </button>
        </div>

        {/* Ajuda */}
        <div className="mfa-help">
          <p>
            <i className="fa-solid fa-desktop"></i>
            Abre a aplicação <strong>Eye Web Auth</strong> no teu computador para obter o código
          </p>
        </div>
      </div>
    </div>
  );
}
