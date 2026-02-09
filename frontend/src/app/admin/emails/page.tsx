'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import './emails.css';

interface Subscriber {
  email: string;
  display_name: string | null;
  subscribed_at: string | null;
}

interface SubscribersResponse {
  total_subscribers: number;
  subscribers: Subscriber[];
}

interface BroadcastResponse {
  success: boolean;
  message: string;
  total_recipients: number;
  successful_sends: number;
  failed_sends: number;
  failed_emails: string[] | null;
}

export default function EmailManagerPage() {
  const router = useRouter();
  const { isAuthenticated, isAdmin, loading } = useAuth();
  const [activeTab, setActiveTab] = useState<'compose' | 'subscribers'>('compose');
  
  // Verificar MFA da sessão
  const isMfaVerified = () => {
    if (typeof window === 'undefined') return false;
    return localStorage.getItem('mfa_verified') === 'true';
  };
  
  // Redirecionar se não autenticado, não admin, ou MFA não verificado
  useEffect(() => {
    if (loading) return;
    
    if (!isAuthenticated) {
      router.push('/login');
      return;
    }
    
    if (!isAdmin) {
      router.push('/perfil');
      return;
    }
    
    if (!isMfaVerified()) {
      router.push('/admin/mfa');
      return;
    }
  }, [isAuthenticated, isAdmin, loading, router]);
  
  // Estado do formulário
  const [subject, setSubject] = useState('');
  const [message, setMessage] = useState('');
  const [testMode, setTestMode] = useState(true);
  const [isSending, setIsSending] = useState(false);
  const [sendResult, setSendResult] = useState<BroadcastResponse | null>(null);
  const [isFadingOut, setIsFadingOut] = useState(false);
  
  // Estado dos subscritores
  const [subscribers, setSubscribers] = useState<Subscriber[]>([]);
  const [totalSubscribers, setTotalSubscribers] = useState(0);
  const [isLoadingSubscribers, setIsLoadingSubscribers] = useState(false);
  
  // Carregar subscritores
  const loadSubscribers = async () => {
    setIsLoadingSubscribers(true);
    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/admin/emails/subscribers`
      );
      
      if (response.ok) {
        const data: SubscribersResponse = await response.json();
        setSubscribers(data.subscribers);
        setTotalSubscribers(data.total_subscribers);
      }
    } catch (error) {
      console.error('Erro ao carregar subscritores:', error);
    } finally {
      setIsLoadingSubscribers(false);
    }
  };
  
  useEffect(() => {
    loadSubscribers();
  }, []);
  
  // Enviar email
  const handleSendEmail = async () => {
    if (!subject.trim() || !message.trim()) {
      alert('Preenche o assunto e a mensagem');
      return;
    }
    
    setIsSending(true);
    setSendResult(null);
    
    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/admin/emails/broadcast`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            subject: subject.trim(),
            message: message.trim(),
            test_mode: testMode,
          }),
        }
      );
      
      const data: BroadcastResponse = await response.json();
      setSendResult(data);
      
      // Iniciar fade out após 1.5 segundos
      setTimeout(() => {
        setIsFadingOut(true);
        // Limpar formulário após a animação (0.5s)
        setTimeout(() => {
          setSubject('');
          setMessage('');
          setSendResult(null);
          setIsFadingOut(false);
        }, 500);
      }, 1500);
    } catch (error) {
      console.error('Erro ao enviar email:', error);
      setSendResult({
        success: false,
        message: 'Erro de conexão ao servidor',
        total_recipients: 0,
        successful_sends: 0,
        failed_sends: 0,
        failed_emails: null,
      });
    } finally {
      setIsSending(false);
    }
  };
  
  // Formatar data
  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleDateString('pt-PT', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };
  
  // Não mostrar nada enquanto verifica autenticação
  if (loading || !isAuthenticated || !isAdmin || !isMfaVerified()) {
    return null;
  }
  
  return (
    <div className="emails-container">
      {/* Botão Voltar - Canto superior esquerdo */}
      <div className="back-btn-wrapper">
        <button className="back-btn" onClick={() => router.push('/admin')}>
          <i className="fa-solid fa-arrow-left"></i>
          Voltar
        </button>
      </div>
      
      {/* Header */}
      <div className="emails-header">
        <h1>
          <i className="fa-solid fa-envelope"></i>
          Gestor de E-Mails
        </h1>
        <div className="header-stats">
          <span className="stat-badge">
            <i className="fa-solid fa-users"></i>
            {totalSubscribers} subscritores
          </span>
        </div>
      </div>
      
      {/* Tabs */}
      <div className="emails-tabs">
        <button 
          className={`tab-btn ${activeTab === 'compose' ? 'active' : ''}`}
          onClick={() => setActiveTab('compose')}
        >
          Escrever Email
        </button>
        <button 
          className={`tab-btn ${activeTab === 'subscribers' ? 'active' : ''}`}
          onClick={() => setActiveTab('subscribers')}
        >
          Subscritores
        </button>
      </div>
      
      {/* Content */}
      <div className="emails-content">
        {activeTab === 'compose' ? (
          <div className="compose-section">
            <div className="compose-card">
              <h2>Enviar E-mails</h2>
              
              {/* Modo de envio */}
              <div className="send-mode-toggle">
                <label className={`mode-option ${testMode ? 'active' : ''}`}>
                  <input
                    type="radio"
                    name="sendMode"
                    checked={testMode}
                    onChange={() => setTestMode(true)}
                  />
                  <span>Modo Teste</span>
                  <small>Envia apenas para ti</small>
                </label>
                <label className={`mode-option ${!testMode ? 'active' : ''}`}>
                  <input
                    type="radio"
                    name="sendMode"
                    checked={!testMode}
                    onChange={() => setTestMode(false)}
                  />
                  <span>Enviar a Todos</span>
                  <small>Envia para todos os subscritores</small>
                </label>
              </div>
              
              {/* Formulário */}
              <div className="compose-form">
                <div className="form-group">
                  <label htmlFor="subject">
                    <i className="fa-solid fa-heading"></i>
                    Assunto
                  </label>
                  <input
                    id="subject"
                    type="text"
                    placeholder="Assunto do comunicado"
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    maxLength={100}
                  />
                  <span className="char-count">{subject.length}/100</span>
                </div>
                
                <div className="form-group">
                  <label htmlFor="message">
                    <i className="fa-solid fa-message"></i>
                    Mensagem
                  </label>
                  <textarea
                    id="message"
                    placeholder="Escreva a sua mensagem."
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    rows={10}
                  />
                  <small className="form-hint">
                    A sua mensagem suporta HTML básico: &lt;strong&gt;, &lt;em&gt;, &lt;br&gt;, &lt;p&gt;, &lt;ul&gt;, &lt;li&gt;
                  </small>
                </div>
                
                {/* Resultado */}
                {sendResult && (
                  <div className={`send-result ${sendResult.success ? 'success' : 'error'} ${isFadingOut ? 'fade-out' : ''}`}>
                    <div className="result-content">
                      <strong>Emails enviados: {sendResult.successful_sends}/{sendResult.total_recipients}</strong>
                      {sendResult.failed_sends > 0 && (
                        <span>Erro: {sendResult.failed_sends} email(s) não enviado(s)</span>
                      )}
                    </div>
                  </div>
                )}
                
                {/* Botão de enviar */}
                <button 
                  className="send-btn"
                  onClick={handleSendEmail}
                  disabled={isSending || !subject.trim() || !message.trim()}
                >
                  {isSending ? (
                    <>
                      <div className="spinner-small"></div>
                      A enviar...
                    </>
                  ) : (
                    <>
                      <i className="fa-solid fa-paper-plane"></i>
                      Enviar Email
                    </>
                  )}
                </button>
                
                {!testMode && (
                  <p className="warning-text-simple">
                    Este email será enviado para todos os subscritores.
                  </p>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="subscribers-section">
            <div className="subscribers-card">
              <div className="subscribers-header">
                <h2>Lista de Subscritores</h2>
                <button 
                  className="refresh-btn"
                  onClick={loadSubscribers}
                  disabled={isLoadingSubscribers}
                >
                  <i className={`fa-solid fa-rotate ${isLoadingSubscribers ? 'fa-spin' : ''}`}></i>
                </button>
              </div>
              
              {isLoadingSubscribers ? (
                <div className="loading-state">
                  <div className="spinner"></div>
                  <p>A carregar subscritores...</p>
                </div>
              ) : subscribers.length === 0 ? (
                <div className="empty-state">
                  <i className="fa-solid fa-inbox"></i>
                  <p>Nenhum subscritor encontrado</p>
                </div>
              ) : (
                <div className="subscribers-table-wrapper">
                  <table className="subscribers-table">
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Email</th>
                        <th>Nome</th>
                        <th>Registado em</th>
                      </tr>
                    </thead>
                    <tbody>
                      {subscribers.map((sub, index) => (
                        <tr key={sub.email}>
                          <td className="row-number">{index + 1}</td>
                          <td className="email-cell">
                            {sub.email}
                          </td>
                          <td className="name-cell">
                            {sub.display_name || <span className="no-name">Sem nome</span>}
                          </td>
                          <td className="date-cell">
                            {formatDate(sub.subscribed_at)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
