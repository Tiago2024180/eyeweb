'use client';

import { useEffect, useState, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import { supabase } from '@/lib/supabase';
import './admin.css';

// Tipos para as secções
type AdminSection = 'menu' | 'emails' | 'health' | 'traffic' | 'chat';

export default function AdminDashboardPage() {
  console.log('🔴 Admin Page Component Mounted');
  const router = useRouter();
  const { user, profile, isAuthenticated, isAdmin, loading, logout, refreshProfile } = useAuth();
  const [mfaVerified, setMfaVerified] = useState(false);
  const [checkingMfa, setCheckingMfa] = useState(true);
  const [currentSection, setCurrentSection] = useState<AdminSection>('menu');
  const [profileOpen, setProfileOpen] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [isEditingName, setIsEditingName] = useState(false);
  const [editedName, setEditedName] = useState('');
  const [nameError, setNameError] = useState('');
  const [nameSuccess, setNameSuccess] = useState(false);
  const [profileTimeout, setProfileTimeout] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const nameInputRef = useRef<HTMLInputElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Verificar MFA
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const verified = sessionStorage.getItem('mfa_verified') === 'true';
      const verifiedAt = sessionStorage.getItem('mfa_verified_at');
      
      if (verified && verifiedAt) {
        const expiryTime = 60 * 60 * 1000; // 1 hora
        const isExpired = Date.now() - parseInt(verifiedAt) > expiryTime;
        
        if (!isExpired) {
          setMfaVerified(true);
        } else {
          sessionStorage.removeItem('mfa_verified');
          sessionStorage.removeItem('mfa_verified_at');
        }
      }
      
      setCheckingMfa(false);
    }
  }, []);

  // Timeout para profile - não ficar preso para sempre
  useEffect(() => {
    if (!loading && !profile && isAuthenticated) {
      const timer = setTimeout(() => {
        setProfileTimeout(true);
      }, 5000); // 5 segundos
      
      return () => clearTimeout(timer);
    }
  }, [loading, profile, isAuthenticated]);

  // Fechar dropdown ao clicar fora
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setProfileOpen(false);
        if (isEditingName) {
          setIsEditingName(false);
          setEditedName('');
          setNameError('');
          setNameSuccess(false);
        }
      }
    };

    if (profileOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [profileOpen, isEditingName]);

  // Redirecionar se não autenticado ou não admin
  useEffect(() => {
    // Esperar que loading termine
    if (loading || checkingMfa) return;
    
    // Se não autenticado, ir para login
    if (!isAuthenticated) {
      window.location.href = '/login';
      return;
    }
    
    // Se profile ainda não carregou, esperar
    if (!profile) return;
    
    // Se não é admin, ir para perfil
    if (!isAdmin) {
      window.location.href = '/perfil';
      return;
    }
    
    // Se MFA não verificado, ir para MFA
    if (!mfaVerified) {
      window.location.href = '/admin/mfa';
      return;
    }
  }, [isAuthenticated, isAdmin, profile, loading, checkingMfa, mfaVerified]);

  const handleLogout = async () => {
    sessionStorage.removeItem('mfa_verified');
    sessionStorage.removeItem('mfa_verified_at');
    await logout();
    router.push('/login');
  };

  // Upload de avatar
  const handleAvatarUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !user) return;

    // Validações
    if (!file.type.startsWith('image/')) {
      alert('Por favor seleciona uma imagem válida');
      return;
    }

    if (file.size > 2 * 1024 * 1024) {
      alert('A imagem deve ter no máximo 2MB');
      return;
    }

    setIsUploading(true);
    console.log('📸 Iniciando upload de avatar...');

    try {
      const fileExt = file.name.split('.').pop();
      const fileName = `${user.id}-${Date.now()}.${fileExt}`;
      const filePath = `${fileName}`; // Sem subpasta

      // Upload para Supabase Storage
      const { error: uploadError, data: uploadData } = await supabase.storage
        .from('avatars')
        .upload(filePath, file, {
          cacheControl: '3600',
          upsert: true
        });

      if (uploadError) {
        console.error('❌ Upload error:', uploadError);
        alert('Erro ao fazer upload: ' + uploadError.message);
        setIsUploading(false);
        return;
      }

      console.log('✅ Upload concluído:', uploadData);

      // Obter URL pública
      const { data: { publicUrl } } = supabase.storage
        .from('avatars')
        .getPublicUrl(filePath);

      console.log('🔗 URL pública:', publicUrl);

      // Atualizar perfil na base de dados
      const { error: updateError } = await supabase
        .from('profiles')
        .update({ avatar_url: publicUrl })
        .eq('id', user.id);

      if (updateError) {
        console.error('❌ Profile update error:', updateError);
        alert('Erro ao atualizar perfil: ' + updateError.message);
        setIsUploading(false);
        return;
      }

      console.log('✅ Perfil atualizado na BD');

      // Atualizar contexto
      await refreshProfile();
      console.log('✅ Contexto atualizado');
      
    } catch (err: any) {
      console.error('❌ Avatar upload error:', err);
      alert('Erro ao processar imagem: ' + err.message);
    } finally {
      setIsUploading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  // Remover avatar
  const handleRemoveAvatar = async () => {
    if (!user || !profile?.avatar_url) return;

    setIsUploading(true);

    try {
      const { error: updateError } = await supabase
        .from('profiles')
        .update({ avatar_url: null })
        .eq('id', user.id);

      if (updateError) {
        console.error('Remove avatar error:', updateError);
        alert('Erro ao remover foto');
        return;
      }

      await refreshProfile();
    } catch (err: any) {
      console.error('Remove avatar error:', err);
      alert('Erro ao remover foto');
    } finally {
      setIsUploading(false);
    }
  };

  // Iniciar edição do nome
  const handleStartEditName = () => {
    setEditedName(profile?.display_name || user?.email?.split('@')[0] || '');
    setIsEditingName(true);
    setNameError('');
    setNameSuccess(false);
    setTimeout(() => nameInputRef.current?.focus(), 100);
  };

  // Validar nome em tempo real
  const validateName = (name: string): string => {
    // Apenas letras, espaços e acentos permitidos
    const validPattern = /^[a-zA-ZÀ-ÿ\s]+$/;
    
    if (!name.trim()) {
      return 'O nome não pode estar vazio';
    }
    if (name.trim().length < 2) {
      return 'Mínimo 2 caracteres';
    }
    if (name.trim().length > 30) {
      return 'Máximo 30 caracteres';
    }
    if (/\d/.test(name)) {
      return 'Números não são permitidos';
    }
    if (/[-_]+/.test(name)) {
      return 'Hífens e underscores não são permitidos';
    }
    if (!validPattern.test(name.trim())) {
      return 'Apenas letras e espaços são permitidos';
    }
    if (/\s{2,}/.test(name)) {
      return 'Evita espaços duplos';
    }
    return '';
  };

  // Atualizar nome com validação em tempo real
  const handleNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    // Limitar a 30 caracteres
    if (value.length <= 30) {
      setEditedName(value);
      const error = validateName(value);
      setNameError(error);
      setNameSuccess(false);
    }
  };

  // Guardar nome
  const handleSaveName = async () => {
    const trimmedName = editedName.trim();
    const error = validateName(trimmedName);
    
    if (error) {
      setNameError(error);
      return;
    }

    if (!user) {
      handleCancelEditName();
      return;
    }

    try {
      const { error: dbError } = await supabase
        .from('profiles')
        .update({ display_name: trimmedName })
        .eq('id', user.id);

      if (dbError) {
        console.error('Error updating name:', dbError);
        setNameError('Erro ao guardar. Tenta novamente.');
        return;
      }

      await refreshProfile();
      setNameSuccess(true);
      setNameError('');
      
      // Fechar após 1.5s de sucesso
      setTimeout(() => {
        setIsEditingName(false);
        setNameSuccess(false);
      }, 1500);
    } catch (err) {
      console.error('Error:', err);
      setNameError('Erro ao guardar. Tenta novamente.');
    }
  };

  // Cancelar edição
  const handleCancelEditName = () => {
    setIsEditingName(false);
    setEditedName('');
    setNameError('');
    setNameSuccess(false);
  };

  // Cancelar edição com Escape
  const handleNameKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleSaveName();
    } else if (e.key === 'Escape') {
      handleCancelEditName();
    }
  };

  // Loading state - mostrar loading enquanto verifica auth e MFA
  if (loading || checkingMfa) {
    return (
      <div className="admin-loading">
        <div className="spinner"></div>
        <p>A carregar...</p>
      </div>
    );
  }

  // Se não autenticado, não mostrar nada (vai redirecionar)
  if (!isAuthenticated) {
    return null;
  }

  // Se profile ainda não carregou, mostrar loading
  if (!profile) {
    if (profileTimeout) {
      // Timeout - tentar recarregar ou ir para login
      return (
        <div className="admin-loading">
          <div className="spinner"></div>
          <p>Erro ao carregar perfil. <a href="/login" style={{ color: '#ef4444' }}>Fazer login novamente</a></p>
        </div>
      );
    }
    return (
      <div className="admin-loading">
        <div className="spinner"></div>
        <p>A carregar perfil...</p>
      </div>
    );
  }

  // Se não é admin, não mostrar nada (vai redirecionar)
  if (!isAdmin) {
    return null;
  }

  // Se MFA não verificado, não mostrar nada (vai redirecionar)
  if (!mfaVerified) {
    return null;
  }

  // Renderizar secção actual
  const renderSection = () => {
    switch (currentSection) {
      case 'emails':
        return <EmailsSection onBack={() => setCurrentSection('menu')} />;
      case 'health':
        return <HealthSection onBack={() => setCurrentSection('menu')} />;
      case 'traffic':
        return <TrafficSection onBack={() => setCurrentSection('menu')} />;
      case 'chat':
        return <ChatSection onBack={() => setCurrentSection('menu')} />;
      default:
        return <MainMenu onNavigate={setCurrentSection} />;
    }
  };

  return (
    <div className="admin-page">
      {/* Navbar */}
      <nav className="admin-navbar">
        <div className="admin-navbar-brand">
          <span>Eye Web</span>
        </div>
        
        <div className="admin-navbar-user">
          <div 
            ref={dropdownRef}
            className={`admin-profile-container ${profileOpen ? 'open' : ''}`}
          >
            <button 
              className="admin-profile-btn"
              onClick={() => setProfileOpen(!profileOpen)}
            >
              <div className="admin-profile-avatar">
                {profile?.avatar_url ? (
                  <img src={profile.avatar_url} alt="Avatar" />
                ) : (
                  <i className="fa-solid fa-user"></i>
                )}
              </div>
              <div className="admin-profile-info">
                <span className="admin-profile-name">
                  {profile?.display_name || user?.email?.split('@')[0] || 'Admin'}
                </span>
                <span className="admin-profile-role">Administrador</span>
              </div>
            </button>
            
            <div className="admin-profile-dropdown">
              {/* Header do Perfil - igual ao user */}
              <div className="admin-dropdown-profile-header">
                <div className={`admin-dropdown-avatar-wrapper ${isUploading ? 'uploading' : ''}`}>
                  <div className="admin-dropdown-avatar-large">
                    {profile?.avatar_url ? (
                      <img src={profile.avatar_url} alt="Avatar" />
                    ) : (
                      <i className="fa-solid fa-user"></i>
                    )}
                  </div>
                  {/* Botão de editar foto - aparece no hover */}
                  {!isUploading && (
                    <div className="admin-avatar-actions">
                      <label className="admin-avatar-edit-btn" title="Alterar foto">
                        <i className="fa-solid fa-pencil"></i>
                        <input 
                          ref={fileInputRef}
                          type="file" 
                          accept="image/*" 
                          onChange={handleAvatarUpload}
                          style={{ display: 'none' }} 
                        />
                      </label>
                      {profile?.avatar_url && (
                        <button 
                          className="admin-avatar-delete-btn" 
                          onClick={handleRemoveAvatar}
                          title="Remover foto"
                        >
                          <i className="fa-solid fa-trash"></i>
                        </button>
                      )}
                    </div>
                  )}
                  {isUploading && (
                    <div className="admin-avatar-loading">
                      <div className="spinner-small"></div>
                    </div>
                  )}
                </div>
                <div className="admin-dropdown-profile-info">
                  <div className="admin-dropdown-name-wrapper">
                    {isEditingName ? (
                      <div className="admin-name-edit-container">
                        <div className="admin-name-input-wrapper">
                          <input
                            ref={nameInputRef}
                            type="text"
                            className={`admin-name-input ${nameError ? 'error' : ''} ${nameSuccess ? 'success' : ''}`}
                            value={editedName}
                            onChange={handleNameChange}
                            onKeyDown={handleNameKeyDown}
                            maxLength={30}
                            placeholder="Escreve o teu nome..."
                          />
                          <span className="admin-name-counter">{editedName.length}/30</span>
                        </div>
                        {nameError && (
                          <span className="admin-name-feedback error">
                            <i className="fa-solid fa-circle-exclamation"></i>
                            {nameError}
                          </span>
                        )}
                        {nameSuccess && (
                          <span className="admin-name-feedback success">
                            <i className="fa-solid fa-circle-check"></i>
                            Nome guardado!
                          </span>
                        )}
                        {!nameSuccess && (
                          <div className="admin-name-edit-actions">
                            <button 
                              className="admin-name-save-btn"
                              onClick={handleSaveName}
                              title="Guardar"
                              disabled={!!nameError || !editedName.trim()}
                            >
                              <i className="fa-solid fa-check"></i>
                            </button>
                            <button 
                              className="admin-name-cancel-btn"
                              onClick={handleCancelEditName}
                              title="Cancelar"
                            >
                              <i className="fa-solid fa-xmark"></i>
                            </button>
                          </div>
                        )}
                      </div>
                    ) : (
                      <>
                        <span className="admin-dropdown-profile-name">
                          {profile?.display_name || user?.email?.split('@')[0] || 'Admin'}
                        </span>
                        <button 
                          className="admin-name-edit-btn"
                          onClick={handleStartEditName}
                          title="Editar nome"
                        >
                          <i className="fa-solid fa-pencil"></i>
                        </button>
                      </>
                    )}
                  </div>
                  <span className="admin-dropdown-profile-email">
                    {user?.email}
                  </span>
                </div>
              </div>
              
              {/* Botão Terminar Sessão - largura total como no perfil */}
              <div className="admin-dropdown-actions">
                <button 
                  className="admin-logout-btn"
                  onClick={handleLogout}
                >
                  <i className="fa-solid fa-right-from-bracket"></i>
                  Terminar sessão
                </button>
              </div>
            </div>
          </div>
        </div>
      </nav>

      {/* Conteúdo */}
      <main className="admin-main">
        {renderSection()}
      </main>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// MENU PRINCIPAL
// ═══════════════════════════════════════════════════════════════

interface MainMenuProps {
  onNavigate: (section: AdminSection) => void;
}

function MainMenu({ onNavigate }: MainMenuProps) {
  return (
    <>
      {/* Título */}
      <div className="admin-title">
        <h1>Eye Web</h1>
        <p className="typing-text">Let's keep an eye on each other</p>
      </div>

      {/* Cards */}
      <div className="admin-cards-grid">
        <div 
          className="admin-card card-emails" 
          onClick={() => onNavigate('emails')}
        >
          <div className="admin-card-icon">
            <i className="fa-solid fa-envelope"></i>
          </div>
          <h3>Gestor Emails</h3>
        </div>

        <div 
          className="admin-card card-health" 
          onClick={() => onNavigate('health')}
        >
          <div className="admin-card-icon">
            <i className="fa-solid fa-heart-pulse"></i>
          </div>
          <h3>Monitor Saúde</h3>
        </div>

        <div 
          className="admin-card card-traffic" 
          onClick={() => onNavigate('traffic')}
        >
          <div className="admin-card-icon">
            <i className="fa-solid fa-shield-halved"></i>
          </div>
          <h3>Monitor Tráfego</h3>
        </div>

        <div 
          className="admin-card card-chat" 
          onClick={() => onNavigate('chat')}
        >
          <div className="admin-card-icon">
            <i className="fa-solid fa-comments"></i>
          </div>
          <h3>Chat</h3>
        </div>
      </div>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECÇÕES (Placeholder - serão implementadas depois)
// ═══════════════════════════════════════════════════════════════

interface SectionProps {
  onBack: () => void;
}

function EmailsSection({ onBack }: SectionProps) {
  return (
    <div className="admin-section">
      <button onClick={onBack} className="admin-back-btn">
        <i className="fa-solid fa-arrow-left"></i>
        Voltar
      </button>
      <h2>📧 Gestor de Emails</h2>
      <p>Em desenvolvimento...</p>
    </div>
  );
}

function HealthSection({ onBack }: SectionProps) {
  return (
    <div className="admin-section">
      <button onClick={onBack} className="admin-back-btn">
        <i className="fa-solid fa-arrow-left"></i>
        Voltar
      </button>
      <h2>🏥 Monitor de Saúde</h2>
      <p>Em desenvolvimento...</p>
    </div>
  );
}

function TrafficSection({ onBack }: SectionProps) {
  return (
    <div className="admin-section">
      <button onClick={onBack} className="admin-back-btn">
        <i className="fa-solid fa-arrow-left"></i>
        Voltar
      </button>
      <h2>🛡️ Monitor de Tráfego</h2>
      <p>Em desenvolvimento...</p>
    </div>
  );
}

function ChatSection({ onBack }: SectionProps) {
  return (
    <div className="admin-section">
      <button onClick={onBack} className="admin-back-btn">
        <i className="fa-solid fa-arrow-left"></i>
        Voltar
      </button>
      <h2>💬 Chat</h2>
      <p>Em desenvolvimento...</p>
    </div>
  );
}
