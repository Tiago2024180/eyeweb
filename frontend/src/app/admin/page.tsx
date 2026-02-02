'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/contexts/AuthContext';
import '../login/login.css';

export default function AdminDashboardPage() {
  const router = useRouter();
  const { user, profile, isAuthenticated, isAdmin, loading, logout } = useAuth();
  const [mfaVerified, setMfaVerified] = useState(false);
  const [checkingMfa, setCheckingMfa] = useState(true);

  // Verificar MFA
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const verified = sessionStorage.getItem('mfa_verified') === 'true';
      const verifiedAt = sessionStorage.getItem('mfa_verified_at');
      
      // Verificar se o MFA ainda é válido (expira após 1 hora)
      if (verified && verifiedAt) {
        const expiryTime = 60 * 60 * 1000; // 1 hora
        const isExpired = Date.now() - parseInt(verifiedAt) > expiryTime;
        
        if (!isExpired) {
          setMfaVerified(true);
        } else {
          // MFA expirado, limpar
          sessionStorage.removeItem('mfa_verified');
          sessionStorage.removeItem('mfa_verified_at');
        }
      }
      
      setCheckingMfa(false);
    }
  }, []);

  // Redirecionar se não autenticado, não admin, ou MFA não verificado
  useEffect(() => {
    if (!loading && !checkingMfa) {
      if (!isAuthenticated) {
        router.push('/login');
        return;
      }
      
      if (!isAdmin && profile) {
        router.push('/perfil');
        return;
      }
      
      if (!mfaVerified) {
        router.push('/admin/mfa');
        return;
      }
    }
  }, [isAuthenticated, isAdmin, profile, loading, checkingMfa, mfaVerified, router]);

  const handleLogout = async () => {
    // Limpar MFA
    sessionStorage.removeItem('mfa_verified');
    sessionStorage.removeItem('mfa_verified_at');
    
    await logout();
    router.push('/login');
  };

  if (loading || checkingMfa) {
    return (
      <div className="auth-container">
        <div className="auth-loading">
          <div className="spinner"></div>
          <p>A carregar...</p>
        </div>
      </div>
    );
  }

  if (!mfaVerified) {
    return null; // Será redirecionado pelo useEffect
  }

  return (
    <div className="admin-container">
      <div className="admin-header">
        <div className="admin-logo">
          <Link href="/">
            <i className="fa-solid fa-eye"></i>
            <span>Eye Web</span>
          </Link>
          <span className="admin-badge">Admin</span>
        </div>
        <div className="admin-user">
          <span>{user?.email}</span>
          <button onClick={handleLogout} className="btn btn-small">
            <i className="fa-solid fa-right-from-bracket"></i>
            Sair
          </button>
        </div>
      </div>

      <div className="admin-content">
        <h1>Painel de Administração</h1>
        <p>Bem-vindo ao painel de administração do Eye Web.</p>

        <div className="admin-cards">
          <div className="admin-card">
            <i className="fa-solid fa-users"></i>
            <h3>Utilizadores</h3>
            <p>Gerir contas de utilizadores</p>
          </div>
          
          <div className="admin-card">
            <i className="fa-solid fa-shield-halved"></i>
            <h3>Segurança</h3>
            <p>Monitorizar atividade suspeita</p>
          </div>
          
          <div className="admin-card">
            <i className="fa-solid fa-database"></i>
            <h3>Base de Dados</h3>
            <p>Estatísticas e gestão</p>
          </div>
          
          <div className="admin-card">
            <i className="fa-solid fa-gear"></i>
            <h3>Definições</h3>
            <p>Configurações do sistema</p>
          </div>
        </div>
      </div>

      <style jsx>{`
        .admin-container {
          min-height: 100vh;
          background: var(--bg-primary);
        }
        
        .admin-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 1rem 2rem;
          background: var(--bg-secondary);
          border-bottom: 1px solid var(--border-color);
        }
        
        .admin-logo {
          display: flex;
          align-items: center;
          gap: 1rem;
        }
        
        .admin-logo a {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          color: var(--text-primary);
          text-decoration: none;
          font-size: 1.25rem;
          font-weight: bold;
        }
        
        .admin-logo i {
          color: var(--accent-primary);
        }
        
        .admin-badge {
          background: var(--accent-primary);
          color: white;
          padding: 0.25rem 0.75rem;
          border-radius: 20px;
          font-size: 0.75rem;
          font-weight: 600;
          text-transform: uppercase;
        }
        
        .admin-user {
          display: flex;
          align-items: center;
          gap: 1rem;
          color: var(--text-secondary);
        }
        
        .admin-content {
          padding: 2rem;
          max-width: 1200px;
          margin: 0 auto;
        }
        
        .admin-content h1 {
          margin-bottom: 0.5rem;
          color: var(--text-primary);
        }
        
        .admin-content > p {
          color: var(--text-secondary);
          margin-bottom: 2rem;
        }
        
        .admin-cards {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
          gap: 1.5rem;
        }
        
        .admin-card {
          background: var(--bg-secondary);
          border: 1px solid var(--border-color);
          border-radius: 12px;
          padding: 1.5rem;
          transition: transform 0.2s, box-shadow 0.2s;
          cursor: pointer;
        }
        
        .admin-card:hover {
          transform: translateY(-2px);
          box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
        }
        
        .admin-card i {
          font-size: 2rem;
          color: var(--accent-primary);
          margin-bottom: 1rem;
        }
        
        .admin-card h3 {
          color: var(--text-primary);
          margin-bottom: 0.5rem;
        }
        
        .admin-card p {
          color: var(--text-secondary);
          font-size: 0.9rem;
        }
        
        .btn-small {
          padding: 0.5rem 1rem;
          font-size: 0.875rem;
          background: transparent;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          color: var(--text-primary);
          cursor: pointer;
          display: flex;
          align-items: center;
          gap: 0.5rem;
          transition: all 0.2s;
        }
        
        .btn-small:hover {
          background: var(--bg-tertiary);
          border-color: var(--accent-primary);
        }
      `}</style>
    </div>
  );
}
