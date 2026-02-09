'use client';

import { createContext, useContext, useEffect, useState, useRef, ReactNode } from 'react';
import { User, Session } from '@supabase/supabase-js';
import { 
  supabase, 
  Profile, 
  getProfile, 
  signInWithEmail, 
  signInWithGoogle,
  signUpWithEmail,
  signOut as supabaseSignOut,
  isAdminEmail 
} from '@/lib/supabase';

// ===========================================
// TIPOS
// ===========================================

interface AuthContextType {
  // Estado
  user: User | null;
  profile: Profile | null;
  session: Session | null;
  loading: boolean;
  
  // Funções de auth
  login: (email: string, password: string) => Promise<void>;
  loginWithGoogle: () => Promise<void>;
  signup: (email: string, password: string, fullName?: string) => Promise<void>;
  logout: () => Promise<void>;
  
  // Helpers
  isAuthenticated: boolean;
  isAdmin: boolean;
  refreshProfile: () => Promise<void>;
}

// ===========================================
// CONTEXT
// ===========================================

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// ===========================================
// PROVIDER
// ===========================================

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  
  // Ref para o ID do user atual (acessível em closures sem stale state)
  const userIdRef = useRef<string | null>(null);

  // Enviar email de boas-vindas (apenas uma vez por utilizador)
  const sendWelcomeEmail = async (email: string, displayName: string | null) => {
    try {
      // Verificar se já foi enviado (usando localStorage)
      const welcomeSentKey = `welcome_sent_${email}`;
      if (localStorage.getItem(welcomeSentKey)) {
        return; // Já foi enviado
      }
      
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
      const response = await fetch(`${apiUrl}/api/admin/emails/welcome?email=${encodeURIComponent(email)}&display_name=${encodeURIComponent(displayName || '')}`, {
        method: 'POST',
      });
      
      if (response.ok) {
        localStorage.setItem(welcomeSentKey, 'true');
        console.log('✅ Email de boas-vindas enviado!');
      }
    } catch (error) {
      console.error('Erro ao enviar email de boas-vindas:', error);
    }
  };

  // Carregar perfil do utilizador
  const loadProfile = async (userId: string) => {
    try {
      const userProfile = await getProfile(userId);
      
      // Se o perfil não existe, criar um perfil básico
      if (!userProfile) {
        console.warn('Profile not found - creating basic profile');
        
        // Obter dados do utilizador atual
        const { data: { user: currentUser } } = await supabase.auth.getUser();
        
        if (currentUser) {
          // Verificar se é admin (async)
          const userIsAdmin = await isAdminEmail(currentUser.email || '');
          
          // Criar perfil básico
          const newProfile = {
            id: currentUser.id,
            email: currentUser.email,
            display_name: currentUser.user_metadata?.display_name || 
                         currentUser.user_metadata?.full_name || 
                         currentUser.email?.split('@')[0],
            avatar_url: currentUser.user_metadata?.avatar_url,
            role: userIsAdmin ? 'admin' : 'user',
          };
          
          const { data, error } = await supabase
            .from('profiles')
            .upsert(newProfile)
            .select()
            .single();
          
          if (error) {
            console.error('Error creating profile:', error);
            return;
          }
          
          setProfile(data);
          
          // Enviar email de boas-vindas para novos utilizadores (não admin)
          if (data.email && !userIsAdmin) {
            sendWelcomeEmail(data.email, data.display_name);
          }
          
          return;
        }
        return;
      }
      
      setProfile(userProfile);
    } catch (error) {
      console.error('Error loading profile:', error);
    }
  };

  // Refrescar perfil
  const refreshProfile = async () => {
    if (user) {
      await loadProfile(user.id);
    }
  };

  // Inicializar auth state
  // NOTA: Usa onAuthStateChange com INITIAL_SESSION como fonte primária.
  // INITIAL_SESSION lê do localStorage (instantâneo), ao contrário de getSession()
  // que faz chamada de rede e pode ser lento/pendurar em produção.
  useEffect(() => {
    let isMounted = true;
    
    // Safety timeout - garantir que loading NUNCA fica preso infinitamente
    const safetyTimeout = setTimeout(() => {
      if (isMounted) {
        console.error('⚠️ AuthContext safety timeout: loading stuck for 12s, forcing false');
        setLoading(false);
      }
    }, 12000);

    // Listener para mudanças de auth (INCLUI INITIAL_SESSION)
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      async (event, session) => {
        console.log('Auth event:', event);
        
        if (!isMounted) return;
        
        // INITIAL_SESSION: sessão carregada do localStorage (instantâneo)
        // É o primeiro evento que dispara — usa-lo para resolver loading rapidamente
        if (event === 'INITIAL_SESSION') {
          setSession(session);
          setUser(session?.user ?? null);
          userIdRef.current = session?.user?.id ?? null;
          
          if (session?.user) {
            try {
              await loadProfile(session.user.id);
            } catch (err) {
              console.error('Error loading profile on INITIAL_SESSION:', err);
            }
          }
          
          if (isMounted) setLoading(false);
          return;
        }
        
        // TOKEN_REFRESHED só renova o JWT - os dados do perfil não mudam
        if (event === 'TOKEN_REFRESHED') {
          setSession(session);
          setUser(session?.user ?? null);
          return;
        }
        
        // SIGNED_OUT explícito - limpar tudo
        if (event === 'SIGNED_OUT') {
          setSession(null);
          setUser(null);
          setProfile(null);
          userIdRef.current = null;
          setLoading(false);
          return;
        }
        
        // SIGNED_IN do mesmo user (BroadcastChannel sync entre tabs)
        // Não recarregar perfil - evitar re-render que bloqueia botões
        if (event === 'SIGNED_IN' && session?.user?.id === userIdRef.current) {
          setSession(session);
          return;
        }
        
        // Outros eventos (SIGNED_IN novo user, USER_UPDATED, etc.)
        setSession(session);
        setUser(session?.user ?? null);
        userIdRef.current = session?.user?.id ?? null;
        
        if (session?.user) {
          try {
            await loadProfile(session.user.id);
          } catch (err) {
            console.error('Error loading profile:', err);
          }
        }
        
        if (isMounted) setLoading(false);
      }
    );

    return () => {
      isMounted = false;
      clearTimeout(safetyTimeout);
      subscription.unsubscribe();
    };
  }, []);

  // Listener para detetar quando o perfil é eliminado (realtime)
  useEffect(() => {
    if (!user) return;

    // Subscrever a mudanças na tabela profiles para este utilizador
    const channel = supabase
      .channel('profile-changes')
      .on(
        'postgres_changes',
        {
          event: 'DELETE',
          schema: 'public',
          table: 'profiles',
          filter: `id=eq.${user.id}`,
        },
        async () => {
          console.log('Profile deleted - logging out');
          await supabaseSignOut();
          setUser(null);
          setProfile(null);
          setSession(null);
          // Redirecionar para login
          if (typeof window !== 'undefined') {
            window.location.href = '/login?reason=account_deleted';
          }
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [user]);

  // ===========================================
  // FUNÇÕES DE AUTH
  // ===========================================

  const login = async (email: string, password: string) => {
    setLoading(true);
    try {
      const { user: authUser } = await signInWithEmail(email, password);
      
      if (authUser) {
        setUser(authUser);
        await loadProfile(authUser.id);
      }
    } finally {
      setLoading(false);
    }
  };

  const loginWithGoogle = async () => {
    // O redirect é handled pelo Supabase
    await signInWithGoogle();
  };

  const signup = async (email: string, password: string, fullName?: string) => {
    setLoading(true);
    try {
      // Verificar se é email de admin (não pode registar via signup normal)
      const emailIsAdmin = await isAdminEmail(email);
      if (emailIsAdmin) {
        throw new Error('Este email não pode ser registado. Contacte o administrador.');
      }
      
      await signUpWithEmail(email, password, fullName);
      // O utilizador precisa confirmar o email antes de fazer login
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      // Limpar MFA verificado (segurança: limpar antes de tudo)
      localStorage.removeItem('mfa_verified');
      await supabaseSignOut();
      setUser(null);
      setProfile(null);
      setSession(null);
      // Redirecionar para home após logout (usar window.location para garantir reload completo)
      window.location.href = '/';
    } catch (error) {
      console.error('Logout error:', error);
      // Mesmo com erro, limpar estado local e redirecionar
      localStorage.removeItem('mfa_verified');
      setUser(null);
      setProfile(null);
      setSession(null);
      window.location.href = '/';
    }
  };

  // ===========================================
  // VALORES DO CONTEXT
  // ===========================================

  const value: AuthContextType = {
    user,
    profile,
    session,
    loading,
    login,
    loginWithGoogle,
    signup,
    logout,
    isAuthenticated: !!user,
    isAdmin: profile?.role === 'admin',
    refreshProfile,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

// ===========================================
// HOOK
// ===========================================

export function useAuth() {
  const context = useContext(AuthContext);
  
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  
  return context;
}

// ===========================================
// HOC PARA PROTEGER ROTAS
// ===========================================

export function withAuth<P extends object>(
  WrappedComponent: React.ComponentType<P>,
  options?: { requireAdmin?: boolean }
) {
  return function AuthenticatedComponent(props: P) {
    const { isAuthenticated, isAdmin, loading } = useAuth();
    
    if (loading) {
      return (
        <div className="loading-container">
          <div className="spinner"></div>
          <p>A carregar...</p>
        </div>
      );
    }
    
    if (!isAuthenticated) {
      // Redirecionar para login
      if (typeof window !== 'undefined') {
        window.location.href = '/login';
      }
      return null;
    }
    
    if (options?.requireAdmin && !isAdmin) {
      // Redirecionar para home se não for admin
      if (typeof window !== 'undefined') {
        window.location.href = '/';
      }
      return null;
    }
    
    return <WrappedComponent {...props} />;
  };
}
