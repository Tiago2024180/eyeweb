'use client';

import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
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
          // Criar perfil básico
          const newProfile = {
            id: currentUser.id,
            email: currentUser.email,
            display_name: currentUser.user_metadata?.display_name || 
                         currentUser.user_metadata?.full_name || 
                         currentUser.email?.split('@')[0],
            avatar_url: currentUser.user_metadata?.avatar_url,
            role: isAdminEmail(currentUser.email || '') ? 'admin' : 'user',
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
  useEffect(() => {
    let isMounted = true;
    
    // Obter sessão inicial
    const initAuth = async () => {
      try {
        const { data: { session }, error } = await supabase.auth.getSession();
        
        if (error) {
          console.error('Error getting session:', error);
          if (isMounted) setLoading(false);
          return;
        }
        
        if (isMounted) {
          setSession(session);
          setUser(session?.user ?? null);
          
          if (session?.user) {
            await loadProfile(session.user.id);
          }
          
          setLoading(false);
        }
      } catch (error) {
        console.error('Auth init error:', error);
        if (isMounted) setLoading(false);
      }
    };
    
    initAuth();

    // Listener para mudanças de auth
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      async (event, session) => {
        console.log('Auth event:', event);
        
        if (!isMounted) return;
        
        setSession(session);
        setUser(session?.user ?? null);
        
        if (session?.user) {
          await loadProfile(session.user.id);
        } else {
          setProfile(null);
        }
        
        setLoading(false);
      }
    );

    return () => {
      isMounted = false;
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
      if (isAdminEmail(email)) {
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
      await supabaseSignOut();
      setUser(null);
      setProfile(null);
      setSession(null);
      // Redirecionar para home após logout (usar window.location para garantir reload completo)
      window.location.href = '/';
    } catch (error) {
      console.error('Logout error:', error);
      // Mesmo com erro, limpar estado local e redirecionar
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
