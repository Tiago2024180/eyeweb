/**
 * Eye Web - Cliente Supabase
 * Configuração do cliente Supabase para autenticação e base de dados
 */

import { createBrowserClient } from '@supabase/ssr';
import CryptoJS from 'crypto-js';

// Variáveis de ambiente
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';

// Flag para verificar se Supabase está configurado
const isSupabaseConfigured = !!(supabaseUrl && supabaseAnonKey);

if (!isSupabaseConfigured) {
  console.warn('⚠️ Supabase credentials not configured. Auth features will be disabled.');
}

// Criar cliente Supabase apenas se estiver configurado
// Durante o build, usamos URLs placeholder para evitar erros
export const supabase = createBrowserClient(
  supabaseUrl || 'https://placeholder.supabase.co',
  supabaseAnonKey || 'placeholder-key',
  {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true,
      // Desativar o lock que causa o AbortError
      lock: async (name: string, acquireTimeout: number, fn: () => Promise<any>) => {
        return await fn();
      },
    },
  }
);

// ===========================================
// TIPOS
// ===========================================

export interface Profile {
  id: string;
  email: string;
  display_name: string | null;
  avatar_url: string | null;
  role: 'user' | 'admin';
  is_subscribed: boolean;
  created_at: string;
  updated_at: string;
}

export interface AuthUser {
  id: string;
  email: string;
  profile: Profile | null;
}

// ===========================================
// FUNÇÕES DE AUTH
// ===========================================

/**
 * Login com email e password
 */
export async function signInWithEmail(email: string, password: string) {
  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  });
  
  if (error) throw error;
  return data;
}

/**
 * Validar credenciais sem criar sessão no browser
 * Usa signInWithOtp primeiro para verificar se o utilizador existe,
 * depois tenta login com password mas faz signOut imediato ANTES de propagar
 */
export async function validateCredentials(email: string, password: string): Promise<boolean> {
  // Criar um cliente Supabase separado sem persistência de sessão
  // para não afetar o estado de auth do browser
  const { createClient } = await import('@supabase/supabase-js');
  
  const tempClient = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL || '',
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '',
    {
      auth: {
        persistSession: false, // NÃO persistir sessão
        autoRefreshToken: false,
        detectSessionInUrl: false,
      },
    }
  );
  
  const { data, error } = await tempClient.auth.signInWithPassword({
    email,
    password,
  });
  
  if (error) {
    throw error;
  }
  
  // Credenciais válidas - fazer logout no cliente temporário (não afeta o principal)
  if (data.session) {
    await tempClient.auth.signOut();
    return true;
  }
  
  return false;
}

/**
 * Enviar magic link para verificação de login
 */
export async function sendLoginMagicLink(email: string) {
  const { data, error } = await supabase.auth.signInWithOtp({
    email,
    options: {
      shouldCreateUser: false, // Não criar novo utilizador
      emailRedirectTo: `${window.location.origin}/auth/callback?type=magiclink`, // Redireciona para callback com type
    },
  });
  
  if (error) throw error;
  return data;
}

/**
 * Login com Google OAuth
 */
export async function signInWithGoogle() {
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: 'google',
    options: {
      redirectTo: `${window.location.origin}/auth/callback`,
    },
  });
  
  if (error) throw error;
  return data;
}

/**
 * Registo com email e password
 */
export async function signUpWithEmail(email: string, password: string, fullName?: string) {
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      data: {
        full_name: fullName,
      },
    },
  });
  
  if (error) throw error;
  return data;
}

/**
 * Logout - com scope global para terminar todas as sessões
 */
export async function signOut() {
  try {
    const { error } = await supabase.auth.signOut({ scope: 'global' });
    if (error) {
      console.error('SignOut error:', error);
    }
  } catch (error) {
    console.error('SignOut exception:', error);
  }
}

/**
 * Obter sessão atual
 */
export async function getSession() {
  const { data: { session }, error } = await supabase.auth.getSession();
  if (error) throw error;
  return session;
}

/**
 * Obter utilizador atual
 */
export async function getCurrentUser() {
  const { data: { user }, error } = await supabase.auth.getUser();
  if (error) throw error;
  return user;
}

/**
 * Obter perfil do utilizador
 */
export async function getProfile(userId: string): Promise<Profile | null> {
  const { data, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', userId)
    .single();
  
  if (error) {
    console.error('Error fetching profile:', error);
    return null;
  }
  
  return data;
}

/**
 * Atualizar perfil do utilizador
 */
export async function updateProfile(userId: string, updates: Partial<Profile>) {
  const { data, error } = await supabase
    .from('profiles')
    .update(updates)
    .eq('id', userId)
    .select()
    .single();
  
  if (error) throw error;
  return data;
}

/**
 * Verificar se email é de admin (para bloquear Google OAuth)
 * Usa hash SHA-256 para não expor o email admin no código
 */
export function isAdminEmail(email: string): boolean {
  // Hash do email admin (SHA-256) - não expor email no código
  const adminEmailHash = process.env.NEXT_PUBLIC_ADMIN_EMAIL_HASH || '';
  
  if (!adminEmailHash) return false;
  
  // Calcular hash do email introduzido
  const emailHash = hashEmail(email.toLowerCase().trim());
  
  return emailHash === adminEmailHash;
}

/**
 * Gerar hash SHA-256 de uma string
 */
function hashEmail(email: string): string {
  return CryptoJS.SHA256(email).toString();
}

/**
 * Verificar se o utilizador é admin
 */
export async function isAdmin(userId: string): Promise<boolean> {
  const profile = await getProfile(userId);
  return profile?.role === 'admin';
}

// ===========================================
// VERIFICAÇÃO COM CÓDIGO (2FA Simplificado)
// ===========================================

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export interface SendCodeResponse {
  success: boolean;
  codes: string[];
  session_id: string;
  expires_in: number;
  message: string;
  dev_hint?: string;
}

export interface VerifyCodeResponse {
  success: boolean;
  message: string;
}

/**
 * Envia código de verificação para o email
 * Retorna 3 códigos para mostrar ao utilizador
 */
export async function sendVerificationCode(email: string): Promise<SendCodeResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/auth/send-code`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email }),
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Erro ao enviar código de verificação');
  }
  
  return response.json();
}

/**
 * Verifica se o código submetido está correto
 */
export async function verifyCode(
  sessionId: string,
  code: string,
  email: string
): Promise<VerifyCodeResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/auth/verify-code`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      session_id: sessionId,
      code,
      email,
    }),
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Código incorreto');
  }
  
  return response.json();
}

/**
 * Completa o login após verificação do código
 * Faz o login real no Supabase
 */
export async function completeLogin(email: string, password: string) {
  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  });
  
  if (error) throw error;
  return data;
}
