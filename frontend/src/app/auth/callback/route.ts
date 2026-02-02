import { createServerClient, type CookieOptions } from '@supabase/ssr';
import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { createHash } from 'crypto';

// Função para verificar se é admin via hash (não expor email)
function isAdminEmail(email: string): boolean {
  const adminEmailHash = process.env.NEXT_PUBLIC_ADMIN_EMAIL_HASH || '';
  if (!adminEmailHash) return false;
  
  const emailHash = createHash('sha256').update(email.toLowerCase().trim()).digest('hex');
  return emailHash === adminEmailHash;
}

export async function GET(request: NextRequest) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get('code');
  const next = searchParams.get('next') ?? '/';
  const type = searchParams.get('type'); // 'magiclink', 'signup', 'recovery', etc.

  if (code) {
    const cookieStore = await cookies();
    
    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      {
        cookies: {
          getAll() {
            return cookieStore.getAll();
          },
          setAll(cookiesToSet: { name: string; value: string; options?: CookieOptions }[]) {
            try {
              cookiesToSet.forEach(({ name, value, options }) =>
                cookieStore.set(name, value, options)
              );
            } catch {
              // The `setAll` method was called from a Server Component.
              // This can be ignored if you have middleware refreshing sessions.
            }
          },
        },
      }
    );

    const { error } = await supabase.auth.exchangeCodeForSession(code);
    
    if (!error) {
      const { data: { user } } = await supabase.auth.getUser();
      
      if (user) {
        // BLOQUEIO DE SEGURANÇA: Admins NÃO podem usar Google OAuth
        // Verificar se é admin via hash
        if (user.email && isAdminEmail(user.email)) {
          // Verificar se veio do Google OAuth (bloquear)
          const isGoogleLogin = user.app_metadata?.provider === 'google';
          if (isGoogleLogin) {
            await supabase.auth.signOut();
            return NextResponse.redirect(`${origin}/login?error=admin_google_blocked`);
          }
        }
        
        // Verificar se é utilizador novo do Google (não tem password)
        const hasEmailIdentity = user.identities?.some(
          (identity) => identity.provider === 'email'
        );
        const hasPasswordFlag = user.user_metadata?.has_password === true;
        
        // Se só tem Google e não tem email identity NEM flag de password, precisa completar signup
        if (!hasEmailIdentity && !hasPasswordFlag) {
          return NextResponse.redirect(`${origin}/auth/complete-signup`);
        }
        
        // Se é magic link de login (verificação), mostrar página de sucesso
        if (type === 'magiclink') {
          return NextResponse.redirect(`${origin}/auth/login-success`);
        }
      }
      
      return NextResponse.redirect(`${origin}${next}`);
    }
  }

  // Erro - redirecionar para login com mensagem
  return NextResponse.redirect(`${origin}/login?error=auth_failed`);
}
