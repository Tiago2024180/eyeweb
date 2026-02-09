import { createServerClient, type CookieOptions } from '@supabase/ssr';
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Rotas que requerem autenticação no middleware
// NOTA: Desde que migramos o Supabase client para createClient (localStorage),
// o middleware server-side NÃO consegue ver sessões client-side.
// A verificação de auth é feita client-side nas próprias páginas.
// O middleware só protege rotas onde o redirect para login é ESSENCIAL no server-side.
const protectedRoutes: string[] = [];

// Rotas de admin são verificadas inteiramente no client-side
// porque a sessão Supabase é guardada em localStorage (não cookies)
// e o middleware (server-side) não consegue ver localStorage.
// O admin/page.tsx já verifica: isAuthenticated, isAdmin, mfaVerified
const adminRoutes: string[] = [];

// Rotas públicas dentro de admin (não requerem autenticação prévia)
const publicAdminRoutes = ['/admin/mfa', '/admin', '/admin/chat'];

// Verificar se Supabase está configurado
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';
const isSupabaseConfigured = !!(supabaseUrl && supabaseAnonKey);

// Função para criar hash SHA-256 usando Web Crypto API (compatível com Edge Runtime)
async function sha256(message: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Função para verificar se é admin via hash (não expor email no código)
async function isAdminEmail(email: string): Promise<boolean> {
  const adminEmailHash = process.env.NEXT_PUBLIC_ADMIN_EMAIL_HASH || '';
  if (!adminEmailHash) return false;
  const emailHash = await sha256(email.toLowerCase());
  return emailHash === adminEmailHash;
}

export async function middleware(req: NextRequest) {
  // Se Supabase não está configurado, deixar passar todas as rotas
  if (!isSupabaseConfigured) {
    return NextResponse.next();
  }

  let res = NextResponse.next({
    request: {
      headers: req.headers,
    },
  });

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return req.cookies.getAll();
        },
        setAll(cookiesToSet: { name: string; value: string; options?: CookieOptions }[]) {
          cookiesToSet.forEach(({ name, value }) =>
            req.cookies.set(name, value)
          );
          res = NextResponse.next({
            request: {
              headers: req.headers,
            },
          });
          cookiesToSet.forEach(({ name, value, options }) =>
            res.cookies.set(name, value, options)
          );
        },
      },
    }
  );

  const pathname = req.nextUrl.pathname;

  // Verificar se é uma rota pública de admin (como MFA)
  // IMPORTANTE: verificar ANTES de getUser() para evitar chamada de rede desnecessária
  // As rotas de admin são verificadas inteiramente no client-side (localStorage)
  const isPublicAdminRoute = publicAdminRoutes.some(route => pathname.startsWith(route));
  
  // Permitir acesso a rotas públicas de admin sem autenticação
  if (isPublicAdminRoute) {
    return res;
  }

  const {
    data: { user },
  } = await supabase.auth.getUser();

  // Verificar se é uma rota protegida
  const isProtectedRoute = protectedRoutes.some(route => pathname.startsWith(route));
  const isAdminRoute = adminRoutes.some(route => pathname.startsWith(route));

  // Se não está autenticado e tenta aceder a rota protegida
  if (isProtectedRoute && !user) {
    const loginUrl = new URL('/login', req.url);
    loginUrl.searchParams.set('redirect', pathname);
    return NextResponse.redirect(loginUrl);
  }

  // Se está autenticado mas tenta aceder a rota de admin sem ser admin
  if (isAdminRoute && user) {
    const isAdmin = user.email ? await isAdminEmail(user.email) : false;
    
    if (!isAdmin) {
      // Redirecionar para perfil com mensagem
      const perfilUrl = new URL('/perfil', req.url);
      perfilUrl.searchParams.set('error', 'access_denied');
      return NextResponse.redirect(perfilUrl);
    }
  }

  // Se está autenticado, verificar se precisa completar signup (OAuth sem password)
  if (user && isProtectedRoute && pathname !== '/auth/complete-signup') {
    const hasEmailIdentity = user.identities?.some(
      (identity) => identity.provider === 'email'
    );
    const hasPasswordFlag = user.user_metadata?.has_password === true;
    
    // Se só tem OAuth e não tem email identity NEM flag de password, precisa completar signup
    if (!hasEmailIdentity && !hasPasswordFlag) {
      return NextResponse.redirect(new URL('/auth/complete-signup', req.url));
    }
  }

  // Se está autenticado e vai para login/signup, redirecionar para perfil
  if (user && (pathname === '/login' || pathname === '/signup')) {
    const isAdmin = user.email ? await isAdminEmail(user.email) : false;
    // Admin vai direto para MFA se necessário
    if (isAdmin && pathname === '/login') {
      return NextResponse.redirect(new URL('/admin/mfa', req.url));
    }
    return NextResponse.redirect(new URL('/perfil', req.url));
  }

  return res;
}

export const config = {
  matcher: [
    '/login',
    '/signup',
    '/perfil/:path*',
    '/admin/:path*',
    '/auth/complete-signup',
  ],
};
