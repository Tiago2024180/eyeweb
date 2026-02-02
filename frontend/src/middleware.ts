import { createServerClient, type CookieOptions } from '@supabase/ssr';
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { createHash } from 'crypto';

// Rotas que requerem autenticação
const protectedRoutes = ['/perfil', '/admin'];

// Rotas que requerem ser admin
const adminRoutes = ['/admin'];

// Função para verificar se é admin via hash (não expor email no código)
function isAdminEmail(email: string): boolean {
  const adminEmailHash = process.env.NEXT_PUBLIC_ADMIN_EMAIL_HASH || '';
  if (!adminEmailHash) return false;
  const emailHash = createHash('sha256').update(email.toLowerCase()).digest('hex');
  return emailHash === adminEmailHash;
}

export async function middleware(req: NextRequest) {
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

  const {
    data: { user },
  } = await supabase.auth.getUser();

  const pathname = req.nextUrl.pathname;

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
    const isAdmin = user.email ? isAdminEmail(user.email) : false;
    
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
    const isAdmin = user.email ? isAdminEmail(user.email) : false;
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
