import { createServerClient, type CookieOptions } from '@supabase/ssr';
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// ─── BACKEND URL (para verificar IPs bloqueados) ────
const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// ─── CACHE de IPs bloqueados (in-memory, eficaz em Node.js) ───
const ipCache = new Map<string, { blocked: boolean; ts: number }>();
const CACHE_TTL = 15_000; // 15 segundos — só para bloqueio

// Cache de visitas registadas (evitar duplicados na mesma sessão)
const visitCache = new Map<string, number>(); // "ip|path" → timestamp
const VISIT_TTL = 60_000; // 60 segundos — mesma página não é re-registada

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
  // ═══════════════════════════════════════════════════
  // 1. VERIFICAÇÃO DE IP BLOQUEADO (antes de tudo)
  //    Se o IP está bloqueado → 403 imediato, zero acesso
  // ═══════════════════════════════════════════════════
  const clientIp =
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    '';

  // Verificar IP bloqueado — só para IPs reais (não localhost)
  // Heartbeats de utilizadores reais passam pelo proxy /api/heartbeat
  if (clientIp && clientIp !== '127.0.0.1' && clientIp !== '::1') {
    const pagePath = req.nextUrl.pathname;
    const userAgent = req.headers.get('user-agent') || '';
    // Ler fingerprint do cookie (definido pelo PageTracker no client-side)
    const fpCookie = req.cookies.get('__ewfp')?.value || '';
    // Não enviar path para: rotas admin ou /api/ (evita poluir traffic_logs)
    const isInternal = pagePath.startsWith('/admin') || pagePath.startsWith('/api/');
    const isBlocked = await checkBlocked(
      clientIp,
      isInternal ? '' : pagePath,
      isInternal ? '' : userAgent,
      fpCookie
    );
    if (isBlocked) {
      return blockedResponse();
    }
  }

  // ═══════════════════════════════════════════════════
  // 2. SUPABASE AUTH (lógica original)
  // ═══════════════════════════════════════════════════

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
  // NOTA: Admin redirect vai para /admin (não /admin/mfa) porque o client-side
  // do admin/page.tsx já verifica MFA via localStorage. Redirecionar direto para
  // /admin/mfa causava loop quando cookies e localStorage estavam desincronizados.
  if (user && (pathname === '/login' || pathname === '/signup')) {
    const isAdmin = user.email ? await isAdminEmail(user.email) : false;
    if (isAdmin && pathname === '/login') {
      return NextResponse.redirect(new URL('/admin', req.url));
    }
    return NextResponse.redirect(new URL('/perfil', req.url));
  }

  return res;
}

// ═══════════════════════════════════════════════════════
// BLOCK CHECKER — consulta o backend (IP + fingerprint) com cache
// ═══════════════════════════════════════════════════════

async function checkBlocked(ip: string, path: string = '', ua: string = '', fp: string = ''): Promise<boolean> {
  // 1. Cache check — usar chave combinada IP:FP para evitar falsos negativos
  const cacheKey = fp ? `${ip}:${fp}` : ip;
  const cached = ipCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < CACHE_TTL && cached.blocked) {
    return true;
  }

  // 2. Verificar se esta visita (ip+path) já foi registada recentemente
  const visitKey = `${ip}|${path}`;
  const lastVisit = visitCache.get(visitKey) || 0;
  const skipVisitLog = Date.now() - lastVisit < VISIT_TTL;

  // 3. Perguntar ao backend (envia path+ua+fp para registar visita)
  try {
    const params = new URLSearchParams({ ip });
    if (path && !skipVisitLog) {
      params.set('path', path);
      if (ua) params.set('ua', ua.slice(0, 300));
    }
    // Enviar fingerprint se disponível (do cookie __ewfp)
    if (fp) params.set('fp', fp);

    const r = await fetch(
      `${BACKEND_URL}/api/check-ip?${params.toString()}`,
      { signal: AbortSignal.timeout(2500) }
    );
    if (r.ok) {
      const data = await r.json();
      ipCache.set(cacheKey, { blocked: data.blocked, ts: Date.now() });
      if (path && !skipVisitLog) {
        visitCache.set(visitKey, Date.now());
      }
      if (ipCache.size > 5000) ipCache.clear();
      if (visitCache.size > 10000) visitCache.clear();
      return data.blocked;
    }
  } catch {
    // Fail open
  }
  return false;
}

// ═══════════════════════════════════════════════════════
// BLOCKED PAGE — "é como se o site não existisse"
// Parece uma página 404 genérica do Vercel/Next.js.
// Não revela que o Eye Web existe nem que o utilizador foi bloqueado.
// ═══════════════════════════════════════════════════════

function blockedResponse(): NextResponse {
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width"/><title>404: This page could not be found</title></head><body style="color:#000;background:#fff;font-family:-apple-system,BlinkMacSystemFont,Roboto,'Segoe UI','Fira Sans',Avenir,'Helvetica Neue','Lucida Grande',sans-serif;height:100vh;text-align:center;display:flex;flex-direction:column;align-items:center;justify-content:center"><div><h1 style="display:inline-block;margin:0 20px 0 0;padding:0 23px 0 0;font-size:24px;font-weight:500;vertical-align:top;line-height:49px;border-right:1px solid rgba(0,0,0,.3)">404</h1><div style="display:inline-block"><h2 style="font-size:14px;font-weight:400;line-height:49px;margin:0">This page could not be found.</h2></div></div></body></html>`;

  return new NextResponse(html, {
    status: 404,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store, no-cache',
    },
  });
}

export const config = {
  matcher: [
    /*
     * Intercepta TODAS as rotas exceto ficheiros estáticos:
     * - _next/static (JS/CSS bundles)
     * - _next/image (otimização de imagens)
     * - favicon.ico
     * - Ficheiros estáticos (.svg, .png, .jpg, .css, .js, .woff, etc.)
     */
    '/((?!_next/static|_next/image|favicon\\.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|css|js|woff2?)$).*)',
  ],
};
