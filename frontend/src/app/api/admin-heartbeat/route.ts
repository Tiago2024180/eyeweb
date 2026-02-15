/**
 * Admin Heartbeat Proxy — API route do Next.js
 *
 * Quando o admin está nas páginas /admin/*, o PageTracker envia
 * heartbeats para aqui com o token Supabase. Este proxy:
 * 1. Extrai o IP real do utilizador
 * 2. Reenvia ao backend FastAPI com o token para verificação admin
 * 3. O backend regista o IP como admin (não pode ser bloqueado)
 */

import { NextRequest, NextResponse } from 'next/server';

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export async function POST(req: NextRequest) {
  // Extrair IP real do utilizador
  const ip =
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    '127.0.0.1';

  // Ler fingerprint do cookie (já definido pelo PageTracker nas páginas públicas)
  const fp = req.cookies.get('__ewfp')?.value || '';

  // Obter Authorization header (token Supabase)
  const authHeader = req.headers.get('authorization') || '';

  if (!authHeader.startsWith('Bearer ')) {
    return NextResponse.json({ ok: false }, { status: 401 });
  }

  try {
    const r = await fetch(`${BACKEND_URL}/api/admin-heartbeat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': authHeader,
      },
      body: JSON.stringify({ ip, fp }),
      signal: AbortSignal.timeout(3000),
    });

    if (r.ok) {
      return NextResponse.json({ ok: true });
    }
  } catch {
    // Fail silently
  }

  return NextResponse.json({ ok: true });
}
