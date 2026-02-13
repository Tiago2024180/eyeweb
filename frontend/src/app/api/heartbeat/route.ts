/**
 * Heartbeat Proxy — API route do Next.js
 *
 * O PageTracker chama esta route (same-origin) a cada 30s.
 * Aqui extraímos o IP REAL do utilizador (via headers) e
 * reencaminhamos o heartbeat ao backend FastAPI com o IP correto.
 * Também envia o fingerprint do cookie __ewfp para o backend
 * verificar se o dispositivo está bloqueado.
 */

import { NextRequest, NextResponse } from 'next/server';

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export async function POST(req: NextRequest) {
  // Extrair IP real do utilizador (mesmo método que o middleware)
  const ip =
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    '127.0.0.1';

  // Ler fingerprint do cookie (definido pelo PageTracker no client-side)
  const fp = req.cookies.get('__ewfp')?.value || '';

  try {
    // Chamar check-ip do backend com o IP real + fingerprint
    const params = new URLSearchParams({ ip });
    if (fp) params.set('fp', fp);

    const r = await fetch(
      `${BACKEND_URL}/api/check-ip?${params.toString()}`,
      { signal: AbortSignal.timeout(2000) }
    );

    if (r.ok) {
      const data = await r.json();
      return NextResponse.json({ ok: true, blocked: data.blocked });
    }
  } catch {
    // Fail silently — heartbeat nunca deve quebrar a experiência
  }

  return NextResponse.json({ ok: true });
}
