/**
 * Heartbeat Proxy — API route do Next.js
 *
 * O PageTracker chama esta route (same-origin) a cada 30s.
 * Aqui extraímos o IP REAL do utilizador (via headers) e
 * reencaminhamos o heartbeat ao backend FastAPI com o IP correto.
 *
 * Porquê um proxy?
 * - No browser, fetch/sendBeacon ao backend (porta 8000) chega com IP 127.0.0.1
 * - Esta route (server-side) tem acesso ao IP real via x-forwarded-for
 * - Garante que o heartbeat é registado para o IP correto no dashboard
 */

import { NextRequest, NextResponse } from 'next/server';

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export async function POST(req: NextRequest) {
  // Extrair IP real do utilizador (mesmo método que o middleware)
  const ip =
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    '127.0.0.1';

  try {
    // Chamar check-ip do backend com o IP real
    // check-ip faz ts.heartbeat(ip) automaticamente
    await fetch(
      `${BACKEND_URL}/api/check-ip?ip=${encodeURIComponent(ip)}`,
      { signal: AbortSignal.timeout(2000) }
    );
  } catch {
    // Fail silently — heartbeat nunca deve quebrar a experiência
  }

  return NextResponse.json({ ok: true });
}
