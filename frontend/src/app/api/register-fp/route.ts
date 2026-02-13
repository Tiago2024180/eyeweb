/**
 * Register Fingerprint Proxy — API route do Next.js
 *
 * O PageTracker envia o fingerprint + componentes para este endpoint.
 * Aqui extraímos o IP REAL e reencaminhamos ao backend FastAPI.
 *
 * Retorna { blocked: boolean } para que o PageTracker saiba
 * se deve esconder o site (dispositivo bloqueado).
 */

import { NextRequest, NextResponse } from 'next/server';

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export async function POST(req: NextRequest) {
  const ip =
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    '127.0.0.1';

  try {
    const body = await req.json();
    const r = await fetch(`${BACKEND_URL}/api/register-fingerprint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...body, ip }),
      signal: AbortSignal.timeout(3000),
    });

    if (r.ok) {
      const data = await r.json();
      return NextResponse.json(data);
    }
  } catch {
    // Fail silently
  }

  return NextResponse.json({ blocked: false });
}
