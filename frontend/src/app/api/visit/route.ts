/**
 * Visit Proxy — API route do Next.js
 *
 * Chamado pelo PageTracker quando o user navega para uma página diferente
 * (client-side navigation). Extrai o IP real e envia ao backend para
 * registar a visita em traffic_logs.
 */

import { NextRequest, NextResponse } from 'next/server';

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export async function POST(req: NextRequest) {
  const ip =
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    '127.0.0.1';

  const fp = req.cookies.get('__ewfp')?.value || '';

  try {
    const body = await req.json();
    const page = body.page || '/';
    const ua = body.ua || '';  // Real browser UA from client-side

    const r = await fetch(`${BACKEND_URL}/api/visit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': ip,
      },
      body: JSON.stringify({ page, fp, ua }),
      signal: AbortSignal.timeout(2500),
    });

    if (r.ok) {
      return NextResponse.json({ ok: true });
    }
  } catch {
    // Fail silently
  }

  return NextResponse.json({ ok: true });
}
