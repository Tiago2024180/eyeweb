'use client';

/**
 * PageTracker — componente invisível que regista visitas de página.
 * 
 * Envia um beacon ao backend sempre que o utilizador navega para uma
 * nova página, para que TODAS as visitas (não só chamadas API) apareçam
 * no Monitor de Tráfego do admin.
 * 
 * - Usa `navigator.sendBeacon` quando disponível (não bloqueia)
 * - Fallback para `fetch` keepalive
 * - Não renderiza nada visualmente
 */

import { useEffect, useRef } from 'react';
import { usePathname } from 'next/navigation';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function PageTracker() {
  const pathname = usePathname();
  const lastPath = useRef<string>('');

  useEffect(() => {
    // Evitar duplicados (pathname pode re-disparar)
    if (pathname === lastPath.current) return;
    lastPath.current = pathname;

    // Não rastrear rotas de admin/traffic (evitar feedback loop)
    if (pathname.startsWith('/admin/traffic')) return;

    const body = JSON.stringify({ page: pathname });

    try {
      // sendBeacon — melhor performance, não bloqueia navegação
      if (typeof navigator !== 'undefined' && navigator.sendBeacon) {
        const blob = new Blob([body], { type: 'application/json' });
        navigator.sendBeacon(`${API}/api/visit`, blob);
      } else {
        // Fallback
        fetch(`${API}/api/visit`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body,
          keepalive: true,
        }).catch(() => {});
      }
    } catch {
      // Silenciar erros — tracking nunca deve quebrar a experiência
    }
  }, [pathname]);

  return null; // Componente invisível
}
