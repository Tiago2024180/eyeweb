'use client';

/**
 * PageTracker — componente invisível que regista visitas de página
 * e envia heartbeats periódicos para manter o estado online/offline.
 * 
 * - Envia beacon ao backend a cada navegação (visita de página)
 * - Envia heartbeat a cada 30s (para o admin ver quem está online)
 * - Usa `navigator.sendBeacon` quando disponível (não bloqueia)
 * - Fallback para `fetch` keepalive
 * - Não renderiza nada visualmente
 */

import { useEffect, useRef } from 'react';
import { usePathname } from 'next/navigation';

export default function PageTracker() {
  const pathname = usePathname();
  const lastPath = useRef<string>('');

  // ─── Registar visita de página ────────────────────
  // (Visitas são agora registadas server-to-server pelo middleware.ts,
  //  não precisamos de beacon do browser para isso)

  // ─── Heartbeat periódico (20s) — manter estado online ──
  // Chama /api/heartbeat (Next.js API route, same-origin).
  // O pedido passa pelo middleware que extrai o IP real e
  // reencaminha ao backend — sem criar entradas nos traffic_logs.
  useEffect(() => {
    const sendHeartbeat = () => {
      try {
        fetch('/api/heartbeat', {
          method: 'POST',
          keepalive: true,
        }).catch(() => {});
      } catch {
        // Silenciar — heartbeat nunca deve quebrar a experiência
      }
    };

    // Enviar imediatamente ao carregar
    sendHeartbeat();

    // Repetir a cada 20 segundos (online expira aos 60s)
    const interval = setInterval(sendHeartbeat, 20_000);

    return () => clearInterval(interval);
  }, []);

  return null; // Componente invisível
}
