'use client';

/**
 * PageTracker — componente invisível que:
 * 1. Gera fingerprint do dispositivo e guarda em cookie
 * 2. Regista o fingerprint no backend (uma vez por sessão)
 * 3. Envia heartbeats periódicos para manter o estado online
 * 4. Se o dispositivo estiver bloqueado, esconde todo o site
 */

import { useEffect, useRef, useState } from 'react';
import { usePathname } from 'next/navigation';
import {
  generateFingerprint,
  setFingerprintCookie,
  getFingerprintCookie,
  cacheFingerprint,
  getCachedFingerprint,
} from '@/lib/fingerprint';

export default function PageTracker() {
  const pathname = usePathname();
  const fpSent = useRef(false);
  const [deviceBlocked, setDeviceBlocked] = useState(false);

  // ─── Gerar fingerprint e registar no backend (uma vez por sessão) ──
  useEffect(() => {
    // Não executar em rotas admin (admin não deve ser bloqueado pelo próprio sistema)
    if (pathname.startsWith('/admin')) return;

    async function initFingerprint() {
      if (fpSent.current) return;
      fpSent.current = true;

      try {
        // Verificar se já temos em cache (evita re-gerar em cada navegação)
        let fp = getCachedFingerprint();
        if (!fp) {
          fp = await generateFingerprint();
          cacheFingerprint(fp);
        }

        // Definir cookie para o middleware poder ler
        setFingerprintCookie(fp.hash);

        // Registar no backend (inclui fuzzy matching contra dispositivos bloqueados)
        const r = await fetch('/api/register-fp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ hash: fp.hash, components: fp.components }),
          keepalive: true,
        });

        if (r.ok) {
          const data = await r.json();
          if (data.blocked) {
            setDeviceBlocked(true);
          }
        }
      } catch {
        // Silenciar — fingerprint nunca deve quebrar a experiência
      }
    }

    initFingerprint();
  }, [pathname]);

  // ─── Heartbeat periódico (20s) — manter estado online ──
  useEffect(() => {
    // Não executar em rotas admin
    if (pathname.startsWith('/admin')) return;

    const sendHeartbeat = async () => {
      try {
        const r = await fetch('/api/heartbeat', {
          method: 'POST',
          keepalive: true,
        });

        if (r.ok) {
          const data = await r.json();
          // Se o heartbeat detectar que o dispositivo foi bloqueado
          if (data.blocked) {
            setDeviceBlocked(true);
          }
        }
      } catch {
        // Silenciar
      }
    };

    sendHeartbeat();
    const interval = setInterval(sendHeartbeat, 20_000);
    return () => clearInterval(interval);
  }, [pathname]);

  // ─── Se o dispositivo foi bloqueado, esconder TUDO ──
  // Mostra uma página 404 genérica que não revela que o Eye Web existe.
  if (deviceBlocked) {
    return (
      <div
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: 999999,
          background: '#fff',
          color: '#000',
          fontFamily: "-apple-system,BlinkMacSystemFont,Roboto,'Segoe UI','Fira Sans',Avenir,'Helvetica Neue','Lucida Grande',sans-serif",
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          textAlign: 'center',
        }}
      >
        <div>
          <h1 style={{
            display: 'inline-block',
            margin: '0 20px 0 0',
            padding: '0 23px 0 0',
            fontSize: '24px',
            fontWeight: 500,
            verticalAlign: 'top',
            lineHeight: '49px',
            borderRight: '1px solid rgba(0,0,0,.3)',
          }}>
            404
          </h1>
          <div style={{ display: 'inline-block' }}>
            <h2 style={{
              fontSize: '14px',
              fontWeight: 400,
              lineHeight: '49px',
              margin: 0,
            }}>
              This page could not be found.
            </h2>
          </div>
        </div>
      </div>
    );
  }

  return null; // Componente invisível quando não bloqueado
}
