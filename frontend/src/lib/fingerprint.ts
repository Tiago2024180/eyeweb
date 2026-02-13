/**
 * ═══════════════════════════════════════════════════════
 * Eye Web — Device Fingerprinting
 * ═══════════════════════════════════════════════════════
 *
 * Gera uma impressão digital única do dispositivo usando APIs nativas do browser.
 * Sem bibliotecas externas — 100% vanilla JS.
 *
 * Componentes e pesos (devem corresponder ao backend):
 *   Canvas=25, WebGL=30, Audio=20, Screen=10, CPU=5, RAM=3, TZ=3, Platform=2, UA=2
 *
 * Total: 100 pontos. Threshold de match: ≥70 pontos = mesmo dispositivo.
 *
 * HARDWARE HASH (anti-browser-switch):
 *   Hash separado gerado APENAS com componentes de hardware que NÃO mudam
 *   entre browsers (WebGL GPU, Screen, CPU, RAM, TZ, Platform, DPR, TouchPoints).
 *   Permite detetar o mesmo dispositivo mesmo que mude de browser ou use VPN.
 */

// ─── TYPES ───────────────────────────────────────────

export interface FingerprintComponents {
  canvas: string;      // SHA-256 do canvas rendering
  webgl: string;       // GPU vendor~renderer
  audio: string;       // Audio context fingerprint value
  screen: string;      // WxHxColorDepth
  cpu: number;         // navigator.hardwareConcurrency
  ram: number;         // navigator.deviceMemory
  tz: string;          // Timezone (ex: Europe/Lisbon)
  platform: string;    // navigator.platform
  ua: string;          // User agent (truncated)
  dpr: number;         // devicePixelRatio (hardware-invariant)
  touchPoints: number; // maxTouchPoints (hardware-invariant)
  langs: string;       // Primary language (OS setting)
}

export interface DeviceFingerprint {
  hash: string;
  hardwareHash: string; // Hash de APENAS componentes hardware (anti browser-switch)
  components: FingerprintComponents;
}

// ─── SHA-256 via Web Crypto API ──────────────────────

async function sha256(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ─── CANVAS FINGERPRINT ─────────────────────────────
// Cada GPU/driver renderiza text+gradients de forma ligeiramente diferente.

function getCanvasFingerprint(): string {
  try {
    const c = document.createElement('canvas');
    c.width = 220;
    c.height = 60;
    const ctx = c.getContext('2d');
    if (!ctx) return '';

    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('Cwm fjord veg', 2, 15);
    ctx.fillStyle = 'rgba(102,204,0,0.7)';
    ctx.fillText('Cwm fjord veg', 4, 17);

    const gradient = ctx.createLinearGradient(0, 0, c.width, 0);
    gradient.addColorStop(0, '#f00');
    gradient.addColorStop(0.5, '#0f0');
    gradient.addColorStop(1, '#00f');
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 35, 220, 10);

    return c.toDataURL();
  } catch {
    return '';
  }
}

// ─── WEBGL GPU FINGERPRINT ──────────────────────────
// GPU vendor + renderer são únicos por hardware.

function getWebGLFingerprint(): string {
  try {
    const c = document.createElement('canvas');
    const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    if (!gl || !(gl instanceof WebGLRenderingContext)) return '';

    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    if (!ext) return gl.getParameter(gl.RENDERER) || '';

    const vendor = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '';
    const renderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '';
    return `${vendor}~${renderer}`;
  } catch {
    return '';
  }
}

// ─── AUDIO FINGERPRINT (OfflineAudioContext) ─────────
// DAC + audio pipeline são únicos por hardware/driver.

function getAudioFingerprint(): Promise<string> {
  return new Promise((resolve) => {
    try {
      const Ctx = window.OfflineAudioContext || (window as unknown as { webkitOfflineAudioContext: typeof OfflineAudioContext }).webkitOfflineAudioContext;
      if (!Ctx) { resolve(''); return; }

      const ctx = new Ctx(1, 44100, 44100);
      const osc = ctx.createOscillator();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(10000, ctx.currentTime);

      const comp = ctx.createDynamicsCompressor();
      comp.threshold.setValueAtTime(-50, ctx.currentTime);
      comp.knee.setValueAtTime(40, ctx.currentTime);
      comp.ratio.setValueAtTime(12, ctx.currentTime);
      comp.attack.setValueAtTime(0, ctx.currentTime);
      comp.release.setValueAtTime(0.25, ctx.currentTime);

      osc.connect(comp);
      comp.connect(ctx.destination);
      osc.start(0);

      ctx.startRendering()
        .then((buf) => {
          const d = buf.getChannelData(0);
          let sum = 0;
          for (let i = 4500; i < 5000; i++) sum += Math.abs(d[i]);
          resolve(sum.toFixed(6));
        })
        .catch(() => resolve(''));

      setTimeout(() => resolve('timeout'), 2000);
    } catch {
      resolve('');
    }
  });
}

// ─── SCREEN FINGERPRINT ─────────────────────────────

function getScreenFP(): string {
  return `${screen.width}x${screen.height}x${screen.colorDepth}`;
}

// ═══════════════════════════════════════════════════════
// MAIN — Generate complete device fingerprint
// ═══════════════════════════════════════════════════════

export async function generateFingerprint(): Promise<DeviceFingerprint> {
  const canvasRaw = getCanvasFingerprint();
  const webgl = getWebGLFingerprint();
  const audio = await getAudioFingerprint();
  const screenFp = getScreenFP();
  const cpu = navigator.hardwareConcurrency || 0;
  const ram = (navigator as unknown as { deviceMemory?: number }).deviceMemory || 0;
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
  const platform = navigator.platform || '';
  const ua = navigator.userAgent.slice(0, 200);
  const dpr = typeof window !== 'undefined' ? window.devicePixelRatio || 1 : 1;
  const touchPoints = navigator.maxTouchPoints || 0;
  const langs = (navigator.languages?.[0] || navigator.language || '');

  const components: FingerprintComponents = {
    canvas: await sha256(canvasRaw),
    webgl,
    audio,
    screen: screenFp,
    cpu,
    ram,
    tz,
    platform,
    ua,
    dpr,
    touchPoints,
    langs,
  };

  // Hash completo (todos os componentes — identifica browser+device exacto)
  const hash = await sha256(JSON.stringify(components));

  // Hardware Hash — APENAS componentes que NÃO mudam entre browsers.
  // Mesmo GPU, ecrã, CPU, RAM, timezone, etc. = mesmo hardware hash.
  // Isto deteta o dispositivo mesmo que use outro browser ou limpe cookies.
  const hardwareHash = await sha256([
    webgl,        // GPU vendor~renderer (hardware-unique)
    screenFp,     // WxHxColorDepth
    cpu,          // CPU cores
    ram,          // RAM
    tz,           // Timezone
    platform,     // OS
    dpr,          // devicePixelRatio
    touchPoints,  // maxTouchPoints
  ].join('|'));

  return { hash, hardwareHash, components };
}

// ─── Cookie management (middleware pode ler) ─────────

export function setFingerprintCookie(hash: string): void {
  const secure = location.protocol === 'https:' ? ';Secure' : '';
  document.cookie = `__ewfp=${hash};path=/;max-age=31536000;SameSite=Lax${secure}`;
}

export function getFingerprintCookie(): string {
  const match = document.cookie.match(/(?:^|;\s*)__ewfp=([^;]*)/);
  return match ? match[1] : '';
}

// Hardware hash cookie — sobrevive troca de browser (middleware lê)
export function setHardwareFingerprintCookie(hwHash: string): void {
  const secure = location.protocol === 'https:' ? ';Secure' : '';
  document.cookie = `__ewhw=${hwHash};path=/;max-age=31536000;SameSite=Lax${secure}`;
}

export function getHardwareFingerprintCookie(): string {
  const match = document.cookie.match(/(?:^|;\s*)__ewhw=([^;]*)/);
  return match ? match[1] : '';
}

// ─── Session cache (evitar re-gerar em cada página) ──

export function cacheFingerprint(fp: DeviceFingerprint): void {
  try { sessionStorage.setItem('__ewfp_data', JSON.stringify(fp)); } catch {}
}

export function getCachedFingerprint(): DeviceFingerprint | null {
  try {
    const raw = sessionStorage.getItem('__ewfp_data');
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}
