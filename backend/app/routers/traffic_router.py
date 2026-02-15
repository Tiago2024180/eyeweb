"""
===========================================
Eye Web Backend — Traffic Monitor Router
===========================================
API endpoints for the admin traffic monitoring dashboard.

Endpoints (PROTEGIDOS — requerem token admin):
    GET  /admin/traffic/stats          — Dashboard statistics
    GET  /admin/traffic/connections    — Active connections
    GET  /admin/traffic/logs           — Paginated request logs
    GET  /admin/traffic/suspicious     — Suspicious activity events
    GET  /admin/traffic/detailed-logs  — Wireshark-style combined timeline
    GET  /admin/traffic/blocked        — Blocked IPs list
    POST /admin/traffic/block-ip       — Manually block an IP
    POST /admin/traffic/unblock-ip     — Unblock an IP

Endpoints (PÚBLICOS — sem autenticação):
    GET  /check-ip                  — Check if IP is blocked (middleware)
    POST /visit                     — Log page visit from frontend
    POST /heartbeat                 — Heartbeat to maintain online status
    POST /admin-heartbeat            — Admin heartbeat (verifies admin + tags IP)
"""

import os
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from ..dependencies import verify_admin

# ─── ROUTER ADMIN (protegido — requer token admin) ───
router = APIRouter(
    prefix="/admin/traffic",
    tags=["admin-traffic"],
    dependencies=[Depends(verify_admin)],
)

# ─── ROUTER PÚBLICO (sem autenticação) ───────────────
visit_router = APIRouter(tags=["traffic-visit"])


# ─── RATE LIMITER para endpoints públicos ─────────────
_public_rate: dict[str, list[float]] = defaultdict(list)
_PUBLIC_RATE_WINDOW = 60    # 60 segundos
_PUBLIC_RATE_LIMIT = 40     # máximo 40 requests/min por IP (heartbeat=3 + check-ip + visitas)


def _check_public_rate_limit(ip: str) -> bool:
    """Retorna True se o IP excedeu o rate limit (deve rejeitar)."""
    now = time.time()
    cutoff = now - _PUBLIC_RATE_WINDOW
    # Limpar entradas antigas
    _public_rate[ip] = [t for t in _public_rate[ip] if t > cutoff]
    if len(_public_rate[ip]) >= _PUBLIC_RATE_LIMIT:
        return True
    _public_rate[ip].append(now)
    # Limpar cache se crescer demais (evitar memory leak)
    if len(_public_rate) > 10000:
        stale = [k for k, v in _public_rate.items() if not v or v[-1] < cutoff]
        for k in stale:
            del _public_rate[k]
    return False


# ─── HELPERS ──────────────────────────────────────────

def _url():
    return os.getenv("SUPABASE_URL", "")


def _headers():
    key = os.getenv("SUPABASE_SERVICE_KEY", "")
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }


def _parse_count(resp) -> int:
    """Parse total count from PostgREST Content-Range header."""
    cr = resp.headers.get("content-range", "*/0")
    total = cr.split("/")[-1]
    return int(total) if total not in ("*", "") else 0


# ─── MODELS ───────────────────────────────────────────

class BlockIPRequest(BaseModel):
    ip: str
    reason: str


class UnblockIPRequest(BaseModel):
    ip: str


class BlockDeviceRequest(BaseModel):
    fingerprint_hash: str
    reason: str


class UnblockDeviceRequest(BaseModel):
    fingerprint_hash: str


class RegisterFPRequest(BaseModel):
    hash: str
    hardwareHash: str = ""
    components: dict
    ip: str = ""


# ─── LOCALHOST IPs to exclude from dashboard ─────────
_LOCALHOST_IPS = {"127.0.0.1", "::1", "localhost", "unknown", ""}

# ─── Infrastructure IPs to hide (Vercel, Render, n8n, HuggingFace, AWS) ───
# Cloud-provider CIDR ranges that generate noise in the dashboard.
# Uses broad ranges to avoid constantly adding individual /16 blocks.
_INFRA_CIDRS = [
    # ── AWS (all regions used by Render, n8n, HuggingFace) ──
    ip_network("3.0.0.0/8"),        # 3.x.x.x   (us-west, eu-west, etc.)
    ip_network("13.32.0.0/11"),     # 13.32–63   (CloudFront, EC2 us/eu)
    ip_network("15.0.0.0/8"),       # 15.x.x.x   (eu-west-3, etc.)
    ip_network("18.0.0.0/8"),       # 18.x.x.x   (us-east, eu, etc.)
    ip_network("35.160.0.0/11"),    # 35.160–191 (us-west-2, eu)
    ip_network("44.192.0.0/10"),    # 44.192–255 (EC2 global)
    ip_network("51.44.0.0/16"),     # 51.44.x.x  (eu-west-3 Paris)
    ip_network("52.0.0.0/8"),       # 52.x.x.x   (EC2 global)
    ip_network("54.0.0.0/8"),       # 54.x.x.x   (EC2 global)
    ip_network("99.77.0.0/16"),     # 99.77.x.x  (CloudFront)
    ip_network("184.72.0.0/15"),    # 184.72–73   (EC2 us-west-1)
    # ── DigitalOcean (Vercel infrastructure) ──
    ip_network("24.144.0.0/16"),    # 24.144.x.x
    ip_network("24.199.0.0/16"),    # 24.199.x.x
    ip_network("64.23.0.0/16"),     # 64.23.x.x
    ip_network("68.183.0.0/16"),    # 68.183.x.x
    ip_network("134.199.0.0/16"),   # 134.199.x.x
    ip_network("137.184.0.0/16"),   # 137.184.x.x
    ip_network("138.68.0.0/16"),    # 138.68.x.x
    ip_network("139.59.0.0/16"),    # 139.59.x.x
    ip_network("143.198.0.0/16"),   # 143.198.x.x
    ip_network("143.244.0.0/16"),   # 143.244.x.x
    ip_network("146.190.0.0/16"),   # 146.190.x.x
    ip_network("147.182.0.0/16"),   # 147.182.x.x
    ip_network("157.245.0.0/16"),   # 157.245.x.x
    ip_network("159.65.0.0/16"),    # 159.65.x.x
    ip_network("159.89.0.0/16"),    # 159.89.x.x
    ip_network("159.203.0.0/16"),   # 159.203.x.x
    ip_network("161.35.0.0/16"),    # 161.35.x.x
    ip_network("164.90.0.0/15"),    # 164.90–91
    ip_network("164.92.0.0/16"),    # 164.92.x.x
    ip_network("165.22.0.0/16"),    # 165.22.x.x
    ip_network("165.227.0.0/16"),   # 165.227.x.x
    ip_network("165.232.0.0/16"),   # 165.232.x.x
    ip_network("167.71.0.0/16"),    # 167.71.x.x
    ip_network("167.172.0.0/16"),   # 167.172.x.x
    ip_network("170.64.0.0/16"),    # 170.64.x.x
    ip_network("174.138.0.0/16"),   # 174.138.x.x
    ip_network("178.128.0.0/16"),   # 178.128.x.x
    ip_network("178.62.0.0/16"),    # 178.62.x.x
    ip_network("188.166.0.0/16"),   # 188.166.x.x
    ip_network("206.189.0.0/16"),   # 206.189.x.x
    ip_network("209.97.0.0/16"),    # 209.97.x.x
    # ── Google Cloud (Render) ──
    ip_network("34.0.0.0/8"),       # 34.x.x.x   (GCP global)
    ip_network("35.184.0.0/13"),    # 35.184–191
    ip_network("35.192.0.0/12"),    # 35.192–207
    ip_network("35.208.0.0/12"),    # 35.208–223
    ip_network("35.224.0.0/12"),    # 35.224–239
    ip_network("35.240.0.0/12"),    # 35.240–255
    # ── Microsoft Azure ──
    ip_network("104.40.0.0/13"),    # 104.40–47
    ip_network("104.208.0.0/13"),   # 104.208–215
]

def _is_infra_ip(ip_str: str) -> bool:
    """Check if an IP belongs to known infrastructure CIDRs."""
    try:
        addr = ip_address(ip_str)
        return any(addr in cidr for cidr in _INFRA_CIDRS)
    except (ValueError, TypeError):
        return False

# ─── ENDPOINTS ────────────────────────────────────────

@router.get("/connections")
async def get_connections():
    """
    Unique connections today — one row per device (fingerprint).
    Falls back to IP-based grouping when fingerprint is not available.
    Data is for today only (UTC day).
    """
    from ..services.traffic_service import TrafficService
    url = _url()
    headers = {**_headers(), "Prefer": "return=representation"}
    if not url:
        raise HTTPException(500, "Supabase not configured")

    ts = TrafficService.get()

    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).strftime('%Y-%m-%dT%H:%M:%SZ')

    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(
                f"{url}/rest/v1/traffic_logs?select=ip,country,city,is_vpn,vpn_provider,method,created_at,fingerprint_hash"
                f"&created_at=gte.{today_start}&order=created_at.asc",
                headers=headers, timeout=10.0,
            )

        if r.status_code != 200:
            return {"connections": []}

        rows = r.json()
        if not rows:
            return {"connections": []}

        # Group by fingerprint_hash (when available) or IP
        seen: dict = {}
        for row in rows:
            ip = row.get("ip", "")
            method = row.get("method", "")
            fp = row.get("fingerprint_hash", "") or ""
            if not ip or ip in _LOCALHOST_IPS or _is_infra_ip(ip):
                continue
            # Skip API calls without fingerprint — noise (OPTIONS/POST/GET)
            if method in ("OPTIONS", "POST", "GET") and not fp:
                continue

            group_key = fp if fp else f"ip:{ip}"

            if group_key not in seen:
                seen[group_key] = {
                    "fingerprint_hash": fp,
                    "ips": [],
                    "country": row.get("country", ""),
                    "city": row.get("city", ""),
                    "is_vpn": row.get("is_vpn", False),
                    "vpn_provider": row.get("vpn_provider", ""),
                    "method": row.get("method", ""),
                    "requests": 0,
                    "online": False,
                    "_ips_set": set(),
                    "_last_seen": "",
                }

            conn = seen[group_key]
            conn["requests"] += 1

            # Track unique IPs
            if ip not in conn["_ips_set"]:
                conn["_ips_set"].add(ip)
                conn["ips"].append(ip)

            # Track VPN flag
            if row.get("is_vpn"):
                conn["is_vpn"] = True

            # Prefer PAGE over GET
            if row.get("method") == "PAGE":
                conn["method"] = "PAGE"

            # Track most recent activity (rows are ordered ASC)
            conn["_last_seen"] = row.get("created_at", "")

        # Determine online: heartbeat (in-memory) OR recent Supabase activity (< 2 min)
        # Also check if any IP belongs to an admin
        for conn in seen.values():
            fp = conn.get("fingerprint_hash", "")
            # Prefer per-fingerprint heartbeat; fallback to IP heartbeat
            has_heartbeat = ts.is_online_fp(fp) if fp else any(ts.is_online(ip) for ip in conn["_ips_set"])
            # Admin badge: baseado no fingerprint (não no IP, senão todos
            # os dispositivos na mesma rede apareceriam como admin)
            is_admin = ts.is_admin_fp(conn.get("fingerprint_hash", ""))
            recent = False
            last_seen = conn.pop("_last_seen", "")
            if last_seen:
                try:
                    ls_dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                    recent = (now - ls_dt).total_seconds() < 120
                except Exception:
                    pass
            conn["online"] = has_heartbeat or recent
            conn["is_admin"] = is_admin
            del conn["_ips_set"]

        # Sort: online first, then by most requests
        connections = sorted(
            seen.values(),
            key=lambda c: (0 if c["online"] else 1, -c["requests"]),
        )

        return {"connections": connections}
    except Exception:
        return {"connections": []}


@router.get("/stats")
async def get_traffic_stats():
    """Dashboard statistics: requests today, online IPs, suspicious events, blocked total."""
    from ..services.traffic_service import TrafficService
    url = _url()
    headers = _headers()
    if not url:
        raise HTTPException(500, "Supabase not configured")

    ts = TrafficService.get()
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).strftime('%Y-%m-%dT%H:%M:%SZ')

    count_headers = {**headers, "Prefer": "count=exact", "Range": "0-0"}

    try:
        async with httpx.AsyncClient() as c:

            # 3 queries ao Supabase (requests, suspicious, blocked)
            r1 = await c.get(
                f"{url}/rest/v1/traffic_logs?select=id&created_at=gte.{today_start}"
                f"&ip=not.in.(127.0.0.1,::1,localhost)",
                headers=count_headers, timeout=8.0,
            )
            r3 = await c.get(
                f"{url}/rest/v1/traffic_suspicious?select=id&created_at=gte.{today_start}",
                headers=count_headers, timeout=8.0,
            )
            r4 = await c.get(
                f"{url}/rest/v1/traffic_blocked_ips?select=id",
                headers=count_headers, timeout=8.0,
            )

        # IPs online = heartbeat ativo (mesmo critério do 🟢 na tabela)
        online_ips = ts.online_count()

        return {
            "requests_today": _parse_count(r1) if r1 else 0,
            "active_ips_5m": online_ips,
            "suspicious_today": _parse_count(r3) if r3 else 0,
            "blocked_total": _parse_count(r4) if r4 else 0,
        }
    except Exception as e:
        return {
            "requests_today": 0,
            "active_ips_5m": 0,
            "suspicious_today": 0,
            "blocked_total": 0,
        }


@router.get("/logs")
async def get_traffic_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    ip: str = Query("", description="Filter by IP"),
):
    """Paginated request logs, newest first."""
    url = _url()
    headers = {**_headers(), "Prefer": "return=representation,count=exact"}
    if not url:
        raise HTTPException(500, "Supabase not configured")

    query = f"{url}/rest/v1/traffic_logs?select=*&order=created_at.desc&limit={limit}&offset={offset}"
    if ip:
        query += f"&ip=eq.{ip}"
    else:
        query += "&ip=not.in.(127.0.0.1,::1,localhost)"

    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(query, headers=headers, timeout=10.0)

        if r.status_code != 200:
            return {"logs": [], "total": 0}

        logs = [l for l in r.json() if not _is_infra_ip(l.get("ip", ""))]
        return {"logs": logs, "total": len(logs)}
    except Exception:
        return {"logs": [], "total": 0}


@router.get("/suspicious")
async def get_suspicious_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Paginated suspicious activity events, newest first."""
    url = _url()
    headers = {**_headers(), "Prefer": "return=representation,count=exact"}
    if not url:
        raise HTTPException(500, "Supabase not configured")

    query = f"{url}/rest/v1/traffic_suspicious?select=*&order=created_at.desc&limit={limit}&offset={offset}"

    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(query, headers=headers, timeout=10.0)

        if r.status_code != 200:
            return {"events": [], "total": 0}

        return {"events": r.json(), "total": _parse_count(r)}
    except Exception:
        return {"events": [], "total": 0}


# ═══════════════════════════════════════════════════════
# DETAILED LOGS — Wireshark-style unified timeline
# ═══════════════════════════════════════════════════════


@router.get("/detailed-logs")
async def get_detailed_logs(
    limit: int = Query(200, ge=1, le=500),
):
    """
    Wireshark-style unified timeline — merges traffic_logs + traffic_suspicious
    into a single chronological feed, newest first.
    Filtering (by IP / type) is done client-side for instant UX.
    """
    url = _url()
    headers = {**_headers(), "Prefer": "return=representation"}
    if not url:
        raise HTTPException(500, "Supabase not configured")

    entries: list[dict] = []

    # ─── Fetch traffic_logs (requests) ───
    q_logs = (
        f"{url}/rest/v1/traffic_logs?select=*"
        f"&order=created_at.desc&limit={limit}"
        f"&ip=not.in.(127.0.0.1,::1,localhost)"
    )
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(q_logs, headers=headers, timeout=10.0)
        if r.status_code == 200:
            for log in r.json():
                if _is_infra_ip(log.get("ip", "")):
                    continue
                entries.append({
                    "_type": "request",
                    "id": f"req_{log['id']}",
                    "ip": log.get("ip", ""),
                    "timestamp": log.get("created_at", ""),
                    "method": log.get("method", ""),
                    "path": log.get("path", ""),
                    "status_code": log.get("status_code", 0),
                    "user_agent": log.get("user_agent", ""),
                    "country": log.get("country", ""),
                    "city": log.get("city", ""),
                    "is_vpn": log.get("is_vpn", False),
                    "vpn_provider": log.get("vpn_provider", ""),
                    "response_time_ms": log.get("response_time_ms", 0),
                    "event": None,
                    "severity": None,
                    "details": None,
                    "auto_blocked": False,
                })
    except Exception:
        pass

    # ─── Fetch traffic_suspicious (threats) ───
    q_threats = (
        f"{url}/rest/v1/traffic_suspicious?select=*"
        f"&order=created_at.desc&limit={limit}"
    )
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(q_threats, headers=headers, timeout=10.0)
        if r.status_code == 200:
            for evt in r.json():
                entries.append({
                    "_type": "threat",
                    "id": f"thr_{evt['id']}",
                    "ip": evt.get("ip", ""),
                    "timestamp": evt.get("created_at", ""),
                    "method": "",
                    "path": evt.get("path", ""),
                    "status_code": 0,
                    "user_agent": "",
                    "country": "",
                    "city": "",
                    "is_vpn": False,
                    "vpn_provider": "",
                    "response_time_ms": 0,
                    "event": evt.get("event", ""),
                    "severity": evt.get("severity", ""),
                    "details": evt.get("details", ""),
                    "auto_blocked": evt.get("auto_blocked", False),
                })
    except Exception:
        pass

    # ─── Sort by timestamp descending and trim ───
    entries.sort(key=lambda e: e["timestamp"], reverse=True)
    entries = entries[:limit]

    return {"entries": entries, "total": len(entries)}


@router.get("/blocked")
async def get_blocked_ips():
    """All blocked IPs and devices, newest first."""
    url = _url()
    headers = {**_headers(), "Prefer": "return=representation"}
    if not url:
        raise HTTPException(500, "Supabase not configured")

    try:
        async with httpx.AsyncClient() as c:
            r1 = await c.get(
                f"{url}/rest/v1/traffic_blocked_ips?select=*&order=created_at.desc",
                headers=headers, timeout=10.0,
            )
            r2 = await c.get(
                f"{url}/rest/v1/traffic_blocked_devices?select=*&order=created_at.desc",
                headers=headers, timeout=10.0,
            )

        blocked_ips = r1.json() if r1.status_code == 200 else []
        blocked_devices = r2.json() if r2.status_code == 200 else []

        return {"blocked": blocked_ips, "blocked_devices": blocked_devices}
    except Exception:
        return {"blocked": [], "blocked_devices": []}


@router.post("/block-ip")
async def block_ip(req: BlockIPRequest):
    """Manually block an IP address."""
    from ..services.traffic_service import TrafficService
    ts = TrafficService.get()

    # Impedir bloqueio de IPs de administradores (só no endpoint manual)
    if ts.is_admin_ip(req.ip):
        raise HTTPException(
            status_code=403,
            detail=f"IP {req.ip} pertence a um administrador e não pode ser bloqueado"
        )

    await ts.block_ip(req.ip, req.reason, "admin")
    return {"success": True, "message": f"IP {req.ip} bloqueado"}


@router.post("/unblock-ip")
async def unblock_ip(req: UnblockIPRequest):
    """Unblock an IP address."""
    from ..services.traffic_service import TrafficService
    ts = TrafficService.get()
    await ts.unblock_ip(req.ip)
    return {"success": True, "message": f"IP {req.ip} desbloqueado"}


@router.post("/block-device")
async def block_device(req: BlockDeviceRequest):
    """Block a device by fingerprint hash. Also blocks all associated IPs."""
    from ..services.traffic_service import TrafficService
    ts = TrafficService.get()

    try:
        await ts.block_device(req.fingerprint_hash, req.reason, "admin")
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    return {"success": True, "message": f"Device {req.fingerprint_hash[:12]}... bloqueado"}


@router.post("/unblock-device")
async def unblock_device(req: UnblockDeviceRequest):
    """Unblock a device and all its associated IPs."""
    from ..services.traffic_service import TrafficService
    ts = TrafficService.get()
    await ts.unblock_device(req.fingerprint_hash)
    return {"success": True, "message": f"Device {req.fingerprint_hash[:12]}... desbloqueado"}


# ═══════════════════════════════════════════════════════
# PUBLIC ENDPOINTS — sem autenticação (middleware / frontend beacon)
# ═══════════════════════════════════════════════════════


@visit_router.get("/check-ip")
async def check_ip_blocked(
    ip: str = Query(..., description="IP to check"),
    path: str = Query("", description="Page path (optional — logs visit)"),
    ua: str = Query("", description="User-Agent (optional)"),
    fp: str = Query("", description="Device fingerprint hash (optional)"),
    hwfp: str = Query("", description="Hardware fingerprint hash (anti browser-switch)"),
):
    """
    Quick blocked check — used by Next.js middleware to enforce full site block.
    Checks IP, device fingerprint, AND hardware fingerprint.
    Also logs a PAGE visit if 'path' is provided.
    Rate limited para evitar abuso.
    """
    import asyncio
    from ..services.traffic_service import TrafficService

    # Rate limit por IP
    if _check_public_rate_limit(ip):
        return {"blocked": False, "rate_limited": True}

    ts = TrafficService.get()

    # Verificar bloqueio por IP
    blocked = ts.is_blocked(ip)

    # Verificar bloqueio por fingerprint (se fornecido)
    if not blocked and fp:
        blocked = ts.is_device_blocked(fp)

    # Verificar bloqueio por hardware hash (anti browser-switch)
    if not blocked and hwfp:
        blocked = ts.is_hardware_blocked(hwfp)

    # Sempre registar heartbeat (mantém estado "online" no dashboard)
    if not blocked:
        ts.heartbeat(ip, fp)

    # Se path foi enviado → registar visita no Supabase (fire-and-forget)
    if path and not blocked:
        asyncio.create_task(ts.safe_log_request(
            ip=ip,
            method="PAGE",
            path=path,
            status_code=200,
            user_agent=(ua or "")[:500],
            response_time_ms=0,
            fingerprint_hash=fp,
        ))

    return {"blocked": blocked}


class VisitRequest(BaseModel):
    page: str


@visit_router.post("/visit")
async def log_visit(req: VisitRequest, request: Request):
    """
    Regista uma visita de página enviada pelo frontend.
    O frontend chama isto a cada navegação para que toda a
    atividade (não só chamadas API) apareça no traffic monitor.
    Rate limited para evitar abuso.
    """
    import asyncio
    from ..services.traffic_service import TrafficService

    ip = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if not ip:
        ip = request.client.host if request.client else "unknown"

    # Rate limit por IP
    if _check_public_rate_limit(ip):
        return {"ok": False, "error": "rate_limited"}

    ts = TrafficService.get()

    # Se está bloqueado, rejeitar
    if ts.is_blocked(ip):
        return {"ok": False}

    # Sanitizar path (máx 500 chars, sem scripts)
    page = (req.page or "/")[:500]

    # Log fire-and-forget (não atrasar resposta)
    asyncio.create_task(ts.safe_log_request(
        ip=ip,
        method="PAGE",
        path=page,
        status_code=200,
        user_agent=request.headers.get("user-agent", ""),
        response_time_ms=0,
    ))

    return {"ok": True}

@visit_router.post("/heartbeat")
async def heartbeat(request: Request):
    """
    Heartbeat — frontend envia a cada ~30s para manter estado online.
    Usado pelo endpoint /connections para mostrar 🟢 Online / 🔴 Offline.
    Rate limited para evitar abuso.
    """
    from ..services.traffic_service import TrafficService

    ip = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if not ip:
        ip = request.client.host if request.client else "unknown"

    # Rate limit por IP
    if _check_public_rate_limit(ip):
        return {"ok": False, "error": "rate_limited"}

    ts = TrafficService.get()
    ts.heartbeat(ip)
    return {"ok": True}


class AdminHeartbeatRequest(BaseModel):
    ip: str
    fp: str = ""


@visit_router.post("/admin-heartbeat")
async def admin_heartbeat(req: AdminHeartbeatRequest, request: Request):
    """
    Admin heartbeat — verifica token admin e regista IP como admin.
    Chamado pelo Next.js proxy /api/admin-heartbeat a cada 20s
    quando o admin está nas páginas /admin/*.
    IPs admin não podem ser bloqueados.
    """
    from ..services.traffic_service import TrafficService

    # Verificar token admin (mesma lógica de verify_admin mas manual)
    try:
        admin_data = await verify_admin(request)
    except HTTPException:
        return {"ok": False, "error": "unauthorized"}

    ip = req.ip or ""
    if not ip:
        return {"ok": False}

    ts = TrafficService.get()
    ts.heartbeat(ip, req.fp)
    ts.register_admin_ip(ip)
    # Registar fingerprint como admin (para badge preciso por dispositivo)
    if req.fp:
        ts.register_admin_fp(req.fp)
    return {"ok": True}


@visit_router.post("/register-fingerprint")
async def register_fingerprint(req: RegisterFPRequest):
    """
    Register device fingerprint from the frontend.
    Stores fingerprint components, does fuzzy matching against blocked devices.
    Returns { blocked: true } if the device should be blocked.
    """
    from ..services.traffic_service import TrafficService

    ip = req.ip or ""

    # Rate limit por IP
    if ip and _check_public_rate_limit(ip):
        return {"blocked": False, "rate_limited": True}

    ts = TrafficService.get()
    # Incluir hardware hash nos componentes para o backend guardar
    comps = req.components.copy() if req.components else {}
    if req.hardwareHash:
        comps["hardware_hash"] = req.hardwareHash
    blocked = await ts.register_fingerprint(ip, req.hash, comps)
    return {"blocked": blocked}