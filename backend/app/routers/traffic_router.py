"""
===========================================
Eye Web Backend — Traffic Monitor Router
===========================================
API endpoints for the admin traffic monitoring dashboard.

Endpoints (PROTEGIDOS — requerem token admin):
    GET  /admin/traffic/stats       — Dashboard statistics
    GET  /admin/traffic/connections  — Active connections
    GET  /admin/traffic/logs        — Paginated request logs
    GET  /admin/traffic/suspicious  — Suspicious activity events
    GET  /admin/traffic/blocked     — Blocked IPs list
    POST /admin/traffic/block-ip    — Manually block an IP
    POST /admin/traffic/unblock-ip  — Unblock an IP

Endpoints (PÚBLICOS — sem autenticação):
    GET  /check-ip                  — Check if IP is blocked (middleware)
    POST /visit                     — Log page visit from frontend
    POST /heartbeat                 — Heartbeat to maintain online status
"""

import os
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

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


# ─── LOCALHOST IPs to exclude from dashboard ─────────
_LOCALHOST_IPS = {"127.0.0.1", "::1", "localhost", "unknown", ""}

# ─── ENDPOINTS ────────────────────────────────────────

@router.get("/connections")
async def get_connections():
    """
    Unique connections today — one row per IP.
    Shows: IP, location, VPN, online/offline, first seen, method.
    Data is for today only (UTC day).
    """
    from ..services.traffic_service import TrafficService
    url = _url()
    headers = {**_headers(), "Prefer": "return=representation"}
    if not url:
        raise HTTPException(500, "Supabase not configured")

    ts = TrafficService.get()

    # Today start (UTC midnight) — usar 'Z' em vez de '+00:00' para evitar
    # que PostgREST interprete '+' como espaço na query string
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).strftime('%Y-%m-%dT%H:%M:%SZ')

    try:
        # Get all distinct IPs that visited today
        async with httpx.AsyncClient() as c:
            r = await c.get(
                f"{url}/rest/v1/traffic_logs?select=ip,country,city,is_vpn,vpn_provider,method,created_at"
                f"&created_at=gte.{today_start}&order=created_at.asc",
                headers=headers, timeout=10.0,
            )

        if r.status_code != 200:
            return {"connections": []}

        rows = r.json()
        if not rows:
            return {"connections": []}

        # Group by IP — count requests + keep geo info
        seen: dict = {}
        for row in rows:
            ip = row.get("ip", "")
            if not ip or ip in _LOCALHOST_IPS:
                continue
            if ip not in seen:
                seen[ip] = {
                    "ip": ip,
                    "country": row.get("country", ""),
                    "city": row.get("city", ""),
                    "is_vpn": row.get("is_vpn", False),
                    "vpn_provider": row.get("vpn_provider", ""),
                    "method": row.get("method", ""),
                    "requests": 0,
                    "online": False,
                    "_last_seen": "",
                }
            seen[ip]["requests"] += 1
            # Prefer PAGE over GET (PAGE = real page visit, GET = internal API call)
            if row.get("method", "") == "PAGE":
                seen[ip]["method"] = "PAGE"
            # Track most recent activity (rows are ordered ASC)
            seen[ip]["_last_seen"] = row.get("created_at", "")

        # Determine online: heartbeat (in-memory) OR recent Supabase activity (< 2 min)
        for conn in seen.values():
            last_seen = conn.pop("_last_seen", "")
            recent = False
            if last_seen:
                try:
                    ls_dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                    recent = (now - ls_dt).total_seconds() < 120
                except Exception:
                    pass
            conn["online"] = ts.is_online(conn["ip"]) or recent

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

        return {"logs": r.json(), "total": _parse_count(r)}
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


@router.get("/blocked")
async def get_blocked_ips():
    """All blocked IPs, newest first."""
    url = _url()
    headers = {**_headers(), "Prefer": "return=representation"}
    if not url:
        raise HTTPException(500, "Supabase not configured")

    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(
                f"{url}/rest/v1/traffic_blocked_ips?select=*&order=created_at.desc",
                headers=headers, timeout=10.0,
            )

        if r.status_code != 200:
            return {"blocked": []}

        return {"blocked": r.json()}
    except Exception:
        return {"blocked": []}


@router.post("/block-ip")
async def block_ip(req: BlockIPRequest):
    """Manually block an IP address."""
    from ..services.traffic_service import TrafficService
    ts = TrafficService.get()
    await ts.block_ip(req.ip, req.reason, "admin")
    return {"success": True, "message": f"IP {req.ip} bloqueado"}


@router.post("/unblock-ip")
async def unblock_ip(req: UnblockIPRequest):
    """Unblock an IP address."""
    from ..services.traffic_service import TrafficService
    ts = TrafficService.get()
    await ts.unblock_ip(req.ip)
    return {"success": True, "message": f"IP {req.ip} desbloqueado"}


# ═══════════════════════════════════════════════════════
# PUBLIC ENDPOINTS — sem autenticação (middleware / frontend beacon)
# ═══════════════════════════════════════════════════════


@visit_router.get("/check-ip")
async def check_ip_blocked(
    ip: str = Query(..., description="IP to check"),
    path: str = Query("", description="Page path (optional — logs visit)"),
    ua: str = Query("", description="User-Agent (optional)"),
):
    """
    Quick blocked check — used by Next.js middleware to enforce full site block.
    Also logs a PAGE visit if 'path' is provided (server-to-server, no CORS issues).
    Rate limited para evitar abuso.
    """
    import asyncio
    from ..services.traffic_service import TrafficService

    # Rate limit por IP
    if _check_public_rate_limit(ip):
        return {"blocked": False, "rate_limited": True}

    ts = TrafficService.get()
    blocked = ts.is_blocked(ip)

    # Sempre registar heartbeat (mantém estado "online" no dashboard)
    if not blocked:
        ts.heartbeat(ip)

    # Se path foi enviado → registar visita no Supabase (fire-and-forget)
    if path and not blocked:
        asyncio.create_task(ts.safe_log_request(
            ip=ip,
            method="PAGE",
            path=path,
            status_code=200,
            user_agent=(ua or "")[:500],
            response_time_ms=0,
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