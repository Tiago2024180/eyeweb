"""
===========================================
Eye Web Backend — Traffic Monitor Router
===========================================
API endpoints for the admin traffic monitoring dashboard.

Endpoints:
    GET  /admin/traffic/stats       — Dashboard statistics
    GET  /admin/traffic/logs        — Paginated request logs
    GET  /admin/traffic/suspicious  — Suspicious activity events
    GET  /admin/traffic/blocked     — Blocked IPs list
    POST /admin/traffic/block-ip    — Manually block an IP
    POST /admin/traffic/unblock-ip  — Unblock an IP
"""

import os
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(prefix="/admin/traffic", tags=["admin-traffic"])


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


# ─── ENDPOINTS ────────────────────────────────────────

@router.get("/stats")
async def get_traffic_stats():
    """Dashboard statistics: requests 24h, active IPs, suspicious events, blocked total."""
    url = _url()
    headers = _headers()
    if not url:
        raise HTTPException(500, "Supabase not configured")

    now = datetime.now(timezone.utc)
    since_24h = (now - timedelta(hours=24)).isoformat()
    since_5m = (now - timedelta(minutes=5)).isoformat()

    count_headers = {**headers, "Prefer": "count=exact", "Range": "0-0"}

    try:
        async with httpx.AsyncClient() as c:
            r1, r2, r3, r4 = await c.get(
                f"{url}/rest/v1/traffic_logs?select=id&created_at=gte.{since_24h}",
                headers=count_headers, timeout=8.0,
            ), None, None, None

            # Run all 4 queries (sequential to avoid connection issues)
            r1 = await c.get(
                f"{url}/rest/v1/traffic_logs?select=id&created_at=gte.{since_24h}",
                headers=count_headers, timeout=8.0,
            )
            r2 = await c.get(
                f"{url}/rest/v1/traffic_logs?select=ip&created_at=gte.{since_5m}",
                headers={**headers, "Prefer": "return=representation"}, timeout=8.0,
            )
            r3 = await c.get(
                f"{url}/rest/v1/traffic_suspicious?select=id&created_at=gte.{since_24h}",
                headers=count_headers, timeout=8.0,
            )
            r4 = await c.get(
                f"{url}/rest/v1/traffic_blocked_ips?select=id",
                headers=count_headers, timeout=8.0,
            )

        # Active unique IPs in last 5 min
        active_ips = 0
        if r2 and r2.status_code == 200:
            try:
                ips = {row.get("ip") for row in r2.json() if row.get("ip")}
                active_ips = len(ips)
            except Exception:
                pass

        return {
            "requests_24h": _parse_count(r1) if r1 else 0,
            "active_ips_5m": active_ips,
            "suspicious_24h": _parse_count(r3) if r3 else 0,
            "blocked_total": _parse_count(r4) if r4 else 0,
        }
    except Exception as e:
        return {
            "requests_24h": 0,
            "active_ips_5m": 0,
            "suspicious_24h": 0,
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
